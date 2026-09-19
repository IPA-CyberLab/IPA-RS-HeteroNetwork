import AppKit
import Combine
import HeteroNetworkCore
import OSLog
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var session: ClientSession?
    @Published private(set) var vpnStatus: TunnelStatus = .invalid
    @Published private(set) var isBusy = false
    @Published var registrationRequest = ""
    @Published var importInput = ""
    @Published var lastError: String?
    @Published private(set) var updateStatus: AppUpdateStatus = .idle

    let tunnelManager = TunnelManager()

    private let controlPlane = ControlPlaneClient()
    private let sessionStore = ClientSessionStore()
    private let appUpdateService = AppUpdateService()
    private let logger = Logger(
        subsystem: "jp.go.ipa.cyberlab.heteronetwork",
        category: "TunnelMaintenance"
    )
    private var pendingRegistration: PendingClientRegistration?
    private var cancellables = Set<AnyCancellable>()
    private var failedGatewayUntil = [String: Date]()
    private var consecutiveProbeFailures = 0
    private var profileActivatedAt = Date.distantPast
    private var isMaintainingTunnel = false
    private var availableAppUpdate: DesktopReleaseUpdate?

    init() {
        guard !InstalledAppKeychainProbe.isRequested else { return }
        tunnelManager.$status
            .receive(on: RunLoop.main)
            .sink { [weak self] status in self?.vpnStatus = status }
            .store(in: &cancellables)
        Timer.publish(
            every: HeteroNetworkConstants.gatewayRefreshInterval,
            on: .main,
            in: .common
        )
            .autoconnect()
            .sink { [weak self] _ in
                Task { await self?.maintainTunnel() }
            }
            .store(in: &cancellables)
        Timer.publish(every: 6 * 60 * 60, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                Task { await self?.checkForUpdates() }
            }
            .store(in: &cancellables)
        Task {
            await restore()
            await checkForUpdates()
        }
    }

    var isConfigured: Bool { session != nil }

    var canRetryAvailableUpdate: Bool {
        availableAppUpdate != nil && !updateStatus.isActive
    }

    var currentReleaseTag: String {
        Bundle.main.object(forInfoDictionaryKey: "HeteroNetworkReleaseTag") as? String
            ?? "development"
    }

    var gatewayName: String {
        tunnelManager.activeGatewayNodeID
            ?? session?.selectedGatewayNodeID
            ?? session?.peerMap.peers.first?.nodeID
            ?? "-"
    }

    func generateRegistrationRequest() {
        guard !isBusy else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            let pending = try SponsoredEnrollment.makeRegistration()
            try sessionStore.savePendingRegistration(pending)
            pendingRegistration = pending
            registrationRequest = try pending.bundle.uri()
            copyRegistrationRequest()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func copyRegistrationRequest() {
        guard !registrationRequest.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(registrationRequest, forType: .string)
    }

    func importProfile() async {
        guard !isBusy else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            let pending: PendingClientRegistration?
            if let current = pendingRegistration {
                pending = current
            } else {
                pending = try sessionStore.loadPendingRegistration()
            }
            let imported = try SponsoredEnrollment.importProfile(
                importInput,
                pending: pending
            )
            _ = try TunnelProfile(session: imported)
            guard let pending else {
                throw SponsoredEnrollmentError.pendingRegistrationMissing
            }
            try sessionStore.completeImport(pending: pending, session: imported)
            pendingRegistration = nil
            session = imported
            try await tunnelManager.prepare(for: imported)
            registrationRequest = ""
            importInput = ""
        } catch {
            lastError = error.localizedDescription
        }
    }

    func connect() async {
        guard !isBusy, var current = session else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            _ = try TunnelProfile(session: current)
            try await tunnelManager.prepare(for: current)
            try await tunnelManager.connect(current)
            if let activeGateway = tunnelManager.activeGatewayNodeID {
                current.selectedGatewayNodeID = activeGateway
                try sessionStore.save(current)
                session = current
            }
            consecutiveProbeFailures = 0
            failedGatewayUntil.removeAll()
            profileActivatedAt = Date()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() async {
        guard !isBusy else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            try await tunnelManager.disconnect()
            consecutiveProbeFailures = 0
            failedGatewayUntil.removeAll()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func openWebUI() {
        NSWorkspace.shared.open(HeteroNetworkConstants.overlayWebUIURL)
    }

    func refresh() async {
        guard !isBusy, var current = session else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            current.selectedGatewayNodeID = tunnelManager.activeGatewayNodeID
                ?? current.selectedGatewayNodeID
            var refreshed = try await controlPlane.refresh(current)
            let selected = try preferredGateway(in: refreshed)
            refreshed.selectedGatewayNodeID = selected
            _ = try TunnelProfile(session: refreshed, gatewayIndex: gatewayIndex(
                nodeID: selected,
                in: refreshed
            ))
            if tunnelManager.status == .connected {
                try await tunnelManager.update(refreshed)
            }
            try sessionStore.save(refreshed)
            session = refreshed
        } catch {
            lastError = error.localizedDescription
        }
    }

    func removeThisMac() async {
        guard !isBusy, let current = session else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            var remoteRemovalError: Error?
            do {
                try await controlPlane.remove(current)
            } catch {
                remoteRemovalError = error
            }
            try await tunnelManager.removeProfile()
            try sessionStore.delete()
            try sessionStore.deletePendingRegistration()
            pendingRegistration = nil
            registrationRequest = ""
            importInput = ""
            session = nil
            consecutiveProbeFailures = 0
            failedGatewayUntil.removeAll()
            if let remoteRemovalError {
                lastError = "This Mac was removed locally, but control-plane cleanup failed: "
                    + remoteRemovalError.localizedDescription
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    func clearError() {
        lastError = nil
    }

    func checkForUpdates() async {
        guard !isBusy, !updateStatus.isActive else { return }
        guard currentReleaseTag.hasPrefix("v") else {
            updateStatus = .unavailableForDevelopmentBuild
            return
        }
        updateStatus = .checking
        do {
            let update = try await appUpdateService.availableUpdate(
                currentTag: currentReleaseTag
            )
            guard let update else {
                availableAppUpdate = nil
                updateStatus = .upToDate(currentReleaseTag)
                return
            }
            availableAppUpdate = update
            updateStatus = .available(update.tag)
            await installAvailableUpdate()
        } catch {
            updateStatus = .failed(error.localizedDescription)
        }
    }

    func installAvailableUpdate() async {
        guard !isBusy,
              !updateStatus.isActive,
              let update = availableAppUpdate
        else {
            return
        }
        updateStatus = .downloading(update.tag)
        do {
            let prepared = try await appUpdateService.prepare(update)
            updateStatus = .restarting(update.tag)
            try appUpdateService.activate(prepared)
            try? await Task.sleep(nanoseconds: 250_000_000)
            NSApp.terminate(nil)
        } catch {
            updateStatus = .failed(error.localizedDescription)
        }
    }

    private func restore() async {
        do {
            session = try sessionStore.load()
            if session != nil {
                try sessionStore.deletePendingRegistration()
            } else if let pending = try sessionStore.loadPendingRegistration() {
                pendingRegistration = pending
                registrationRequest = try pending.bundle.uri()
            }
            try await tunnelManager.load(configured: session != nil)
            if let session {
                try await tunnelManager.prepare(for: session)
                if tunnelManager.status == .connected {
                    profileActivatedAt = Date()
                }
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func maintainTunnel() async {
        guard !isMaintainingTunnel, !isBusy, session != nil else { return }
        isMaintainingTunnel = true
        defer { isMaintainingTunnel = false }
        do {
            try await tunnelManager.refreshStatus()
            guard tunnelManager.status == .connected, var current = session else { return }
            if let activeGateway = tunnelManager.activeGatewayNodeID {
                current.selectedGatewayNodeID = activeGateway
            }
            await assessActiveGateway(in: current)

            var refreshed = current
            do {
                refreshed = try await controlPlane.refresh(current)
            } catch {
                logger.warning(
                    "Peer-map refresh failed; retaining cached gateways: \(error.localizedDescription, privacy: .public)"
                )
            }
            let selectedGateway = try preferredGateway(in: refreshed)
            refreshed.selectedGatewayNodeID = selectedGateway
            if selectedGateway != tunnelManager.activeGatewayNodeID {
                try await tunnelManager.update(refreshed)
                profileActivatedAt = Date()
                consecutiveProbeFailures = 0
                logger.notice("WireGuard gateway changed to \(selectedGateway, privacy: .public)")
            }
            try sessionStore.save(refreshed)
            session = refreshed
        } catch is CancellationError {
            return
        } catch {
            logger.warning("Tunnel maintenance failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func assessActiveGateway(in current: ClientSession) async {
        guard let activeGateway = tunnelManager.activeGatewayNodeID,
              let index = current.peerMap.peers.firstIndex(where: { $0.nodeID == activeGateway }),
              let profile = try? TunnelProfile(session: current, gatewayIndex: index)
        else {
            return
        }
        if await GatewayHealthProbe.isHealthy(profile) {
            consecutiveProbeFailures = 0
            return
        }
        guard Date().timeIntervalSince(profileActivatedAt) >= 10 else { return }
        consecutiveProbeFailures += 1
        guard consecutiveProbeFailures >= HeteroNetworkConstants.gatewayFailureThreshold else {
            return
        }
        failedGatewayUntil[activeGateway] = Date().addingTimeInterval(
            HeteroNetworkConstants.gatewayFailureCooldown
        )
        consecutiveProbeFailures = 0
        logger.warning("Gateway \(activeGateway, privacy: .public) failed its VPN health probe")
    }

    private func preferredGateway(in current: ClientSession) throws -> String {
        let now = Date()
        failedGatewayUntil = failedGatewayUntil.filter { $0.value > now }
        if let candidate = current.peerMap.peers.first(where: {
            failedGatewayUntil[$0.nodeID] == nil
        }) {
            return candidate.nodeID
        }
        if let activeGateway = tunnelManager.activeGatewayNodeID,
           current.peerMap.peers.contains(where: { $0.nodeID == activeGateway }) {
            return activeGateway
        }
        throw TunnelProfileError.invalidGatewayCount(current.peerMap.peers.count)
    }

    private func gatewayIndex(nodeID: String, in current: ClientSession) -> Int {
        current.peerMap.peers.firstIndex(where: { $0.nodeID == nodeID }) ?? 0
    }
}
