import AppKit
import Combine
import HeteroNetworkCore
import NetworkExtension
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var session: ClientSession?
    @Published private(set) var vpnStatus: NEVPNStatus = .invalid
    @Published private(set) var isBusy = false
    @Published var registrationRequest = ""
    @Published var importInput = ""
    @Published var lastError: String?

    let tunnelManager = TunnelManager()

    private let controlPlane = ControlPlaneClient()
    private let sessionStore = ClientSessionStore()
    private var pendingRegistration: PendingClientRegistration?
    private var cancellables = Set<AnyCancellable>()

    init() {
        tunnelManager.$status
            .receive(on: RunLoop.main)
            .sink { [weak self] status in self?.vpnStatus = status }
            .store(in: &cancellables)
        Timer.publish(every: 5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.reloadSessionFromExtension() }
            .store(in: &cancellables)
        Task { await restore() }
    }

    var isConfigured: Bool { session != nil }

    var gatewayName: String {
        session?.selectedGatewayNodeID ?? session?.peerMap.peers.first?.nodeID ?? "-"
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
        guard !isBusy, let current = session else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            // Management endpoints are VPN-only. The cached gateway map must
            // establish WireGuard before the extension refreshes over it.
            _ = try TunnelProfile(session: current)
            try await tunnelManager.prepare(for: current)
            try tunnelManager.connect()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        tunnelManager.disconnect()
    }

    func openWebUI() {
        NSWorkspace.shared.open(HeteroNetworkConstants.overlayWebUIURL)
    }

    func refresh() async {
        guard !isBusy, let current = session else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            let refreshed = try await controlPlane.refresh(current)
            _ = try TunnelProfile(session: refreshed)
            try sessionStore.save(refreshed)
            session = refreshed
            try await tunnelManager.prepare(for: refreshed)
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
            // Keep the overlay route alive until the signed removal reaches a
            // control plane. Disconnecting first can remove the only working
            // management path when the public gateway is unavailable.
            do {
                try await controlPlane.remove(current)
            } catch {
                remoteRemovalError = error
            }
            tunnelManager.disconnect()
            try await tunnelManager.removeProfile()
            try sessionStore.delete()
            try sessionStore.deletePendingRegistration()
            pendingRegistration = nil
            registrationRequest = ""
            importInput = ""
            session = nil
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

    private func restore() async {
        do {
            session = try sessionStore.load()
            if session != nil {
                try sessionStore.deletePendingRegistration()
            } else if let pending = try sessionStore.loadPendingRegistration() {
                pendingRegistration = pending
                registrationRequest = try pending.bundle.uri()
            }
            try await tunnelManager.load()
            if let session, vpnStatus == .invalid {
                try await tunnelManager.prepare(for: session)
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func reloadSessionFromExtension() {
        guard vpnStatus == .connected || vpnStatus == .reasserting else {
            return
        }
        do {
            guard let stored = try sessionStore.load() else {
                return
            }
            let current = session
            guard stored.refreshedAt > (current?.refreshedAt ?? .distantPast)
                    || stored.selectedGatewayNodeID != current?.selectedGatewayNodeID
            else { return }
            session = stored
        } catch {
            lastError = error.localizedDescription
        }
    }
}

extension NEVPNStatus {
    var displayName: LocalizedStringKey {
        switch self {
        case .invalid: return "Not configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        @unknown default: return "Unknown"
        }
    }

    var symbolName: String {
        switch self {
        case .connected: return "checkmark.shield.fill"
        case .connecting, .reasserting: return "arrow.triangle.2.circlepath"
        case .disconnecting: return "hourglass"
        case .invalid, .disconnected: return "shield.slash"
        @unknown default: return "questionmark.shield"
        }
    }
}
