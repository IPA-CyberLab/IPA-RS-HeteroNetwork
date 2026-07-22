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
    @Published var enrollmentInput = ""
    @Published var lastError: String?

    let tunnelManager = TunnelManager()

    private let controlPlane = ControlPlaneClient()
    private let sessionStore = ClientSessionStore()
    private var cancellables = Set<AnyCancellable>()

    init() {
        tunnelManager.$status
            .receive(on: RunLoop.main)
            .sink { [weak self] status in self?.vpnStatus = status }
            .store(in: &cancellables)
        NotificationCenter.default.publisher(for: .heteroNetworkEnrollmentURL)
            .compactMap { $0.object as? URL }
            .receive(on: RunLoop.main)
            .sink { [weak self] url in
                self?.enrollmentInput = url.absoluteString
            }
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

    func enroll() async {
        guard !isBusy else { return }
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            let token = try EnrollmentParser.parse(enrollmentInput)
            let joined = try await controlPlane.join(
                token: token,
                keyMaterial: ClientKeyMaterial.generate()
            )
            _ = try TunnelProfile(session: joined)
            try sessionStore.save(joined)
            session = joined
            try await tunnelManager.prepare(for: joined)
            enrollmentInput = ""
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
            let refreshed = try await controlPlane.refresh(current)
            _ = try TunnelProfile(session: refreshed)
            try sessionStore.save(refreshed)
            session = refreshed
            try await tunnelManager.prepare(for: refreshed)
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
            tunnelManager.disconnect()
            try await controlPlane.remove(current)
            try await tunnelManager.removeProfile()
            try sessionStore.delete()
            session = nil
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

extension Notification.Name {
    static let heteroNetworkEnrollmentURL = Notification.Name("HeteroNetworkEnrollmentURL")
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
