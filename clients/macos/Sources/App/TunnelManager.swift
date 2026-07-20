import Combine
import HeteroNetworkCore
import NetworkExtension

@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.syncStatus()
            }
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    func load() async throws {
        manager = try await findManager()
        syncStatus()
    }

    func prepare(for session: ClientSession) async throws {
        let manager = try await findManager() ?? NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = HeteroNetworkConstants.packetTunnelBundleIdentifier
        tunnelProtocol.serverAddress = session.peerMap.peers.first?.nodeID ?? "HeteroNetwork gateway"
        tunnelProtocol.providerConfiguration = [
            "sessionSchemaVersion": HeteroNetworkConstants.sessionSchemaVersion,
        ]
        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "HeteroNetwork"
        manager.isEnabled = true
        try await save(manager)
        try await reload(manager)
        self.manager = manager
        syncStatus()
    }

    func connect() throws {
        guard let manager else { throw TunnelManagerError.profileMissing }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            return
        case .disconnecting:
            throw TunnelManagerError.busy
        case .invalid, .disconnected:
            try manager.connection.startVPNTunnel()
        @unknown default:
            throw TunnelManagerError.busy
        }
        syncStatus()
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        syncStatus()
    }

    func removeProfile() async throws {
        guard let manager = try await findManager() else {
            self.manager = nil
            status = .invalid
            return
        }
        manager.connection.stopVPNTunnel()
        try await remove(manager)
        self.manager = nil
        status = .invalid
    }

    private func syncStatus() {
        status = manager?.connection.status ?? .invalid
    }

    private func findManager() async throws -> NETunnelProviderManager? {
        let managers = try await loadAllManagers()
        return managers.first { candidate in
            guard let tunnelProtocol = candidate.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return tunnelProtocol.providerBundleIdentifier
                == HeteroNetworkConstants.packetTunnelBundleIdentifier
        }
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func remove(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
            manager.removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

private enum TunnelManagerError: LocalizedError {
    case profileMissing
    case busy

    var errorDescription: String? {
        switch self {
        case .profileMissing: return "The HeteroNetwork VPN profile is not installed."
        case .busy: return "The VPN connection is busy."
        }
    }
}
