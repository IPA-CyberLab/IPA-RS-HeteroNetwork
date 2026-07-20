import HeteroNetworkCore
import NetworkExtension
import OSLog
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "HeteroNetworkPacketTunnel",
        category: "WireGuard"
    )
    private lazy var adapter = WireGuardAdapter(with: self) { [weak self] level, message in
        self?.logger.log(level: .debug, "[\(String(describing: level), privacy: .public)] \(message, privacy: .public)")
    }

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            guard let session = try ClientSessionStore().load() else {
                throw PacketTunnelError.missingSession
            }
            let configuration = try makeTunnelConfiguration(session: session)
            adapter.start(tunnelConfiguration: configuration) { [weak self] error in
                if let error {
                    self?.logger.error("WireGuard start failed: \(String(describing: error), privacy: .public)")
                }
                completionHandler(error)
            }
        } catch {
            logger.error("Tunnel configuration failed: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        adapter.stop { [weak self] error in
            if let error {
                self?.logger.warning("WireGuard stop returned: \(String(describing: error), privacy: .public)")
            }
            completionHandler()
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        adapter.getRuntimeConfiguration { [weak self] configuration in
            let payload: [String: Any] = [
                "interface": self?.adapter.interfaceName ?? "",
                "running": configuration != nil,
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: payload))
        }
    }

    private func makeTunnelConfiguration(session: ClientSession) throws -> TunnelConfiguration {
        let profile = try TunnelProfile(session: session)
        guard let privateKey = PrivateKey(rawValue: session.wireGuardPrivateKey),
              let address = IPAddressRange(from: profile.clientAddress)
        else {
            throw PacketTunnelError.invalidPrivateConfiguration
        }
        guard let publicKey = PublicKey(base64Key: profile.gatewayWireGuardPublicKey),
              let endpoint = Endpoint(from: profile.gatewayEndpoint)
        else {
            throw PacketTunnelError.invalidGatewayConfiguration
        }
        let allowedIPs = profile.allowedIPs.compactMap(IPAddressRange.init(from:))
        guard allowedIPs.count == profile.allowedIPs.count else {
            throw PacketTunnelError.invalidGatewayConfiguration
        }

        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = [address]

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = endpoint
        peer.allowedIPs = allowedIPs
        peer.persistentKeepAlive = 25

        return TunnelConfiguration(
            name: "HeteroNetwork",
            interface: interface,
            peers: [peer]
        )
    }
}

private enum PacketTunnelError: LocalizedError {
    case missingSession
    case invalidPrivateConfiguration
    case invalidGatewayConfiguration

    var errorDescription: String? {
        switch self {
        case .missingSession: return "No enrolled HeteroNetwork session was found."
        case .invalidPrivateConfiguration: return "The saved client tunnel identity is invalid."
        case .invalidGatewayConfiguration: return "The gateway tunnel configuration is invalid."
        }
    }
}
