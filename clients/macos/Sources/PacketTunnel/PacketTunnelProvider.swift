import Foundation
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
    private let controlPlane = ControlPlaneClient()
    private let sessionStore = ClientSessionStore()
    private var activeProfile: TunnelProfile?
    private var profileActivatedAt = Date.distantPast
    private var consecutiveProbeFailures = 0
    private var failedGatewayUntil = [String: Date]()
    private var refreshTask: Task<Void, Never>?

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            guard let session = try sessionStore.load() else {
                throw PacketTunnelError.missingSession
            }
            let gatewayIndex = session.selectedGatewayNodeID.flatMap { selected in
                session.peerMap.peers.firstIndex(where: { $0.nodeID == selected })
            } ?? 0
            let profile = try TunnelProfile(session: session, gatewayIndex: gatewayIndex)
            let configuration = try makeTunnelConfiguration(session: session, profile: profile)
            adapter.start(tunnelConfiguration: configuration) { [weak self] error in
                if let error {
                    self?.logger.error("WireGuard start failed: \(String(describing: error), privacy: .public)")
                } else {
                    self?.activeProfile = profile
                    self?.profileActivatedAt = Date()
                    self?.consecutiveProbeFailures = 0
                    self?.startRefreshLoop()
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
        refreshTask?.cancel()
        refreshTask = nil
        activeProfile = nil
        consecutiveProbeFailures = 0
        failedGatewayUntil.removeAll()
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
                "gateway": self?.activeProfile?.gatewayNodeID ?? "",
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: payload))
        }
    }

    private func makeTunnelConfiguration(
        session: ClientSession,
        profile: TunnelProfile
    ) throws -> TunnelConfiguration {
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
        guard let dnsServer = DNSServer(from: profile.gatewayVPNIP) else {
            throw PacketTunnelError.invalidGatewayConfiguration
        }
        interface.dns = [dnsServer]
        interface.dnsSearch = [HeteroNetworkConstants.overlayDNSName]

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

    private func startRefreshLoop() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(
                        nanoseconds: HeteroNetworkConstants.gatewayRefreshIntervalNanoseconds
                    )
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                await self?.refreshGateway()
            }
        }
    }

    private func refreshGateway() async {
        do {
            guard var session = try sessionStore.load() else {
                throw PacketTunnelError.missingSession
            }
            await assessActiveGateway(session: session)
            session.selectedGatewayNodeID = activeProfile?.gatewayNodeID
            do {
                session = try await controlPlane.refresh(session)
            } catch {
                logger.warning(
                    "Peer-map refresh failed; retaining cached gateways: \(error.localizedDescription, privacy: .public)"
                )
            }
            try await applyPreferredGateway(session: session)
            session.selectedGatewayNodeID = activeProfile?.gatewayNodeID
            try sessionStore.save(session)
        } catch is CancellationError {
            return
        } catch {
            logger.warning("Gateway refresh failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func assessActiveGateway(session: ClientSession) async {
        guard let activeProfile else { return }
        if await probeGateway(activeProfile) {
            consecutiveProbeFailures = 0
            return
        }
        guard Date().timeIntervalSince(profileActivatedAt) >= 10 else { return }
        consecutiveProbeFailures += 1
        guard consecutiveProbeFailures >= HeteroNetworkConstants.gatewayFailureThreshold else {
            return
        }
        failedGatewayUntil[activeProfile.gatewayNodeID] = Date().addingTimeInterval(
            HeteroNetworkConstants.gatewayFailureCooldown
        )
        consecutiveProbeFailures = 0
        logger.warning(
            "Gateway \(activeProfile.gatewayNodeID, privacy: .public) failed its VPN health probe"
        )
        do {
            try await applyPreferredGateway(session: session)
        } catch {
            logger.warning(
                "Cached gateway failover failed: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    private func applyPreferredGateway(session: ClientSession) async throws {
        let now = Date()
        failedGatewayUntil = failedGatewayUntil.filter { $0.value > now }
        var preferred: TunnelProfile?
        for index in session.peerMap.peers.indices {
            let gateway = session.peerMap.peers[index]
            if failedGatewayUntil[gateway.nodeID] != nil { continue }
            preferred = try TunnelProfile(session: session, gatewayIndex: index)
            break
        }
        if preferred == nil,
           let activeProfile,
           session.peerMap.peers.contains(where: { $0.nodeID == activeProfile.gatewayNodeID })
        {
            preferred = activeProfile
        }
        guard let preferred else {
            throw TunnelProfileError.invalidGatewayCount(session.peerMap.peers.count)
        }
        guard preferred != activeProfile else { return }

        let configuration = try makeTunnelConfiguration(session: session, profile: preferred)
        try await updateAdapter(configuration)
        guard !Task.isCancelled else { throw CancellationError() }
        activeProfile = preferred
        profileActivatedAt = now
        consecutiveProbeFailures = 0
        logger.notice(
            "WireGuard gateway changed to \(preferred.gatewayNodeID, privacy: .public)"
        )
    }

    private func probeGateway(_ profile: TunnelProfile) async -> Bool {
        let hostHeader = profile.gatewayVPNIP.contains(":")
            ? "[\(profile.gatewayVPNIP)]"
            : profile.gatewayVPNIP
        let endpoint = NWHostEndpoint(
            hostname: profile.gatewayVPNIP,
            port: String(HeteroNetworkConstants.overlayWebUIPort)
        )
        let connection = createTCPConnectionThroughTunnel(
            to: endpoint,
            enableTLS: false,
            tlsParameters: nil,
            delegate: nil
        )
        let request = Data(
            "GET /v1/web-ui/healthz HTTP/1.1\r\nHost: \(hostHeader):\(HeteroNetworkConstants.overlayWebUIPort)\r\nAccept: application/json\r\nConnection: close\r\n\r\n".utf8
        )
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                TunnelHTTPHealthProbe(
                    connection: connection,
                    request: request,
                    completion: { continuation.resume(returning: $0) }
                ).start()
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private func updateAdapter(_ configuration: TunnelConfiguration) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            adapter.update(tunnelConfiguration: configuration) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

private final class TunnelHTTPHealthProbe {
    private let connection: NWTCPConnection
    private let request: Data
    private let lock = NSLock()
    private var response = Data()
    private var completion: ((Bool) -> Void)?
    private var timeout: DispatchWorkItem?

    init(connection: NWTCPConnection, request: Data, completion: @escaping (Bool) -> Void) {
        self.connection = connection
        self.request = request
        self.completion = completion
    }

    func start() {
        let timeout = DispatchWorkItem { [self] in finish(false) }
        lock.lock()
        self.timeout = timeout
        lock.unlock()
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + 3,
            execute: timeout
        )
        connection.write(request) { [self] error in
            if error != nil {
                finish(false)
            } else {
                readNextChunk()
            }
        }
    }

    private func readNextChunk() {
        lock.lock()
        let remaining = OverlayHealthResponseParser.maximumResponseBytes - response.count
        let active = completion != nil
        lock.unlock()
        guard active, remaining > 0 else {
            finish(false)
            return
        }
        connection.readMinimumLength(1, maximumLength: remaining) { [self] data, error in
            guard error == nil else {
                finish(false)
                return
            }
            lock.lock()
            guard completion != nil else {
                lock.unlock()
                return
            }
            if let data {
                response.append(data)
            }
            let result = OverlayHealthResponseParser.result(
                from: response,
                streamClosed: data == nil || data?.isEmpty == true
            )
            lock.unlock()

            if let result {
                finish(result)
            } else {
                readNextChunk()
            }
        }
    }

    private func finish(_ result: Bool) {
        lock.lock()
        guard let completion else {
            lock.unlock()
            return
        }
        self.completion = nil
        let timeout = self.timeout
        self.timeout = nil
        lock.unlock()

        timeout?.cancel()
        connection.cancel()
        completion(result)
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
