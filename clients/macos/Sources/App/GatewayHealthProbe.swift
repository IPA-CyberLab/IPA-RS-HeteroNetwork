import Foundation
import HeteroNetworkCore
import Network

enum GatewayHealthProbe {
    private static let webSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 3
        configuration.timeoutIntervalForResource = 3
        configuration.waitsForConnectivity = false
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.connectionProxyDictionary = [:]
        return URLSession(configuration: configuration)
    }()

    static func isHealthy(_ profile: TunnelProfile) async -> Bool {
        async let webHealthy = probeWebUI(profile)
        async let dnsHealthy = probeDNS(profile)
        let result = await (webHealthy, dnsHealthy)
        return result.0 && result.1
    }

    private static func probeWebUI(_ profile: TunnelProfile) async -> Bool {
        var components = URLComponents()
        components.scheme = "http"
        components.host = profile.gatewayVPNIP
        components.port = HeteroNetworkConstants.overlayWebUIPort
        components.path = "/v1/web-ui/healthz"
        guard let url = components.url else { return false }
        var request = URLRequest(url: url)
        request.timeoutInterval = 3
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        do {
            let (data, response) = try await webSession.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  data.count <= 1_024,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                return false
            }
            return object["status"] as? String == "ok"
        } catch {
            return false
        }
    }

    private static func probeDNS(_ profile: TunnelProfile) async -> Bool {
        let queryID = UInt16.random(in: UInt16.min...UInt16.max)
        let probe = UDPDNSProbe(
            host: profile.gatewayVPNIP,
            request: OverlayDNSHealthProbe.query(id: queryID),
            queryID: queryID
        )
        return await probe.run()
    }
}

private final class UDPDNSProbe: @unchecked Sendable {
    private let connection: NWConnection
    private let request: Data
    private let queryID: UInt16
    private let queue = DispatchQueue(label: "jp.go.ipa.cyberlab.heteronetwork.dns-probe")
    private var completion: CheckedContinuation<Bool, Never>?
    private var completed = false

    init(host: String, request: Data, queryID: UInt16) {
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: 53)!,
            using: .udp
        )
        self.request = request
        self.queryID = queryID
    }

    func run() async -> Bool {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                queue.async { [self] in
                    completion = continuation
                    connection.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        switch state {
                        case .ready:
                            sendQuery()
                        case .failed, .cancelled:
                            finish(false)
                        default:
                            break
                        }
                    }
                    connection.start(queue: queue)
                    queue.asyncAfter(deadline: .now() + 3) { [weak self] in
                        self?.finish(false)
                    }
                }
            }
        } onCancel: {
            queue.async { [weak self] in self?.finish(false) }
        }
    }

    private func sendQuery() {
        connection.send(content: request, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if error != nil {
                finish(false)
                return
            }
            connection.receiveMessage { [weak self] data, _, _, receiveError in
                guard let self else { return }
                finish(
                    receiveError == nil
                        && data.map {
                            OverlayDNSHealthProbe.isHealthyResponse($0, queryID: self.queryID)
                        }
                            == true
                )
            }
        })
    }

    private func finish(_ result: Bool) {
        guard !completed else { return }
        completed = true
        let pending = completion
        completion = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        pending?.resume(returning: result)
    }
}
