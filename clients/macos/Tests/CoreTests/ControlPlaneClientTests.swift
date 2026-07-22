import XCTest
@testable import HeteroNetworkCore

final class ControlPlaneClientTests: XCTestCase {
    func testRecoversEnrollmentWhenJoinResponseIsLost() async throws {
        let keyMaterial = ClientKeyMaterial.generate()
        let clientID = try keyMaterial.clientID
        let identityPublicKey = try keyMaterial.identityPublicKey
        let wireGuardPublicKey = try keyMaterial.wireGuardPublicKey
        let now = Date(timeIntervalSince1970: 1_784_550_896)
        let clientRecord = NodeRecord(
            nodeID: clientID,
            clusterID: "cluster-a",
            vpnIP: "100.96.0.10",
            identityPublicKey: identityPublicKey,
            wireGuardPublicKey: wireGuardPublicKey,
            role: "client",
            tags: [],
            endpointCandidates: [],
            routes: [],
            registeredAt: now
        )
        let peerMap = PeerMap(
            clusterID: "cluster-a",
            peers: [gatewayRecord(now: now)],
            bootstrapEndpoints: [
                BootstrapEndpoint(url: "https://cp.example:8443", kind: .controlPlane),
                BootstrapEndpoint(url: "https://next-gateway.example", kind: .webUi),
            ],
            generatedAt: now
        )
        let response = ClientConfigurationFixture(client: clientRecord, peerMap: peerMap)
        let responseData = try HeteroNetworkCoding.makeEncoder().encode(response)

        let lock = NSLock()
        var paths = [String]()
        var hosts = [String]()
        var selectedGateways = [String]()
        StubURLProtocol.handler = { request in
            lock.lock()
            paths.append(request.url?.path ?? "")
            hosts.append(request.url?.host ?? "")
            lock.unlock()
            if request.url?.path == "/v1/clients/join" {
                throw URLError(.networkConnectionLost)
            }
            guard request.url?.path == "/v1/clients/peers/query" else {
                throw URLError(.badURL)
            }
            let requestObject = try JSONSerialization.jsonObject(
                with: try requestBody(request)
            ) as? [String: Any]
            lock.lock()
            selectedGateways.append(requestObject?["active_gateway_node_id"] as? String ?? "-")
            lock.unlock()
            let http = HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            return (http, responseData)
        }
        defer { StubURLProtocol.handler = nil }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let controlPlane = ControlPlaneClient(session: URLSession(configuration: configuration))
        let session = try await controlPlane.join(token: token(now: now), keyMaterial: keyMaterial)
        let refreshed = try await controlPlane.refresh(session)

        XCTAssertEqual(session.client, clientRecord)
        XCTAssertEqual(session.peerMap, peerMap)
        XCTAssertEqual(refreshed.controlPlaneURLs.first?.host, "next-gateway.example")
        lock.lock()
        let requestedPaths = paths
        let requestedHosts = hosts
        let requestedGateways = selectedGateways
        lock.unlock()
        XCTAssertEqual(
            requestedPaths,
            [
                "/v1/clients/join",
                "/v1/clients/join",
                "/v1/clients/peers/query",
                "/v1/clients/peers/query",
            ]
        )
        XCTAssertEqual(
            requestedHosts,
            ["gateway.example", "cp.example", "gateway.example", "gateway.example"]
        )
        XCTAssertEqual(requestedGateways, ["-", "node-gateway"])
    }

    private func token(now: Date) -> SignedJoinToken {
        SignedJoinToken(
            claims: JoinTokenClaims(
                clusterID: "cluster-a",
                bootstrapEndpoints: [
                    BootstrapEndpoint(url: "https://cp.example:8443", kind: .controlPlane),
                    BootstrapEndpoint(url: "https://gateway.example", kind: .webUi),
                ],
                expiresAt: now.addingTimeInterval(600),
                notBefore: now.addingTimeInterval(-5),
                role: "client",
                tags: [],
                issuer: "node-issuer",
                keyID: "client-enrollment",
                policy: TokenPolicy(
                    allowJoin: true,
                    allowRelay: false,
                    allowedRoutes: [],
                    allowedTags: [],
                    maxTokenUses: 1
                ),
                nonce: "client-recovery-test"
            ),
            signature: String(repeating: "A", count: 88)
        )
    }

    private func gatewayRecord(now: Date) -> NodeRecord {
        NodeRecord(
            nodeID: "node-gateway",
            clusterID: "cluster-a",
            vpnIP: "100.96.0.1",
            identityPublicKey: Data(repeating: 1, count: 32).base64EncodedString(),
            wireGuardPublicKey: Data(repeating: 2, count: 32).base64EncodedString(),
            role: "gateway",
            tags: [],
            endpointCandidates: [],
            routes: [],
            registeredAt: now
        )
    }
}

private func requestBody(_ request: URLRequest) throws -> Data {
    if let body = request.httpBody {
        return body
    }
    let stream = try XCTUnwrap(request.httpBodyStream)
    stream.open()
    defer { stream.close() }
    var body = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
        let count = stream.read(&buffer, maxLength: buffer.count)
        if count < 0 {
            throw stream.streamError ?? URLError(.cannotDecodeRawData)
        }
        if count == 0 {
            return body
        }
        body.append(contentsOf: buffer.prefix(count))
    }
}

private struct ClientConfigurationFixture: Encodable {
    let client: NodeRecord
    let peerMap: PeerMap

    enum CodingKeys: String, CodingKey {
        case client
        case peerMap = "peer_map"
    }
}

private final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw URLError(.unknown) }
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
