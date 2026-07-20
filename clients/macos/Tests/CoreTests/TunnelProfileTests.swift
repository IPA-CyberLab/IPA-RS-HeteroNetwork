import XCTest
@testable import HeteroNetworkCore

final class TunnelProfileTests: XCTestCase {
    func testRoutesOnlyThroughPreferredGatewayEndpoint() throws {
        let session = makeSession(routes: ["100.96.0.3/32", "10.42.0.0/16"])

        let profile = try TunnelProfile(session: session)

        XCTAssertEqual(profile.clientAddress, "100.96.0.4/32")
        XCTAssertEqual(profile.gatewayEndpoint, "[2001:db8::10]:51820")
        XCTAssertEqual(profile.allowedIPs, ["100.96.0.1/32", "100.96.0.3/32", "10.42.0.0/16"])
    }

    func testRejectsDefaultRoute() {
        XCTAssertThrowsError(try TunnelProfile(session: makeSession(routes: ["0.0.0.0/0"]))) { error in
            XCTAssertEqual(error as? TunnelProfileError, .invalidRoute("0.0.0.0/0"))
        }
    }

    private func makeSession(routes: [String]) -> ClientSession {
        let now = Date(timeIntervalSince1970: 1_784_550_896)
        let gatewayID = "node-gateway"
        let candidates = [
            EndpointCandidate(
                nodeID: gatewayID,
                kind: .publicUDP,
                address: "198.51.100.10:51820",
                observedAt: now,
                priority: 100,
                cost: 1,
                source: "interface_scan"
            ),
            EndpointCandidate(
                nodeID: gatewayID,
                kind: .ipv6,
                address: "[2001:db8::10]:51820",
                observedAt: now,
                priority: 10,
                cost: 100,
                source: "interface_scan"
            ),
        ]
        let gateway = NodeRecord(
            nodeID: gatewayID,
            clusterID: "cluster-a",
            vpnIP: "100.96.0.1",
            identityPublicKey: Data(repeating: 1, count: 32).base64EncodedString(),
            wireGuardPublicKey: Data(repeating: 2, count: 32).base64EncodedString(),
            role: "gateway",
            tags: [],
            endpointCandidates: candidates,
            routes: routes.enumerated().map { index, cidr in
                Route(
                    id: "route-\(index)",
                    cidr: cidr,
                    advertisedBy: gatewayID,
                    via: gatewayID,
                    metric: 10,
                    tags: []
                )
            },
            registeredAt: now
        )
        let client = NodeRecord(
            nodeID: "node-client",
            clusterID: "cluster-a",
            vpnIP: "100.96.0.4",
            identityPublicKey: Data(repeating: 3, count: 32).base64EncodedString(),
            wireGuardPublicKey: Data(repeating: 4, count: 32).base64EncodedString(),
            role: "client",
            tags: [],
            endpointCandidates: [],
            routes: [],
            registeredAt: now
        )
        return ClientSession(
            identityPrivateKey: Data(repeating: 5, count: 32),
            wireGuardPrivateKey: Data(repeating: 6, count: 32),
            controlPlaneURLs: [URL(string: "https://cp-a.example:8443")!],
            client: client,
            peerMap: PeerMap(
                clusterID: "cluster-a",
                peers: [gateway],
                bootstrapEndpoints: [],
                generatedAt: now
            ),
            enrolledAt: now
        )
    }
}
