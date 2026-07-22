import XCTest
@testable import HeteroNetworkCore

final class EnrollmentTests: XCTestCase {
    func testParsesClientEnrollmentURI() throws {
        let now = Date(timeIntervalSince1970: 1_784_550_896)
        let token = makeToken(now: now)
        let data = try HeteroNetworkCoding.makeEncoder().encode(token)
        let uri = "heteronetwork://enroll?token=\(data.base64URLEncodedString())"

        let parsed = try EnrollmentParser.parse(uri, now: now)

        XCTAssertEqual(parsed, token)
        XCTAssertEqual(try EnrollmentParser.controlPlaneURLs(from: parsed).count, 2)
        XCTAssertEqual(try EnrollmentParser.managementURLs(from: parsed).count, 3)
        XCTAssertEqual(
            try EnrollmentParser.managementURLs(from: parsed).first?.host,
            "gateway.example"
        )
    }

    func testRejectsNodeEnrollmentToken() throws {
        let now = Date(timeIntervalSince1970: 1_784_550_896)
        let client = makeToken(now: now)
        let node = SignedJoinToken(
            claims: JoinTokenClaims(
                clusterID: client.claims.clusterID,
                bootstrapEndpoints: client.claims.bootstrapEndpoints,
                expiresAt: client.claims.expiresAt,
                notBefore: client.claims.notBefore,
                role: "edge",
                tags: [],
                issuer: client.claims.issuer,
                keyID: client.claims.keyID,
                policy: client.claims.policy,
                nonce: client.claims.nonce
            ),
            signature: client.signature
        )
        let data = try HeteroNetworkCoding.makeEncoder().encode(node)
        let uri = "heteronetwork://enroll?token=\(data.base64URLEncodedString())"

        XCTAssertThrowsError(try EnrollmentParser.parse(uri, now: now)) { error in
            XCTAssertEqual(error as? EnrollmentError, .wrongRole)
        }
    }

    private func makeToken(now: Date) -> SignedJoinToken {
        SignedJoinToken(
            claims: JoinTokenClaims(
                clusterID: "cluster-a",
                bootstrapEndpoints: [
                    BootstrapEndpoint(url: "https://cp-a.example:8443", kind: .controlPlane),
                    BootstrapEndpoint(url: "https://cp-b.example:8443", kind: .controlPlane),
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
                nonce: "client-enroll-test"
            ),
            signature: String(repeating: "A", count: 88)
        )
    }
}
