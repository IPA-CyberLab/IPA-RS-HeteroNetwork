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

    func testPreservesSignedTokenTimestampPrecisionWhenReencodingJoinRequest() throws {
        let rawToken = #"""
        {
          "claims": {
            "cluster_id": "cluster-a",
            "bootstrap_endpoints": [
              {"url": "https://gateway.example", "kind": "web_ui"},
              {"url": "https://cp.example:8443", "kind": "control_plane"}
            ],
            "expires_at": "2026-07-21T12:34:56.846167233Z",
            "not_before": "2026-07-20T12:34:51.123456789Z",
            "role": "client",
            "tags": [],
            "issuer": "node-issuer",
            "key_id": "client-enrollment",
            "policy": {
              "allow_join": true,
              "allow_relay": false,
              "allowed_routes": [],
              "allowed_tags": [],
              "max_token_uses": 1
            },
            "nonce": "client-enroll-precision-test"
          },
          "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }
        """#
        let tokenData = try XCTUnwrap(rawToken.data(using: .utf8))
        let uri = "heteronetwork://enroll?token=\(tokenData.base64URLEncodedString())"
        let token = try EnrollmentParser.parse(
            uri,
            now: Date(timeIntervalSince1970: 1_784_550_896)
        )
        let request = JoinClientRequest(
            token: token,
            registration: RegisterClientRequest(
                clientID: "node-client",
                identityPublicKey: "identity-public-key",
                wireGuardPublicKey: "wireguard-public-key"
            )
        )

        let encoded = try HeteroNetworkCoding.makeEncoder().encode(request)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        let tokenObject = try XCTUnwrap(object["token"] as? [String: Any])
        let claims = try XCTUnwrap(tokenObject["claims"] as? [String: Any])
        XCTAssertEqual(claims["expires_at"] as? String, "2026-07-21T12:34:56.846167233Z")
        XCTAssertEqual(claims["not_before"] as? String, "2026-07-20T12:34:51.123456789Z")
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
