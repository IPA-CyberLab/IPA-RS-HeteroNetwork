import CryptoKit
import XCTest
@testable import HeteroNetworkCore

final class SponsoredEnrollmentTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_784_550_896)

    func testRegistrationSignatureMatchesRustFixedVector() throws {
        let identity = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 9, count: 32)
        )
        let unsigned = ClientRegistrationBundle(
            registration: RegisterClientRequest(
                clientID: "node-dbc298251c51321b7266e78d1c151c2b",
                identityPublicKey:
                    "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=",
                wireGuardPublicKey:
                    "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="
            ),
            issuedAt: Date(timeIntervalSince1970: 1_785_412_800),
            expiresAt: Date(timeIntervalSince1970: 1_785_416_400),
            nonce: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF",
            signature: ""
        )
        let signature = try identity.signature(for: unsigned.signingPayload())
            .base64EncodedString()
        let bundle = ClientRegistrationBundle(
            registration: unsigned.registration,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            nonce: unsigned.nonce,
            signature: signature
        )

        XCTAssertEqual(
            bundle.registration.clientID,
            "node-dbc298251c51321b7266e78d1c151c2b"
        )
        XCTAssertEqual(
            bundle.signature,
            "X084nfek9SQJlfKOEjrupHiAPaapn9fxsNpWYIBFwcD9YHn8f8qdS/XV1F2Te3HQPk1LYVrkmaeGXXTDGvJaBg=="
        )
        XCTAssertEqual(
            try SponsoredEnrollment.parseRegistrationURI(
                bundle.uri(),
                now: bundle.issuedAt
            ),
            bundle
        )
    }

    func testRegistrationRejectsTamperedPublicKey() throws {
        let pending = try fixedPending()
        let data = try HeteroNetworkCoding.makeEncoder().encode(pending.bundle)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        var registration = try XCTUnwrap(object["registration"] as? [String: Any])
        registration["wireguard_public_key"] =
            Data(repeating: 10, count: 32).base64EncodedString()
        object["registration"] = registration
        let tampered = try JSONSerialization.data(withJSONObject: object)
        let uri =
            "heteronetwork://register?request=\(tampered.base64URLEncodedString())"

        XCTAssertThrowsError(
            try SponsoredEnrollment.parseRegistrationURI(uri, now: now)
        ) { error in
            XCTAssertEqual(error as? SponsoredEnrollmentError, .invalidSignature)
        }
    }

    func testRegistrationRejectsExpiredBundle() throws {
        let pending = try fixedPending()

        XCTAssertThrowsError(
            try SponsoredEnrollment.parseRegistrationURI(
                pending.bundle.uri(),
                now: now.addingTimeInterval(901)
            )
        ) { error in
            XCTAssertEqual(error as? SponsoredEnrollmentError, .expired)
        }
    }

    func testImportsMatchingProfileUsingCachedPrivateGateways() throws {
        let pending = try fixedPending()
        let uri = try importURI(
            pending: pending,
            unknownProfileField: ["future": true]
        )

        let session = try SponsoredEnrollment.importProfile(
            uri,
            pending: pending,
            now: now
        )

        XCTAssertEqual(session.identityPrivateKey, pending.identityPrivateKey)
        XCTAssertEqual(session.wireGuardPrivateKey, pending.wireGuardPrivateKey)
        XCTAssertEqual(session.client.nodeID, pending.bundle.registration.clientID)
        XCTAssertEqual(session.peerMap.peers.count, 1)
        XCTAssertEqual(session.peerMap.peers[0].endpointCandidates.count, 1)
        XCTAssertEqual(
            session.peerMap.peers[0].endpointCandidates[0].address,
            "8.8.8.8:51820"
        )
        XCTAssertEqual(
            session.controlPlaneURLs,
            [URL(string: "http://10.250.0.4:19088")!]
        )
        XCTAssertNoThrow(try TunnelProfile(session: session))
    }

    func testImportRejectsPendingKeyMismatch() throws {
        let pending = try fixedPending()
        let uri = try importURI(
            pending: pending,
            clientIdentityPublicKey: Data(repeating: 12, count: 32).base64EncodedString()
        )

        XCTAssertThrowsError(
            try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
        ) { error in
            XCTAssertEqual(
                error as? SponsoredEnrollmentError,
                .pendingRegistrationMismatch
            )
        }
    }

    func testImportRejectsExpiredProfile() throws {
        let pending = try fixedPending()
        let uri = try importURI(
            pending: pending,
            issuedAt: now.addingTimeInterval(-120),
            expiresAt: now.addingTimeInterval(-1)
        )

        XCTAssertThrowsError(
            try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
        ) { error in
            XCTAssertEqual(error as? SponsoredEnrollmentError, .expired)
        }
    }

    func testImportRejectsUnsupportedSchema() throws {
        let pending = try fixedPending()
        let uri = try importURI(pending: pending, schemaVersion: 2)

        XCTAssertThrowsError(
            try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
        ) { error in
            XCTAssertEqual(
                error as? SponsoredEnrollmentError,
                .unsupportedSchema(2)
            )
        }
    }

    func testImportRequiresOneToFourGateways() throws {
        let pending = try fixedPending()
        for count in [0, 5] {
            let uri = try importURI(pending: pending, gatewayCount: count)
            XCTAssertThrowsError(
                try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
            ) { error in
                XCTAssertEqual(
                    error as? SponsoredEnrollmentError,
                    .invalidGatewayCount(count)
                )
            }
        }
    }

    func testImportRejectsPrivateOrSTUNOnlyGateway() throws {
        let pending = try fixedPending()
        for candidateValue in [
            candidate(kind: "public_udp", address: "10.250.0.4:51820"),
            candidate(kind: "stun_reflexive", address: "8.8.8.8:51820"),
        ] {
            let uri = try importURI(
                pending: pending,
                gatewayCandidate: candidateValue
            )
            XCTAssertThrowsError(
                try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
            ) { error in
                XCTAssertEqual(
                    error as? SponsoredEnrollmentError,
                    .invalidGateway("node-gateway")
                )
            }
        }

        let mixedURI = try importURI(
            pending: pending,
            extraCandidates: [
                candidate(kind: "stun_reflexive", address: "8.8.8.8:51820")
            ]
        )
        XCTAssertThrowsError(
            try SponsoredEnrollment.importProfile(
                mixedURI,
                pending: pending,
                now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? SponsoredEnrollmentError,
                .invalidGateway("node-gateway")
            )
        }
    }

    func testImportRejectsPublicManagementURL() throws {
        let pending = try fixedPending()
        let uri = try importURI(
            pending: pending,
            managementURLs: ["https://management.example:443"]
        )

        XCTAssertThrowsError(
            try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
        ) { error in
            XCTAssertEqual(
                error as? SponsoredEnrollmentError,
                .invalidManagementURL("https://management.example:443")
            )
        }
    }

    func testRegistrationAndProfileContainNoPrivateKeys() throws {
        let pending = try fixedPending()
        let requestData = try XCTUnwrap(
            Data(
                base64URLEncoded: try encodedQueryValue(
                    pending.bundle.uri(),
                    name: "request"
                )
            )
        )
        let requestText = String(decoding: requestData, as: UTF8.self)
        XCTAssertFalse(requestText.contains("private_key"))
        XCTAssertFalse(
            requestText.contains(pending.identityPrivateKey.base64EncodedString())
        )
        XCTAssertFalse(
            requestText.contains(pending.wireGuardPrivateKey.base64EncodedString())
        )

        let profileURI = try importURI(pending: pending)
        let profileData = try XCTUnwrap(
            Data(
                base64URLEncoded: try encodedQueryValue(
                    profileURI,
                    name: "profile"
                )
            )
        )
        let profileText = String(decoding: profileData, as: UTF8.self)
        XCTAssertFalse(profileText.contains("private_key"))
        XCTAssertFalse(
            profileText.contains(pending.identityPrivateKey.base64EncodedString())
        )
        XCTAssertFalse(
            profileText.contains(pending.wireGuardPrivateKey.base64EncodedString())
        )
    }

    func testImportRejectsUnknownPrivateKeyField() throws {
        let pending = try fixedPending()
        for fieldName in [
            "WIREGUARD_PRIVATE_KEY",
            "identityPrivateKey",
            "future_private_key",
        ] {
            let uri = try importURI(
                pending: pending,
                unknownProfileField: [
                    fieldName: pending.wireGuardPrivateKey.base64EncodedString()
                ]
            )

            XCTAssertThrowsError(
                try SponsoredEnrollment.importProfile(uri, pending: pending, now: now)
            ) { error in
                XCTAssertEqual(
                    error as? SponsoredEnrollmentError,
                    .containsPrivateKeyMaterial
                )
            }
        }
    }

    private func fixedPending() throws -> PendingClientRegistration {
        let keys = try ClientKeyMaterial(
            identityPrivateKey: Data(repeating: 7, count: 32),
            wireGuardPrivateKey: Data(repeating: 9, count: 32)
        )
        return try SponsoredEnrollment.makeRegistration(
            keyMaterial: keys,
            issuedAt: now,
            lifetime: 900,
            nonce: Data(repeating: 3, count: 24)
        )
    }

    private func importURI(
        pending: PendingClientRegistration,
        schemaVersion: Int = 1,
        gatewayCount: Int = 1,
        clientIdentityPublicKey: String? = nil,
        gatewayCandidate: [String: Any]? = nil,
        extraCandidates: [[String: Any]] = [],
        managementURLs: [String] = ["http://10.250.0.4:19088"],
        issuedAt: Date? = nil,
        expiresAt: Date? = nil,
        unknownProfileField: [String: Any]? = nil
    ) throws -> String {
        let registration = pending.bundle.registration
        let issued = issuedAt ?? now.addingTimeInterval(-1)
        let expires = expiresAt ?? now.addingTimeInterval(600)
        var candidates = [
            gatewayCandidate ?? candidate(kind: "public_udp", address: "8.8.8.8:51820")
        ]
        candidates.append(contentsOf: extraCandidates)
        let gateway: [String: Any] = [
            "node_id": "node-gateway",
            "cluster_id": "cluster-a",
            "vpn_ip": "10.250.0.4",
            "identity_public_key":
                Data(repeating: 1, count: 32).base64EncodedString(),
            "wireguard_public_key":
                Data(repeating: 2, count: 32).base64EncodedString(),
            "role": "edge",
            "tags": [],
            "endpoint_candidates": candidates,
            "routes": [],
            "registered_at": timestamp(issued),
        ]
        var profile: [String: Any] = [
            "schema_version": schemaVersion,
            "sponsor_node_id": "node-sponsor",
            "registration": [
                "client": [
                    "node_id": registration.clientID,
                    "cluster_id": "cluster-a",
                    "vpn_ip": "10.250.0.100",
                    "identity_public_key":
                        clientIdentityPublicKey ?? registration.identityPublicKey,
                    "wireguard_public_key": registration.wireGuardPublicKey,
                    "role": "client",
                    "tags": [],
                    "endpoint_candidates": [],
                    "routes": [],
                    "registered_at": timestamp(issued),
                ],
                "peer_map": [
                    "cluster_id": "cluster-a",
                    "peers": Array(repeating: gateway, count: gatewayCount),
                    "bootstrap_endpoints": [
                        [
                            "url": "http://10.250.0.4:19088",
                            "kind": "control_plane",
                        ],
                    ],
                    "generated_at": timestamp(issued),
                ],
                "cluster_policy": [
                    "allow_ipv6_direct": true,
                    "future_policy_field": ["accepted": true],
                ],
            ],
            "management_urls": managementURLs,
            "issued_at": timestamp(issued),
            "expires_at": timestamp(expires),
        ]
        if let unknownProfileField {
            profile["future_profile_field"] = unknownProfileField
        }
        let data = try JSONSerialization.data(withJSONObject: profile)
        return "heteronetwork://import?profile=\(data.base64URLEncodedString())"
    }

    private func candidate(kind: String, address: String) -> [String: Any] {
        [
            "node_id": "node-gateway",
            "kind": kind,
            "addr": address,
            "observed_at": timestamp(now),
            "priority": 100,
            "cost": 1,
            "source": "interface_scan",
        ]
    }

    private func timestamp(_ date: Date) -> String {
        HeteroNetworkCoding.rfc3339String(from: date)
    }

    private func encodedQueryValue(_ uri: String, name: String) throws -> String {
        let components = try XCTUnwrap(URLComponents(string: uri))
        return try XCTUnwrap(
            components.queryItems?.first(where: { $0.name == name })?.value
        )
    }
}
