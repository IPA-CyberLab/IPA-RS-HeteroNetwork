import CryptoKit
import XCTest
@testable import HeteroNetworkCore

final class ClientSignatureTests: XCTestCase {
    func testSignatureMatchesRustGoldenVector() throws {
        let keys = try ClientKeyMaterial(
            identityPrivateKey: Data(repeating: 7, count: 32),
            wireGuardPrivateKey: Data(repeating: 9, count: 32)
        )
        let clientID = try keys.clientID
        XCTAssertEqual(clientID, "node-fe812c12f3ab4ce6ac5db69ac352f906")

        let signature = try keys.sign(
            clientID: clientID,
            kind: .peerMap,
            at: Date(timeIntervalSince1970: 1_784_550_896),
            nonce: Data(repeating: 3, count: 24)
        )

        XCTAssertEqual(signature.nonce, "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD")
        let payload = Data(
            "heteronetwork-client-request-v1\npeer_map\nnode-fe812c12f3ab4ce6ac5db69ac352f906\n1784550896\nAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD\n".utf8
        )
        let publicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey
        let swiftSignature = try XCTUnwrap(Data(base64Encoded: signature.signature))
        let rustSignature = try XCTUnwrap(Data(
            base64Encoded: "34UsDq5YNr83tomJ2N2o3cgPcaPIihje5uO+OjPp3Ad9DIZJs9Tiu6Dek8OWMkNKPbf+5+ythYm1WTkQWVlGBg=="
        ))

        // CryptoKit randomizes Ed25519 signing, so verify both implementations.
        XCTAssertTrue(publicKey.isValidSignature(swiftSignature, for: payload))
        XCTAssertTrue(publicKey.isValidSignature(rustSignature, for: payload))
    }
}
