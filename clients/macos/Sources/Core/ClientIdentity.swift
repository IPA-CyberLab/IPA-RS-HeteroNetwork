import CryptoKit
import Foundation
import Security

public enum ClientIdentityError: LocalizedError {
    case invalidIdentityKey
    case invalidWireGuardKey
    case randomGenerationFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidIdentityKey: return "The saved client identity key is invalid."
        case .invalidWireGuardKey: return "The saved WireGuard key is invalid."
        case .randomGenerationFailed(let status):
            return "Secure random generation failed (\(status))."
        }
    }
}

public struct ClientKeyMaterial: Equatable, Sendable {
    public let identityPrivateKey: Data
    public let wireGuardPrivateKey: Data

    public init(identityPrivateKey: Data, wireGuardPrivateKey: Data) throws {
        guard identityPrivateKey.count == 32 else { throw ClientIdentityError.invalidIdentityKey }
        guard wireGuardPrivateKey.count == 32 else { throw ClientIdentityError.invalidWireGuardKey }
        self.identityPrivateKey = identityPrivateKey
        self.wireGuardPrivateKey = wireGuardPrivateKey
    }

    public static func generate() -> ClientKeyMaterial {
        let identity = Curve25519.Signing.PrivateKey()
        let wireGuard = Curve25519.KeyAgreement.PrivateKey()
        return try! ClientKeyMaterial(
            identityPrivateKey: identity.rawRepresentation,
            wireGuardPrivateKey: wireGuard.rawRepresentation
        )
    }

    public var identityPublicKey: String {
        get throws {
            try Curve25519.Signing.PrivateKey(rawRepresentation: identityPrivateKey)
                .publicKey.rawRepresentation.base64EncodedString()
        }
    }

    public var wireGuardPublicKey: String {
        get throws {
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: wireGuardPrivateKey)
                .publicKey.rawRepresentation.base64EncodedString()
        }
    }

    public var clientID: String {
        get throws {
            let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: identityPrivateKey)
                .publicKey.rawRepresentation
            let digest = SHA256.hash(data: publicKey)
            return "node-" + digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        }
    }

    public func sign(
        clientID: String,
        kind: ClientRequestKind,
        activeGatewayNodeID: String? = nil,
        at date: Date = Date(),
        nonce: Data? = nil
    ) throws -> ClientRequestSignature {
        let nonceData = try nonce ?? secureRandomData(count: 24)
        guard nonceData.count == 24 else { throw ClientIdentityError.randomGenerationFailed(-1) }
        let nonceValue = nonceData.base64URLEncodedString()
        let timestamp = Int64(date.timeIntervalSince1970.rounded(.down))
        let payload: String
        if let activeGatewayNodeID {
            payload = "heteronetwork-client-request-v2\n\(kind.rawValue)\n\(clientID)\n\(activeGatewayNodeID)\n\(timestamp)\n\(nonceValue)\n"
        } else {
            payload = "heteronetwork-client-request-v1\n\(kind.rawValue)\n\(clientID)\n\(timestamp)\n\(nonceValue)\n"
        }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: identityPrivateKey)
        let signature = try key.signature(for: Data(payload.utf8))
        return ClientRequestSignature(
            signedAt: Date(timeIntervalSince1970: TimeInterval(timestamp)),
            nonce: nonceValue,
            signature: signature.base64EncodedString()
        )
    }

    private func secureRandomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw ClientIdentityError.randomGenerationFailed(status)
        }
        return data
    }
}
