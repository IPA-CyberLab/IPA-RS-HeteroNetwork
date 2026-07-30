import CryptoKit
import Foundation
import Security

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum SponsoredEnrollmentError: LocalizedError, Equatable {
    case empty
    case invalidLink
    case oversized
    case malformedRegistration
    case malformedProfile
    case unsupportedSchema(Int)
    case invalidKeyMaterial
    case invalidClientID
    case invalidNonce
    case invalidValidityWindow
    case notYetValid
    case expired
    case invalidSignature
    case pendingRegistrationMissing
    case pendingRegistrationMismatch
    case wrongRole
    case clusterMismatch
    case invalidSponsorNodeID
    case invalidGatewayCount(Int)
    case invalidGateway(String)
    case invalidManagementURL(String)
    case missingClusterPolicy
    case containsPrivateKeyMaterial

    public var errorDescription: String? {
        switch self {
        case .empty: return "A registration or import URI is required."
        case .invalidLink: return "The HeteroNetwork URI is invalid."
        case .oversized: return "The HeteroNetwork profile is too large."
        case .malformedRegistration: return "The registration request is malformed."
        case .malformedProfile: return "The import profile is malformed."
        case .unsupportedSchema(let version):
            return "Profile schema version \(version) is unsupported."
        case .invalidKeyMaterial: return "The profile contains invalid public key material."
        case .invalidClientID: return "The client ID does not match the identity public key."
        case .invalidNonce: return "The registration nonce is invalid."
        case .invalidValidityWindow: return "The profile validity window is invalid."
        case .notYetValid: return "The profile is not valid yet."
        case .expired: return "The profile has expired."
        case .invalidSignature: return "The registration request signature is invalid."
        case .pendingRegistrationMissing:
            return "Generate a registration request on this Mac before importing a profile."
        case .pendingRegistrationMismatch:
            return "The import profile does not match this Mac's pending keys."
        case .wrongRole: return "The imported participant is not a client."
        case .clusterMismatch: return "The client and gateway map belong to different clusters."
        case .invalidSponsorNodeID: return "The sponsor node ID is invalid."
        case .invalidGatewayCount(let count):
            return "The import profile must contain 1 to 4 gateways; received \(count)."
        case .invalidGateway(let nodeID):
            return "Gateway \(nodeID) has no globally routable WireGuard endpoint."
        case .invalidManagementURL(let value):
            return "Management URL is not private to HeteroNetwork: \(value)"
        case .missingClusterPolicy: return "The import profile is missing cluster policy."
        case .containsPrivateKeyMaterial:
            return "An importable profile must not contain private key material."
        }
    }
}

public struct ClientRegistrationBundle: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let registration: RegisterClientRequest
    public let issuedAt: Date
    public let expiresAt: Date
    public let nonce: String
    public let signature: String

    public init(
        schemaVersion: Int = 1,
        registration: RegisterClientRequest,
        issuedAt: Date,
        expiresAt: Date,
        nonce: String,
        signature: String
    ) {
        self.schemaVersion = schemaVersion
        self.registration = registration
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.nonce = nonce
        self.signature = signature
    }

    public func uri() throws -> String {
        let data = try HeteroNetworkCoding.makeEncoder().encode(self)
        return "heteronetwork://register?request=\(data.base64URLEncodedString())"
    }

    public func validate(now: Date = Date()) throws {
        guard schemaVersion == 1 else {
            throw SponsoredEnrollmentError.unsupportedSchema(schemaVersion)
        }
        try SponsoredEnrollment.validateRegistration(registration)
        guard let nonceData = Data(base64URLEncoded: nonce),
              nonceData.count == 24,
              nonceData.base64URLEncodedString() == nonce
        else {
            throw SponsoredEnrollmentError.invalidNonce
        }
        try SponsoredEnrollment.validateWindow(
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            now: now
        )
        guard let signatureData = Data(base64Encoded: signature),
              signatureData.count == 64,
              signatureData.base64EncodedString() == signature,
              let publicKeyData = Data(base64Encoded: registration.identityPublicKey),
              let publicKey = try? Curve25519.Signing.PublicKey(
                  rawRepresentation: publicKeyData
              ),
              publicKey.isValidSignature(signatureData, for: signingPayload())
        else {
            throw SponsoredEnrollmentError.invalidSignature
        }
    }

    public func signingPayload() -> Data {
        let value =
            "heteronetwork-client-registration-v1\n"
            + "\(registration.clientID)\n"
            + "\(registration.identityPublicKey)\n"
            + "\(registration.wireGuardPublicKey)\n"
            + "\(Int64(issuedAt.timeIntervalSince1970.rounded(.down)))\n"
            + "\(Int64(expiresAt.timeIntervalSince1970.rounded(.down)))\n"
            + "\(nonce)\n"
        return Data(value.utf8)
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case registration
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case nonce, signature
    }
}

public struct PendingClientRegistration: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let identityPrivateKey: Data
    public let wireGuardPrivateKey: Data
    public let bundle: ClientRegistrationBundle

    public init(
        identityPrivateKey: Data,
        wireGuardPrivateKey: Data,
        bundle: ClientRegistrationBundle
    ) {
        schemaVersion = 1
        self.identityPrivateKey = identityPrivateKey
        self.wireGuardPrivateKey = wireGuardPrivateKey
        self.bundle = bundle
    }

    public var keyMaterial: ClientKeyMaterial {
        get throws {
            try ClientKeyMaterial(
                identityPrivateKey: identityPrivateKey,
                wireGuardPrivateKey: wireGuardPrivateKey
            )
        }
    }

    public func validate() throws {
        guard schemaVersion == 1 else {
            throw SponsoredEnrollmentError.unsupportedSchema(schemaVersion)
        }
        let keys = try keyMaterial
        guard bundle.registration.clientID == (try keys.clientID),
              bundle.registration.identityPublicKey == (try keys.identityPublicKey),
              bundle.registration.wireGuardPublicKey == (try keys.wireGuardPublicKey)
        else {
            throw SponsoredEnrollmentError.pendingRegistrationMismatch
        }
        try bundle.validate(now: bundle.issuedAt)
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case identityPrivateKey = "identity_private_key"
        case wireGuardPrivateKey = "wireguard_private_key"
        case bundle
    }
}

public struct ClientImportProfile: Decodable, Sendable {
    public let schemaVersion: Int
    public let sponsorNodeID: String
    public let registration: RegisterClientResponse
    public let managementURLs: [URL]
    public let issuedAt: Date
    public let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case sponsorNodeID = "sponsor_node_id"
        case registration
        case managementURLs = "management_urls"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
    }
}

public enum SponsoredEnrollment {
    private static let maximumProfileBytes = 128 * 1024
    private static let clockSkew: TimeInterval = 5
    private static let maximumValidity: TimeInterval = 24 * 60 * 60
    public static let registrationLifetime: TimeInterval = 15 * 60

    public static func makeRegistration(
        keyMaterial: ClientKeyMaterial = .generate(),
        issuedAt: Date = Date(),
        lifetime: TimeInterval = registrationLifetime,
        nonce: Data? = nil
    ) throws -> PendingClientRegistration {
        guard lifetime.isFinite,
              lifetime >= 1,
              lifetime <= maximumValidity
        else {
            throw SponsoredEnrollmentError.invalidValidityWindow
        }
        let issuedSeconds = Int64(issuedAt.timeIntervalSince1970.rounded(.down))
        let expiresSeconds = issuedSeconds + Int64(lifetime.rounded(.down))
        guard expiresSeconds > issuedSeconds else {
            throw SponsoredEnrollmentError.invalidValidityWindow
        }
        let normalizedIssuedAt = Date(timeIntervalSince1970: TimeInterval(issuedSeconds))
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(expiresSeconds))
        let nonceData = try nonce ?? secureRandomData(count: 24)
        guard nonceData.count == 24 else {
            throw SponsoredEnrollmentError.invalidNonce
        }
        let registration = RegisterClientRequest(
            clientID: try keyMaterial.clientID,
            identityPublicKey: try keyMaterial.identityPublicKey,
            wireGuardPublicKey: try keyMaterial.wireGuardPublicKey
        )
        let unsigned = ClientRegistrationBundle(
            registration: registration,
            issuedAt: normalizedIssuedAt,
            expiresAt: expiresAt,
            nonce: nonceData.base64URLEncodedString(),
            signature: ""
        )
        let privateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: keyMaterial.identityPrivateKey
        )
        let signature = try privateKey.signature(for: unsigned.signingPayload())
        let bundle = ClientRegistrationBundle(
            registration: registration,
            issuedAt: normalizedIssuedAt,
            expiresAt: expiresAt,
            nonce: unsigned.nonce,
            signature: signature.base64EncodedString()
        )
        return PendingClientRegistration(
            identityPrivateKey: keyMaterial.identityPrivateKey,
            wireGuardPrivateKey: keyMaterial.wireGuardPrivateKey,
            bundle: bundle
        )
    }

    public static func parseRegistrationURI(
        _ input: String,
        now: Date = Date()
    ) throws -> ClientRegistrationBundle {
        let data = try payloadData(from: input, host: "register", queryName: "request")
        let bundle: ClientRegistrationBundle
        do {
            bundle = try HeteroNetworkCoding.makeDecoder().decode(
                ClientRegistrationBundle.self,
                from: data
            )
        } catch {
            throw SponsoredEnrollmentError.malformedRegistration
        }
        try bundle.validate(now: now)
        return bundle
    }

    public static func importProfile(
        _ input: String,
        pending: PendingClientRegistration?,
        now: Date = Date()
    ) throws -> ClientSession {
        guard let pending else {
            throw SponsoredEnrollmentError.pendingRegistrationMissing
        }
        let data = try payloadData(from: input, host: "import", queryName: "profile")
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw SponsoredEnrollmentError.malformedProfile
        }
        if containsPrivateKeyMaterial(in: object) {
            throw SponsoredEnrollmentError.containsPrivateKeyMaterial
        }
        guard let root = object as? [String: Any],
              let registration = root["registration"] as? [String: Any],
              registration["cluster_policy"] is [String: Any]
        else {
            throw SponsoredEnrollmentError.missingClusterPolicy
        }
        let profile: ClientImportProfile
        do {
            profile = try HeteroNetworkCoding.makeDecoder().decode(
                ClientImportProfile.self,
                from: data
            )
        } catch {
            throw SponsoredEnrollmentError.malformedProfile
        }
        guard profile.schemaVersion == 1 else {
            throw SponsoredEnrollmentError.unsupportedSchema(profile.schemaVersion)
        }
        try validateWindow(
            issuedAt: profile.issuedAt,
            expiresAt: profile.expiresAt,
            now: now
        )
        guard validNodeID(profile.sponsorNodeID) else {
            throw SponsoredEnrollmentError.invalidSponsorNodeID
        }

        guard pending.schemaVersion == 1,
              let keyMaterial = try? pending.keyMaterial,
              (try? pending.validate()) != nil
        else {
            throw SponsoredEnrollmentError.pendingRegistrationMismatch
        }
        let pendingRegistration = pending.bundle.registration
        guard let derivedClientID = try? keyMaterial.clientID,
              let derivedIdentityPublicKey = try? keyMaterial.identityPublicKey,
              let derivedWireGuardPublicKey = try? keyMaterial.wireGuardPublicKey,
              pendingRegistration.clientID == derivedClientID,
              pendingRegistration.identityPublicKey == derivedIdentityPublicKey,
              pendingRegistration.wireGuardPublicKey == derivedWireGuardPublicKey
        else {
            throw SponsoredEnrollmentError.pendingRegistrationMismatch
        }

        let response = profile.registration
        let client = response.client
        guard client.nodeID == pendingRegistration.clientID,
              client.identityPublicKey == pendingRegistration.identityPublicKey,
              client.wireGuardPublicKey == pendingRegistration.wireGuardPublicKey
        else {
            throw SponsoredEnrollmentError.pendingRegistrationMismatch
        }
        guard client.role == "client" else {
            throw SponsoredEnrollmentError.wrongRole
        }
        guard client.clusterID == response.peerMap.clusterID,
              isIPAddress(client.vpnIP)
        else {
            throw SponsoredEnrollmentError.clusterMismatch
        }

        let peers = try validatedGateways(
            response.peerMap.peers,
            clusterID: client.clusterID,
            clientID: client.nodeID
        )
        let managementURLs = try validatedManagementURLs(profile.managementURLs)
        let peerMap = PeerMap(
            clusterID: response.peerMap.clusterID,
            peers: peers,
            bootstrapEndpoints: response.peerMap.bootstrapEndpoints,
            generatedAt: response.peerMap.generatedAt
        )
        let session = ClientSession(
            identityPrivateKey: keyMaterial.identityPrivateKey,
            wireGuardPrivateKey: keyMaterial.wireGuardPrivateKey,
            controlPlaneURLs: managementURLs,
            client: client,
            peerMap: peerMap,
            enrolledAt: profile.issuedAt
        )
        for index in session.peerMap.peers.indices {
            _ = try TunnelProfile(session: session, gatewayIndex: index)
        }
        return session
    }

    public static func isUsableGatewayCandidate(_ candidate: EndpointCandidate) -> Bool {
        guard let address = socketAddress(candidate.address) else { return false }
        switch candidate.kind {
        case .publicUDP:
            return isGloballyRoutableIPv4(address.host)
                || isGloballyRoutableIPv6(address.host)
        case .ipv6:
            return isGloballyRoutableIPv6(address.host)
        case .stunReflexive, .localUDP, .relay:
            return false
        }
    }

    public static func isPrivateManagementURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "http",
              let host = components.host?.lowercased(),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              components.port.map({ (1...65_535).contains($0) }) ?? true
        else {
            return false
        }
        if host == HeteroNetworkConstants.overlayDNSName {
            return true
        }
        var address = in_addr()
        guard host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            return false
        }
        return withUnsafeBytes(of: &address) { bytes in
            bytes.count == 4 && bytes[0] == 10 && bytes[1] == 250
        }
    }

    static func validateRegistration(_ registration: RegisterClientRequest) throws {
        guard let identityKey = canonicalBase64Data(
                  registration.identityPublicKey,
                  count: 32
              ),
              let wireGuardKey = canonicalBase64Data(
                  registration.wireGuardPublicKey,
                  count: 32
              ),
              wireGuardKey.contains(where: { $0 != 0 })
        else {
            throw SponsoredEnrollmentError.invalidKeyMaterial
        }
        let digest = SHA256.hash(data: identityKey)
        let expectedClientID =
            "node-" + digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        guard registration.clientID == expectedClientID else {
            throw SponsoredEnrollmentError.invalidClientID
        }
    }

    static func validateWindow(issuedAt: Date, expiresAt: Date, now: Date) throws {
        let validity = expiresAt.timeIntervalSince(issuedAt)
        guard validity >= 1, validity <= maximumValidity else {
            throw SponsoredEnrollmentError.invalidValidityWindow
        }
        guard issuedAt <= now.addingTimeInterval(clockSkew) else {
            throw SponsoredEnrollmentError.notYetValid
        }
        guard expiresAt > now else {
            throw SponsoredEnrollmentError.expired
        }
    }

    private static func payloadData(
        from input: String,
        host: String,
        queryName: String
    ) throws -> Data {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw SponsoredEnrollmentError.empty }
        guard trimmed.utf8.count <= maximumProfileBytes * 2 else {
            throw SponsoredEnrollmentError.oversized
        }
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "heteronetwork",
              components.host?.lowercased() == host,
              components.user == nil,
              components.password == nil,
              components.port == nil,
              components.path.isEmpty || components.path == "/",
              components.fragment == nil,
              let queryItems = components.queryItems,
              queryItems.count == 1,
              queryItems[0].name == queryName,
              let encoded = queryItems[0].value,
              !encoded.contains("="),
              let data = Data(base64URLEncoded: encoded),
              data.base64URLEncodedString() == encoded
        else {
            throw SponsoredEnrollmentError.invalidLink
        }
        guard data.count <= maximumProfileBytes else {
            throw SponsoredEnrollmentError.oversized
        }
        return data
    }

    private static func validatedGateways(
        _ peers: [NodeRecord],
        clusterID: String,
        clientID: String
    ) throws -> [NodeRecord] {
        guard (1...4).contains(peers.count) else {
            throw SponsoredEnrollmentError.invalidGatewayCount(peers.count)
        }
        var nodeIDs = Set<String>()
        return try peers.map { peer in
            guard peer.clusterID == clusterID,
                  peer.nodeID != clientID,
                  peer.role != "client",
                  nodeIDs.insert(peer.nodeID).inserted,
                  isIPAddress(peer.vpnIP),
                  let wireGuardKey = canonicalBase64Data(
                      peer.wireGuardPublicKey,
                      count: 32
                  ),
                  wireGuardKey.contains(where: { $0 != 0 })
            else {
                throw SponsoredEnrollmentError.invalidGateway(peer.nodeID)
            }
            guard !peer.endpointCandidates.isEmpty,
                  peer.endpointCandidates.allSatisfy({
                      $0.nodeID == peer.nodeID && isUsableGatewayCandidate($0)
                  })
            else {
                throw SponsoredEnrollmentError.invalidGateway(peer.nodeID)
            }
            return NodeRecord(
                nodeID: peer.nodeID,
                clusterID: peer.clusterID,
                vpnIP: peer.vpnIP,
                identityPublicKey: peer.identityPublicKey,
                wireGuardPublicKey: peer.wireGuardPublicKey,
                role: peer.role,
                tags: peer.tags,
                endpointCandidates: peer.endpointCandidates,
                routes: peer.routes,
                registeredAt: peer.registeredAt
            )
        }
    }

    private static func validatedManagementURLs(_ urls: [URL]) throws -> [URL] {
        guard (1...16).contains(urls.count) else {
            throw SponsoredEnrollmentError.invalidManagementURL("invalid URL count")
        }
        var seen = Set<String>()
        var validated = [URL]()
        for url in urls {
            guard isPrivateManagementURL(url) else {
                throw SponsoredEnrollmentError.invalidManagementURL(url.absoluteString)
            }
            let canonical = url.absoluteString.trimmingCharacters(
                in: CharacterSet(charactersIn: "/")
            )
            if seen.insert(canonical).inserted {
                validated.append(url)
            }
        }
        guard !validated.isEmpty else {
            throw SponsoredEnrollmentError.invalidManagementURL("empty")
        }
        return validated
    }

    private static func validNodeID(_ value: String) -> Bool {
        value.hasPrefix("node-")
            && value.count > 5
            && value.count <= 128
            && value.unicodeScalars.allSatisfy {
                (48...57).contains($0.value)
                    || (65...90).contains($0.value)
                    || (97...122).contains($0.value)
                    || $0 == "-"
                    || $0 == "_"
            }
    }

    private static func canonicalBase64Data(_ value: String, count: Int) -> Data? {
        guard let data = Data(base64Encoded: value),
              data.count == count,
              data.base64EncodedString() == value
        else {
            return nil
        }
        return data
    }

    private static func socketAddress(_ value: String) -> (host: String, port: UInt16)? {
        let host: String
        let portText: String
        if value.hasPrefix("[") {
            guard let closing = value.firstIndex(of: "]"),
                  value.index(after: closing) < value.endIndex,
                  value[value.index(after: closing)] == ":"
            else {
                return nil
            }
            host = String(value[value.index(after: value.startIndex)..<closing])
            portText = String(value[value.index(closing, offsetBy: 2)...])
        } else {
            let parts = value.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { return nil }
            host = String(parts[0])
            portText = String(parts[1])
        }
        guard !host.isEmpty,
              let port = UInt16(portText),
              port > 0
        else {
            return nil
        }
        return (host, port)
    }

    private static func isGloballyRoutableIPv4(_ host: String) -> Bool {
        var address = in_addr()
        guard host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
            return false
        }
        return withUnsafeBytes(of: &address) { bytes in
            guard bytes.count == 4 else { return false }
            let a = bytes[0]
            let b = bytes[1]
            let c = bytes[2]
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if a == 100 && (64...127).contains(b) { return false }
            if a == 169 && b == 254 { return false }
            if a == 172 && (16...31).contains(b) { return false }
            if a == 192 && b == 0 && c == 0 { return false }
            if a == 192 && b == 0 && c == 2 { return false }
            if a == 192 && b == 168 { return false }
            if a == 198 && (b == 18 || b == 19) { return false }
            if a == 198 && b == 51 && c == 100 { return false }
            if a == 203 && b == 0 && c == 113 { return false }
            return true
        }
    }

    private static func isGloballyRoutableIPv6(_ host: String) -> Bool {
        var address = in6_addr()
        guard !host.contains("%"),
              host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1
        else {
            return false
        }
        return withUnsafeBytes(of: &address) { bytes in
            guard bytes.count == 16 else { return false }
            if (bytes[0] & 0xe0) != 0x20 { return false }
            if bytes.allSatisfy({ $0 == 0 }) { return false }
            if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1 { return false }
            if bytes[0] == 0xff || (bytes[0] & 0xfe) == 0xfc { return false }
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { return false }
            if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d
                && bytes[3] == 0xb8
            {
                return false
            }
            if bytes.prefix(10).allSatisfy({ $0 == 0 })
                && bytes[10] == 0xff && bytes[11] == 0xff
            {
                return false
            }
            return true
        }
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return true
        }
        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
    }

    private static func containsPrivateKeyMaterial(in object: Any) -> Bool {
        func containsForbiddenKey(_ value: Any) -> Bool {
            if let dictionary = value as? [String: Any] {
                return dictionary.contains { key, child in
                    let normalized = key
                        .replacingOccurrences(of: "-", with: "_")
                        .lowercased()
                    return normalized.contains("private_key")
                        || normalized == "identityprivatekey"
                        || normalized == "wireguardprivatekey"
                        || containsForbiddenKey(child)
                }
            }
            if let array = value as? [Any] {
                return array.contains(where: containsForbiddenKey)
            }
            return false
        }
        return containsForbiddenKey(object)
    }

    private static func secureRandomData(count: Int) throws -> Data {
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
