import Darwin
import Foundation
#if canImport(HeteroNetworkCore)
import HeteroNetworkCore
#endif

private enum LiveE2EError: LocalizedError {
    case disabled
    case usage
    case missingRegistration
    case roundTripFailed
    case invalidPrivateFile
    case invalidKeyMaterial
    case writeFailed

    var errorDescription: String? {
        switch self {
        case .disabled:
            return "Set HETERONETWORK_LIVE_E2E=1 to run the destructive live test."
        case .usage:
            return "Usage: macos-live-e2e {request FILE|import PROFILE CONFIG|configure PROFILE CONFIG|remove PROFILE|purge}"
        case .missingRegistration:
            return "No active or pending client registration is available."
        case .roundTripFailed:
            return "The Keychain value did not survive a save/load round trip."
        case .invalidPrivateFile:
            return "A private E2E file failed ownership, mode, type, or size validation."
        case .invalidKeyMaterial:
            return "The imported tunnel profile contains invalid key material."
        case .writeFailed:
            return "A private E2E file could not be created."
        }
    }
}

private struct RootTunnelConfiguration: Encodable {
    let schemaVersion = 1
    let ownerUID: Int
    let privateKey: String
    let clientAddress: String
    let gatewayNodeID: String
    let gatewayVPNIP: String
    let gatewayWireGuardPublicKey: String
    let gatewayEndpoint: String
    let allowedIPs: [String]
    let dnsServer: String
    let dnsDomain = HeteroNetworkConstants.overlayDNSZone
    let mtu = 1280

    init(session: ClientSession) throws {
        let gatewayIndex: Int
        if let selected = session.selectedGatewayNodeID,
           let index = session.peerMap.peers.firstIndex(where: { $0.nodeID == selected }) {
            gatewayIndex = index
        } else {
            gatewayIndex = 0
        }
        let profile = try TunnelProfile(session: session, gatewayIndex: gatewayIndex)
        guard session.wireGuardPrivateKey.count == 32,
              let gatewayKey = Data(base64Encoded: profile.gatewayWireGuardPublicKey),
              gatewayKey.count == 32
        else {
            throw LiveE2EError.invalidKeyMaterial
        }
        ownerUID = Int(getuid())
        privateKey = session.wireGuardPrivateKey.lowercaseHexadecimalString
        clientAddress = profile.clientAddress
        gatewayNodeID = profile.gatewayNodeID
        gatewayVPNIP = profile.gatewayVPNIP
        gatewayWireGuardPublicKey = gatewayKey.lowercaseHexadecimalString
        gatewayEndpoint = profile.gatewayEndpoint
        allowedIPs = profile.allowedIPs
        dnsServer = profile.gatewayVPNIP
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case ownerUID = "owner_uid"
        case privateKey = "private_key"
        case clientAddress = "client_address"
        case gatewayNodeID = "gateway_node_id"
        case gatewayVPNIP = "gateway_vpn_ip"
        case gatewayWireGuardPublicKey = "gateway_wireguard_public_key"
        case gatewayEndpoint = "gateway_endpoint"
        case allowedIPs = "allowed_ips"
        case dnsServer = "dns_server"
        case dnsDomain = "dns_domain"
        case mtu
    }
}

@main
private struct LiveE2ECommand {
    private static let store = ClientSessionStore()

    static func main() async {
        do {
            guard ProcessInfo.processInfo.environment["HETERONETWORK_LIVE_E2E"] == "1" else {
                throw LiveE2EError.disabled
            }
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard let command = arguments.first else { throw LiveE2EError.usage }
            switch command {
            case "request" where arguments.count == 2:
                try request(outputPath: arguments[1])
            case "import" where arguments.count == 3:
                let session = try importSession(profilePath: arguments[1])
                try writeConfiguration(session: session, path: arguments[2])
                try emit([
                    "keychain_session_round_trip": true,
                    "profile_imported": true,
                    "tunnel_configuration_created": true,
                ])
            case "configure" where arguments.count == 3:
                let session = try ensureSession(profilePath: arguments[1])
                try writeConfiguration(session: session, path: arguments[2])
                try emit(["tunnel_configuration_created": true])
            case "remove" where arguments.count == 2:
                try await remove(profilePath: arguments[1])
            case "purge" where arguments.count == 1:
                try purge()
                try emit(["keychain_purged": true])
            default:
                throw LiveE2EError.usage
            }
        } catch {
            let message = error.localizedDescription
                .replacingOccurrences(of: "\n", with: " ")
                .prefix(512)
            FileHandle.standardError.write(
                Data("macOS live E2E failed: \(message)\n".utf8)
            )
            exit(1)
        }
    }

    private static func request(outputPath: String) throws {
        try store.delete()
        try store.deletePendingRegistration()
        let pending = try SponsoredEnrollment.makeRegistration()
        try store.savePendingRegistration(pending)
        guard try store.loadPendingRegistration() == pending else {
            throw LiveE2EError.roundTripFailed
        }
        let registrationURI = try pending.bundle.uri()
        try writePrivate(Data(registrationURI.utf8), path: outputPath)
        try emit([
            "keychain_pending_round_trip": true,
            "registration_request_created": true,
        ])
    }

    private static func importSession(profilePath: String) throws -> ClientSession {
        guard let pending = try store.loadPendingRegistration() else {
            throw LiveE2EError.missingRegistration
        }
        let session = try SponsoredEnrollment.importProfile(
            readPrivateText(path: profilePath),
            pending: pending
        )
        try store.completeImport(pending: pending, session: session)
        guard try store.load() == session else { throw LiveE2EError.roundTripFailed }
        return session
    }

    private static func ensureSession(profilePath: String) throws -> ClientSession {
        if let session = try store.load() { return session }
        return try importSession(profilePath: profilePath)
    }

    private static func writeConfiguration(session: ClientSession, path: String) throws {
        let configuration = try RootTunnelConfiguration(session: session)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try writePrivate(encoder.encode(configuration), path: path)
    }

    private static func remove(profilePath: String) async throws {
        let session = try ensureSession(profilePath: profilePath)
        do {
            try await ControlPlaneClient().remove(session)
        } catch let error as ControlPlaneAPIError {
            switch error {
            case .rejected(let statusCode, _) where statusCode == 404:
                break
            default:
                throw error
            }
        }
        try purge()
        try emit(["client_removed": true, "keychain_purged": true])
    }

    private static func purge() throws {
        try store.delete()
        try store.deletePendingRegistration()
    }

    private static func readPrivateText(path: String) throws -> String {
        let data = try readPrivate(path: path)
        guard let value = String(data: data, encoding: .utf8), !value.isEmpty else {
            throw LiveE2EError.invalidPrivateFile
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func readPrivate(path: String) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.referenceCount] as? NSNumber)?.intValue == 1,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue,
              permissions & 0o077 == 0,
              let size = (attributes[.size] as? NSNumber)?.intValue,
              (1...(256 * 1024)).contains(size)
        else {
            throw LiveE2EError.invalidPrivateFile
        }
        let values = try URL(fileURLWithPath: path).resourceValues(forKeys: [.isSymbolicLinkKey])
        guard values.isSymbolicLink != true else { throw LiveE2EError.invalidPrivateFile }
        return try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
    }

    private static func writePrivate(_ data: Data, path: String) throws {
        guard !data.isEmpty, data.count <= 256 * 1024 else {
            throw LiveE2EError.writeFailed
        }
        let manager = FileManager.default
        if manager.fileExists(atPath: path) {
            try manager.removeItem(atPath: path)
        }
        guard manager.createFile(
            atPath: path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw LiveE2EError.writeFailed
        }
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }

    private static func emit(_ value: [String: Bool]) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}

private extension Data {
    var lowercaseHexadecimalString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
