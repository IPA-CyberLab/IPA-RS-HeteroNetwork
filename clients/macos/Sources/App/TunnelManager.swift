import Combine
import Darwin
import Foundation
import HeteroNetworkCore
import SwiftUI

enum TunnelStatus: Equatable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting

    var displayName: LocalizedStringKey {
        switch self {
        case .invalid: return "Not configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        }
    }

    var symbolName: String {
        switch self {
        case .connected: return "checkmark.shield.fill"
        case .connecting, .reasserting: return "arrow.triangle.2.circlepath"
        case .disconnecting: return "hourglass"
        case .invalid, .disconnected: return "shield.slash"
        }
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var status: TunnelStatus = .invalid
    @Published private(set) var activeGatewayNodeID: String?

    private static let installedHelperPath =
        "/Library/PrivilegedHelperTools/jp.go.ipa.cyberlab.heteronetwork.root-helper"

    func load(configured: Bool) async throws {
        guard configured else {
            status = .invalid
            activeGatewayNodeID = nil
            return
        }
        try await refreshStatus()
    }

    func prepare(for session: ClientSession) async throws {
        _ = try RootTunnelConfiguration(session: session)
        if status == .invalid {
            status = .disconnected
        }
    }

    func connect(_ session: ClientSession) async throws {
        switch status {
        case .connected, .connecting, .reasserting:
            return
        case .disconnecting:
            throw TunnelManagerError.busy
        case .invalid, .disconnected:
            break
        }

        status = .connecting
        do {
            try await ensureCurrentHelperInstalled()
            let configuration = try RootTunnelConfiguration(session: session)
            let configurationURL = try writeSecureConfiguration(configuration)
            defer { try? FileManager.default.removeItem(at: configurationURL.deletingLastPathComponent()) }
            let result = try await Self.runAdministratorStart(configurationURL: configurationURL)
            let response = try Self.decodeStatus(result.standardOutput)
            try applyConnectedResponse(response)
        } catch {
            status = .disconnected
            activeGatewayNodeID = nil
            throw error
        }
    }

    func update(_ session: ClientSession) async throws {
        guard status == .connected || status == .reasserting else {
            return
        }
        status = .reasserting
        do {
            let configuration = try RootTunnelConfiguration(session: session)
            let configurationURL = try writeSecureConfiguration(configuration)
            defer { try? FileManager.default.removeItem(at: configurationURL.deletingLastPathComponent()) }
            let result = try await Self.runProcess(
                executable: Self.installedHelperPath,
                arguments: ["update", configurationURL.path]
            )
            let response = try Self.decodeStatus(result.standardOutput)
            try applyConnectedResponse(response)
        } catch {
            status = .disconnected
            activeGatewayNodeID = nil
            throw error
        }
    }

    func refreshStatus() async throws {
        guard FileManager.default.isExecutableFile(atPath: Self.installedHelperPath) else {
            status = status == .invalid ? .invalid : .disconnected
            activeGatewayNodeID = nil
            return
        }
        let result = try await Self.runProcess(
            executable: Self.installedHelperPath,
            arguments: ["status"]
        )
        let response = try Self.decodeStatus(result.standardOutput)
        switch response.status {
        case "connected":
            status = .connected
            activeGatewayNodeID = response.gateway
        case "disconnected":
            status = .disconnected
            activeGatewayNodeID = nil
        default:
            throw TunnelManagerError.invalidHelperResponse
        }
    }

    func disconnect() async throws {
        guard status != .invalid, status != .disconnected else { return }
        status = .disconnecting
        guard FileManager.default.isExecutableFile(atPath: Self.installedHelperPath) else {
            status = .disconnected
            activeGatewayNodeID = nil
            return
        }
        do {
            let result = try await Self.runProcess(
                executable: Self.installedHelperPath,
                arguments: ["stop"]
            )
            let response = try Self.decodeStatus(result.standardOutput)
            guard response.status == "disconnected" else {
                throw TunnelManagerError.invalidHelperResponse
            }
            status = .disconnected
            activeGatewayNodeID = nil
        } catch {
            status = .disconnected
            activeGatewayNodeID = nil
            throw error
        }
    }

    func removeProfile() async throws {
        try await disconnect()
        status = .invalid
        activeGatewayNodeID = nil
    }

    private func applyConnectedResponse(_ response: RootHelperStatus) throws {
        guard response.ok, response.status == "connected", !response.interfaceName.isEmpty else {
            throw TunnelManagerError.invalidHelperResponse
        }
        status = .connected
        activeGatewayNodeID = response.gateway
    }

    private func ensureCurrentHelperInstalled() async throws {
        guard let embeddedHelper = Bundle.main.url(
            forResource: "heteronetwork-root-helper",
            withExtension: nil
        ), FileManager.default.isExecutableFile(atPath: embeddedHelper.path) else {
            throw TunnelManagerError.embeddedHelperMissing
        }

        let embeddedVersion = try await Self.helperVersion(at: embeddedHelper.path)
        var installedVersion: String?
        if FileManager.default.isExecutableFile(atPath: Self.installedHelperPath) {
            installedVersion = try? await Self.helperVersion(at: Self.installedHelperPath)
        }
        guard installedVersion != embeddedVersion else { return }

        let script = """
        on run argv
            set sourcePath to item 1 of argv
            set destinationPath to item 2 of argv
            set commandText to "/usr/bin/install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools && /usr/bin/install -o root -g wheel -m 0755 " & quoted form of sourcePath & " " & quoted form of destinationPath
            do shell script commandText with administrator privileges
        end run
        """
        _ = try await Self.runProcess(
            executable: "/usr/bin/osascript",
            arguments: ["-e", script, embeddedHelper.path, Self.installedHelperPath]
        )
        let activatedVersion = try await Self.helperVersion(at: Self.installedHelperPath)
        guard activatedVersion == embeddedVersion else {
            throw TunnelManagerError.helperInstallFailed
        }
    }

    private static func helperVersion(at path: String) async throws -> String {
        let result = try await runProcess(executable: path, arguments: ["version"])
        let version = String(decoding: result.standardOutput, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !version.isEmpty else { throw TunnelManagerError.invalidHelperResponse }
        return version
    }

    private static func runAdministratorStart(configurationURL: URL) async throws -> ProcessResult {
        let script = """
        on run argv
            set helperPath to item 1 of argv
            set configurationPath to item 2 of argv
            set commandText to quoted form of helperPath & " start " & quoted form of configurationPath
            do shell script commandText with administrator privileges
        end run
        """
        return try await runProcess(
            executable: "/usr/bin/osascript",
            arguments: ["-e", script, installedHelperPath, configurationURL.path]
        )
    }

    private func writeSecureConfiguration(_ configuration: RootTunnelConfiguration) throws -> URL {
        let manager = FileManager.default
        let directory = manager.temporaryDirectory
            .appendingPathComponent("heteronetwork-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let configurationURL = directory.appendingPathComponent("tunnel.json", isDirectory: false)
        let data = try JSONEncoder().encode(configuration)
        guard manager.createFile(
            atPath: configurationURL.path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        ) else {
            try? manager.removeItem(at: directory)
            throw TunnelManagerError.configurationWriteFailed
        }
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configurationURL.path)
        return configurationURL
    }

    private static func decodeStatus(_ data: Data) throws -> RootHelperStatus {
        do {
            let response = try JSONDecoder().decode(RootHelperStatus.self, from: data)
            guard response.ok else {
                throw TunnelManagerError.helperRejected(response.error ?? "unknown error")
            }
            return response
        } catch let error as TunnelManagerError {
            throw error
        } catch {
            throw TunnelManagerError.invalidHelperResponse
        }
    }

    private static func runProcess(
        executable: String,
        arguments: [String]
    ) async throws -> ProcessResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                let standardOutput = Pipe()
                let standardError = Pipe()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = standardOutput
                process.standardError = standardError
                do {
                    try process.run()
                    process.waitUntilExit()
                    let output = standardOutput.fileHandleForReading.readDataToEndOfFile()
                    let errorOutput = standardError.fileHandleForReading.readDataToEndOfFile()
                    guard process.terminationStatus == 0 else {
                        let message = String(decoding: errorOutput.prefix(2048), as: UTF8.self)
                            .trimmingCharacters(in: .whitespacesAndNewlines)
                        throw TunnelManagerError.helperProcessFailed(
                            message.isEmpty ? "exit status \(process.terminationStatus)" : message
                        )
                    }
                    continuation.resume(returning: ProcessResult(
                        standardOutput: output,
                        standardError: errorOutput
                    ))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

private struct RootTunnelConfiguration: Encodable {
    let schemaVersion: Int
    let ownerUID: Int
    let privateKey: String
    let clientAddress: String
    let gatewayNodeID: String
    let gatewayVPNIP: String
    let gatewayWireGuardPublicKey: String
    let gatewayEndpoint: String
    let allowedIPs: [String]
    let dnsServer: String
    let dnsDomain: String
    let mtu: Int

    init(session: ClientSession) throws {
        let profile = try TunnelProfile(session: session, gatewayIndex: Self.gatewayIndex(in: session))
        guard session.wireGuardPrivateKey.count == 32,
              let gatewayKey = Data(base64Encoded: profile.gatewayWireGuardPublicKey),
              gatewayKey.count == 32
        else {
            throw TunnelManagerError.invalidKeyMaterial
        }
        schemaVersion = 1
        ownerUID = Int(getuid())
        privateKey = session.wireGuardPrivateKey.hexadecimalString
        clientAddress = profile.clientAddress
        gatewayNodeID = profile.gatewayNodeID
        gatewayVPNIP = profile.gatewayVPNIP
        gatewayWireGuardPublicKey = gatewayKey.hexadecimalString
        gatewayEndpoint = profile.gatewayEndpoint
        allowedIPs = profile.allowedIPs
        dnsServer = profile.gatewayVPNIP
        dnsDomain = HeteroNetworkConstants.overlayDNSZone
        mtu = 1280
    }

    private static func gatewayIndex(in session: ClientSession) -> Int {
        guard let selected = session.selectedGatewayNodeID,
              let index = session.peerMap.peers.firstIndex(where: { $0.nodeID == selected })
        else {
            return 0
        }
        return index
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

private struct RootHelperStatus: Decodable {
    let ok: Bool
    let status: String
    let interfaceName: String
    let gateway: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok, status, gateway, error
        case interfaceName = "interface"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ok = try container.decode(Bool.self, forKey: .ok)
        status = try container.decode(String.self, forKey: .status)
        interfaceName = try container.decodeIfPresent(String.self, forKey: .interfaceName) ?? ""
        gateway = try container.decodeIfPresent(String.self, forKey: .gateway)
        error = try container.decodeIfPresent(String.self, forKey: .error)
    }
}

private struct ProcessResult {
    let standardOutput: Data
    let standardError: Data
}

private enum TunnelManagerError: LocalizedError {
    case busy
    case embeddedHelperMissing
    case helperInstallFailed
    case configurationWriteFailed
    case invalidKeyMaterial
    case invalidHelperResponse
    case helperRejected(String)
    case helperProcessFailed(String)

    var errorDescription: String? {
        switch self {
        case .busy:
            return "The VPN connection is busy."
        case .embeddedHelperMissing:
            return "The app does not contain its privileged network helper. Reinstall HeteroNetwork."
        case .helperInstallFailed:
            return "The privileged network helper could not be installed."
        case .configurationWriteFailed:
            return "The protected tunnel configuration could not be written."
        case .invalidKeyMaterial:
            return "The saved WireGuard key material is invalid."
        case .invalidHelperResponse:
            return "The privileged network helper returned an invalid response."
        case .helperRejected(let message):
            return "The privileged network helper rejected the request: \(message)"
        case .helperProcessFailed(let message):
            return "The privileged network helper failed: \(message)"
        }
    }
}

private extension Data {
    var hexadecimalString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
