import Foundation
import Security

enum InstalledAppKeychainProbe {
    static var isRequested: Bool {
        ProcessInfo.processInfo.environment["HETERONETWORK_LIVE_E2E"] == "1"
            && CommandLine.arguments.dropFirst().first == "--live-e2e-keychain-probe"
    }

    static func run() -> Int32 {
        let service = "jp.go.ipa.cyberlab.heteronetwork.e2e.\(UUID().uuidString)"
        let account = "installed-app-keychain-probe"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        defer { _ = SecItemDelete(query as CFDictionary) }

        do {
            var initial = Data(count: 32)
            let randomStatus: OSStatus = initial.withUnsafeMutableBytes { bytes in
                guard let baseAddress = bytes.baseAddress else { return errSecParam }
                return SecRandomCopyBytes(kSecRandomDefault, bytes.count, baseAddress)
            }
            guard randomStatus == errSecSuccess else {
                throw KeychainProbeError.keychain(randomStatus)
            }

            var item = query
            item[kSecValueData as String] = initial
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainProbeError.keychain(addStatus)
            }
            guard try read(query) == initial else {
                throw KeychainProbeError.roundTripFailed
            }

            let updated = Data(initial.reversed())
            let updateStatus = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: updated] as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KeychainProbeError.keychain(updateStatus)
            }
            guard try read(query) == updated else {
                throw KeychainProbeError.roundTripFailed
            }

            let deleteStatus = SecItemDelete(query as CFDictionary)
            guard deleteStatus == errSecSuccess else {
                throw KeychainProbeError.keychain(deleteStatus)
            }
            var deletedQuery = query
            deletedQuery[kSecReturnData as String] = true
            deletedQuery[kSecMatchLimit as String] = kSecMatchLimitOne
            let missingStatus = SecItemCopyMatching(deletedQuery as CFDictionary, nil)
            guard missingStatus == errSecItemNotFound else {
                throw KeychainProbeError.keychain(missingStatus)
            }

            let releaseTag = Bundle.main.object(
                forInfoDictionaryKey: "HeteroNetworkReleaseTag"
            ) as? String ?? "development"
            try emit([
                "automatic_updates_enabled": releaseTag.hasPrefix("v"),
                "installed_app_started": true,
                "keychain_add_read_update_delete": true,
                "release_tag": releaseTag,
            ])
            return 0
        } catch {
            let message = error.localizedDescription
                .replacingOccurrences(of: "\n", with: " ")
                .prefix(512)
            FileHandle.standardError.write(
                Data("Installed app Keychain probe failed: \(message)\n".utf8)
            )
            return 1
        }
    }

    private static func read(_ baseQuery: [String: Any]) throws -> Data {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw KeychainProbeError.keychain(status)
        }
        guard let data = result as? Data else {
            throw KeychainProbeError.roundTripFailed
        }
        return data
    }

    private static func emit(_ value: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}

private enum KeychainProbeError: LocalizedError {
    case keychain(OSStatus)
    case roundTripFailed

    var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
            return "Keychain operation failed: \(message) (\(status))."
        case .roundTripFailed:
            return "The installed app Keychain value did not survive a round trip."
        }
    }
}
