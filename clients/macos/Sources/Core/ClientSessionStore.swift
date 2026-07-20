import Foundation
import Security

public enum ClientSessionStoreError: LocalizedError {
    case keychain(OSStatus)
    case invalidSession
    case unsupportedSessionVersion(Int)

    public var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
            return "Keychain operation failed: \(message) (\(status))."
        case .invalidSession: return "The saved client session is invalid."
        case .unsupportedSessionVersion(let version):
            return "The saved client session version \(version) is unsupported."
        }
    }
}

public final class ClientSessionStore {
    private let accessGroup: String?
    private let encoder = HeteroNetworkCoding.makeEncoder()
    private let decoder = HeteroNetworkCoding.makeDecoder()

    public init(accessGroup: String? = HeteroNetworkConstants.keychainAccessGroup) {
        self.accessGroup = accessGroup
    }

    public func load() throws -> ClientSession? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ClientSessionStoreError.keychain(status) }
        guard let data = result as? Data,
              let session = try? decoder.decode(ClientSession.self, from: data)
        else {
            throw ClientSessionStoreError.invalidSession
        }
        guard session.schemaVersion == HeteroNetworkConstants.sessionSchemaVersion else {
            throw ClientSessionStoreError.unsupportedSessionVersion(session.schemaVersion)
        }
        return session
    }

    public func save(_ session: ClientSession) throws {
        guard session.schemaVersion == HeteroNetworkConstants.sessionSchemaVersion else {
            throw ClientSessionStoreError.unsupportedSessionVersion(session.schemaVersion)
        }
        let data = try encoder.encode(session)
        let query = baseQuery()
        let attributes: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(updateStatus)
        }

        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw ClientSessionStoreError.keychain(addStatus)
        }
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(status)
        }
    }

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: HeteroNetworkConstants.keychainService,
            kSecAttrAccount as String: HeteroNetworkConstants.keychainAccount,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup, !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
