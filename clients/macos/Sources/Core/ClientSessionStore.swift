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
    private let sessionService: String
    private let sessionAccount: String
    private let pendingService: String
    private let pendingAccount: String
    private let encoder = HeteroNetworkCoding.makeEncoder()
    private let decoder = HeteroNetworkCoding.makeDecoder()

    public convenience init() {
        self.init(
            sessionService: HeteroNetworkConstants.keychainService,
            sessionAccount: HeteroNetworkConstants.keychainAccount,
            pendingService: HeteroNetworkConstants.pendingKeychainService,
            pendingAccount: HeteroNetworkConstants.pendingKeychainAccount
        )
    }

    init(
        sessionService: String,
        sessionAccount: String,
        pendingService: String,
        pendingAccount: String
    ) {
        self.sessionService = sessionService
        self.sessionAccount = sessionAccount
        self.pendingService = pendingService
        self.pendingAccount = pendingAccount
    }

    public func load() throws -> ClientSession? {
        var query = baseQuery(
            service: sessionService,
            account: sessionAccount
        )
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
        let query = baseQuery(
            service: sessionService,
            account: sessionAccount
        )
        let attributes: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(updateStatus)
        }

        var item = query
        item[kSecValueData as String] = data
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw ClientSessionStoreError.keychain(addStatus)
        }
    }

    public func delete() throws {
        let status = SecItemDelete(
            baseQuery(
                service: sessionService,
                account: sessionAccount
            ) as CFDictionary
        )
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(status)
        }
    }

    public func loadPendingRegistration() throws -> PendingClientRegistration? {
        var query = baseQuery(
            service: pendingService,
            account: pendingAccount
        )
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw ClientSessionStoreError.keychain(status)
        }
        guard let data = result as? Data,
              let pending = try? decoder.decode(PendingClientRegistration.self, from: data),
              pending.schemaVersion == 1,
              (try? pending.validate()) != nil
        else {
            throw ClientSessionStoreError.invalidSession
        }
        return pending
    }

    public func savePendingRegistration(_ pending: PendingClientRegistration) throws {
        guard pending.schemaVersion == 1, (try? pending.validate()) != nil else {
            throw ClientSessionStoreError.invalidSession
        }
        let data = try encoder.encode(pending)
        let query = baseQuery(
            service: pendingService,
            account: pendingAccount
        )
        let attributes: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(updateStatus)
        }

        var item = query
        item[kSecValueData as String] = data
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw ClientSessionStoreError.keychain(addStatus)
        }
    }

    public func deletePendingRegistration() throws {
        let status = SecItemDelete(
            baseQuery(
                service: pendingService,
                account: pendingAccount
            ) as CFDictionary
        )
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ClientSessionStoreError.keychain(status)
        }
    }

    public func completeImport(
        pending: PendingClientRegistration,
        session: ClientSession
    ) throws {
        guard let storedPending = try loadPendingRegistration(),
              storedPending == pending
        else {
            throw SponsoredEnrollmentError.pendingRegistrationMismatch
        }
        try save(session)
        do {
            try deletePendingRegistration()
        } catch {
            try? delete()
            throw error
        }
    }

    private func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}
