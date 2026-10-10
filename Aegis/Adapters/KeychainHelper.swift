// KeychainHelper — minimal Keychain read/write for secrets.
//
// Used by the live adapters for: the local identity (private key material),
// wrapped attachment file keys, and the backup passphrase salt. Everything
// is stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — keys
// never leave the device, never enter backups.

import Foundation
import Security

enum KeychainError: Error, Sendable {
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
    case decodingFailed
}

enum KeychainHelper {
    /// True inside the XCTest runner. The test host app lacks the Keychain
    /// entitlement, so every SecItem* call fails with errSecMissingEntitlement
    /// (-34018). Tests therefore use an in-memory dictionary behind the same
    /// API: they exercise the real call paths without real secrets, and no
    /// test secret ever reaches the device keychain. Production never takes
    /// this path.
    static var isRunningTests: Bool {
        NSClassFromString("XCTestCase") != nil
    }

    /// Lock-guarded in-memory stand-in for the keychain, test runs only.
    private final class TestStore: Sendable {
        private let lock = NSLock()
        private var values: [String: Data] = [:]
        func get(_ key: String) -> Data? { lock.withLock { values[key] } }
        func set(_ key: String, _ value: Data) { lock.withLock { values[key] = value } }
        func remove(_ key: String) { lock.withLock { values.removeValue(forKey: key) } }
    }
    private static let testStore = TestStore()

    private static func testKey(service: String, account: String) -> String {
        service + "\u{0}" + account
    }

    static func save(_ data: Data, service: String, account: String) throws {
        if isRunningTests {
            testStore.set(testKey(service: service, account: account), data)
            return
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            guard updateStatus == errSecSuccess else { throw KeychainError.saveFailed(updateStatus) }
            return
        }
        guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
    }

    static func load(service: String, account: String) throws -> Data? {
        if isRunningTests {
            return testStore.get(testKey(service: service, account: account))
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.loadFailed(status) }
        guard let data = result as? Data else { throw KeychainError.decodingFailed }
        return data
    }

    static func delete(service: String, account: String) throws {
        if isRunningTests {
            testStore.remove(testKey(service: service, account: account))
            return
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}
