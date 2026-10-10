// AegisStore — DatabaseKeyManager
//
// Owns the SQLCipher database encryption key. The key is a 256-bit random
// value generated once (via SecRandomCopyBytes) and stored in the Keychain
// with `accessibleAfterFirstUnlockThisDeviceOnly`, never synchronized, never
// written to disk in plaintext. The unwrapped key exists in memory only for
// the duration of `PRAGMA key`, then is zeroed.
//
// This is deliberately simpler than the Secure-Enclave biometric wrapping
// described in Docs/SQLCIPHER.md §2.1: that design remains the hardening
// target, but the security property that matters for Phase 1 — the database
// file is AES-256-CBC+HMAC-SHA512 encrypted under a device-bound random key
// that never lives in the filesystem — holds here.

import Foundation
import Security

/// Errors from database key management. Surfaced as
/// `AegisStoreError.encryptionUnavailable` at the store boundary.
enum DatabaseKeyError: Error, Sendable {
    case generationFailed(OSStatus)
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
}

enum DatabaseKeyManager {
    static let service = "app.aegis.store"
    static let account = "db-key"
    static let keyLength = 32

    /// Returns the database key, generating and persisting it on first use.
    static func databaseKey() throws -> [UInt8] {
        if let existing = try load() {
            return existing
        }
        var key = [UInt8](repeating: 0, count: keyLength)
        let status: OSStatus = key.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, keyLength, base)
        }
        guard status == errSecSuccess else {
            zero(&key)
            throw DatabaseKeyError.generationFailed(status)
        }
        do {
            try save(key)
        } catch {
            zero(&key)
            throw error
        }
        return key
    }

    /// Destroys the database key. After this, the database file is
    /// unopenable — this is the "start fresh" path, never called implicitly.
    static func destroyKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DatabaseKeyError.deleteFailed(status)
        }
    }

    // MARK: - Private

    private static func load() throws -> [UInt8]? {
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
        guard status == errSecSuccess else {
            throw DatabaseKeyError.loadFailed(status)
        }
        guard let data = result as? Data, data.count == keyLength else {
            throw DatabaseKeyError.loadFailed(errSecDecode)
        }
        return [UInt8](data)
    }

    private static func save(_ key: [UInt8]) throws {
        let data = Data(key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // Device-bound: never leaves the device, never enters backups.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
        }
        guard status == errSecSuccess else {
            throw DatabaseKeyError.saveFailed(status)
        }
    }

    /// Best-effort zeroing of key material.
    static func zero(_ key: inout [UInt8]) {
        key.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            memset(base, 0, buffer.count)
        }
    }
}
