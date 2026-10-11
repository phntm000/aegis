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
//
// Simulator note: CI/screenshot builds are unsigned (CODE_SIGNING_ALLOWED=NO),
// so the simulator Keychain is unreachable — every SecItem* call fails with
// errSecMissingEntitlement (-34018), which used to surface as the fail-closed
// "Aegis couldn't start" view on every launch, including first launch on a
// fresh simulator. No accessibility constant can fix an unsigned binary: the
// failure happens before accessibility is consulted, because there is no
// signing identity to authorize. On simulator builds only (never on device),
// an unreachable Keychain falls back to a 0600 file under Application
// Support. Signed simulator runs keep the exact production Keychain path.
// Fail-closed semantics are preserved: a present-but-corrupt key file throws
// instead of silently minting a new key over an existing database.

import Foundation
import Security

/// Errors from database key management. Surfaced as
/// `AegisStoreError.encryptionUnavailable` at the store boundary.
enum DatabaseKeyError: Error, Sendable {
    case generationFailed(OSStatus)
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
    /// Simulator-only file-backed key storage failed. Never raised on device.
    case simulatorStorageFailed(String)
}

enum DatabaseKeyManager {
    static let service = "app.aegis.store"
    static let account = "db-key"
    static let keyLength = 32

    /// Returns the database key, generating and persisting it on first use.
    ///
    /// Device builds always use the Keychain. Simulator builds try the
    /// Keychain first (signed runs exercise the production path exactly) and
    /// fall back to file storage only when the Keychain is unreachable
    /// because the binary is unsigned.
    static func databaseKey() throws -> [UInt8] {
        #if targetEnvironment(simulator)
        do {
            return try keychainDatabaseKey()
        } catch {
            guard isKeychainUnreachable(error) else { throw error }
            return try simulatorFileDatabaseKey()
        }
        #else
        return try keychainDatabaseKey()
        #endif
    }

    /// Destroys the database key. After this, the database file is
    /// unopenable — this is the "start fresh" path, never called implicitly.
    static func destroyKey() throws {
        #if targetEnvironment(simulator)
        try destroySimulatorKeyFile()
        #endif
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        #if targetEnvironment(simulator)
        // An unsigned binary never wrote to the Keychain; -34018 here only
        // means there was nothing keychain-side to delete.
        if status == errSecMissingEntitlement { return }
        #endif
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DatabaseKeyError.deleteFailed(status)
        }
    }

    // MARK: - Private

    /// The production path: fetch-or-create the key in the Keychain.
    private static func keychainDatabaseKey() throws -> [UInt8] {
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

    #if targetEnvironment(simulator)
    // MARK: - Simulator file fallback (unsigned builds only)

    /// True when the Keychain failed because the binary has no signing
    /// identity (errSecMissingEntitlement). Any other keychain error is a
    /// genuine failure and stays fail-closed — it must not fall through to
    /// file storage.
    private static func isKeychainUnreachable(_ error: Error) -> Bool {
        switch error {
        case DatabaseKeyError.loadFailed(let status),
             DatabaseKeyError.saveFailed(let status):
            return status == errSecMissingEntitlement
        default:
            return false
        }
    }

    /// Simulator-only key storage for unsigned builds: a 0600 file under
    /// Application Support/Aegis. Mirrors the keychain semantics — a missing
    /// file means first launch (generate); a present-but-unreadable file is a
    /// genuine failure (throw, fail closed, never silently mint a new key
    /// over an existing database).
    private static func simulatorFileDatabaseKey() throws -> [UInt8] {
        let url = try simulatorKeyFileURL()
        if FileManager.default.fileExists(atPath: url.path) {
            guard let data = try? Data(contentsOf: url),
                  data.count == keyLength else {
                throw DatabaseKeyError.simulatorStorageFailed(
                    "simulator key file is missing or corrupt")
            }
            return [UInt8](data)
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
        let created = FileManager.default.createFile(
            atPath: url.path,
            contents: Data(key),
            attributes: [.posixPermissions: 0o600]
        )
        guard created else {
            zero(&key)
            throw DatabaseKeyError.simulatorStorageFailed(
                "could not write simulator key file")
        }
        return key
    }

    private static func simulatorKeyFileURL() throws -> URL {
        let fm = FileManager.default
        guard let base = fm.urls(for: .applicationSupportDirectory,
                                 in: .userDomainMask).first else {
            throw DatabaseKeyError.simulatorStorageFailed(
                "no application support directory")
        }
        let dir = base.appendingPathComponent("Aegis", isDirectory: true)
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            throw DatabaseKeyError.simulatorStorageFailed(
                "could not create key directory: \(error)")
        }
        return dir.appendingPathComponent("simulator-db-key")
    }

    /// Removes the simulator key file if present. A missing file is fine
    /// (the Keychain path was in use); a present-but-undeletable file throws.
    private static func destroySimulatorKeyFile() throws {
        let url = try simulatorKeyFileURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            throw DatabaseKeyError.simulatorStorageFailed(
                "could not delete simulator key file: \(error)")
        }
    }
    #endif

    /// Best-effort zeroing of key material.
    static func zero(_ key: inout [UInt8]) {
        key.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            memset(base, 0, buffer.count)
        }
    }
}
