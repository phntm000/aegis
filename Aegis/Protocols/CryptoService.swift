import Foundation

// MARK: - CryptoService
//
// What the app needs from the AegisCrypto package.
//
// Boundary rule: private key material NEVER crosses this protocol. Key
// generation, storage (Keychain / Secure Enclave), X3DH, and the Double
// Ratchet all live inside AegisCrypto. The app only ever handles public
// keys, ciphertext, and opaque wrapped keys.

/// An encrypted file produced by `encryptAttachment`: ciphertext on disk plus
/// the session-wrapped key that must travel inside the message envelope.
struct EncryptedFile: Sendable, Hashable {
    let fileURL: URL
    /// Key wrapped for the conversation's session. Opaque to transport/store.
    let wrappedKey: Data
    let nonce: Data
    let byteCount: Int64
}

enum PassphraseStrength: String, Sendable {
    case weak
    case fair
    case strong

    var displayName: String {
        switch self {
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        }
    }
}

protocol CryptoService: Sendable {
    // MARK: Identity lifecycle

    func hasIdentity() async -> Bool
    func createIdentity(displayName: String) async throws -> LocalIdentity
    func loadIdentity() async throws -> LocalIdentity
    func updateDisplayName(_ name: String) async throws -> LocalIdentity
    /// Wipes keychain identity and all session state. The app returns to onboarding.
    func deleteIdentity() async throws

    // MARK: Fingerprints & invites

    /// Long-form fingerprint of a public identity key (grouped for display).
    func fingerprint(of publicKey: Data) -> String
    /// Signal-style safety number combining both parties' keys.
    func safetyNumber(local localKey: Data, remote remoteKey: Data) -> String
    /// QR payload encoding the identity (public key + display name + version).
    func qrPayload(for identity: LocalIdentity) async throws -> String
    /// Parse an invite code produced by `inviteCode(for:)`.
    func inviteCode(for identity: LocalIdentity) async throws -> String
    /// Parse a scanned QR payload or pasted invite code.
    func remoteIdentity(fromInvitePayload payload: String) async throws -> RemoteIdentity

    // MARK: Session encryption

    /// Encrypt a plaintext message body for a conversation. Handles DM
    /// (Double Ratchet) and group (sender-key) sessions internally.
    func encryptMessage(
        _ plaintext: Data,
        conversationID: UUID,
        recipientKeys: [Data]
    ) async throws -> Data

    /// Decrypt an incoming envelope's ciphertext.
    func decryptMessage(
        _ ciphertext: Data,
        conversationID: UUID,
        senderKey: Data
    ) async throws -> Data

    // MARK: Attachments

    /// Encrypt a file with a fresh random key. Returns ciphertext on disk and
    /// the wrapped key to embed in the message envelope.
    func encryptAttachment(at fileURL: URL, conversationID: UUID) async throws -> EncryptedFile
    /// Decrypt a downloaded blob to a destination URL.
    func decryptAttachment(
        ciphertextURL: URL,
        wrappedKey: Data,
        nonce: Data,
        to destinationURL: URL
    ) async throws

    // MARK: Encrypted backup

    /// Export the identity + store snapshot as one encrypted blob.
    /// (Ratchet sessions are device-local: they persist in the encrypted
    /// store across restarts but are excluded from backups, which
    /// re-establish sessions via X3DH on restore.)
    func exportEncryptedBackup(passphrase: String) async throws -> Data
    /// Restore from an encrypted backup blob. Returns the restored identity.
    func importEncryptedBackup(_ data: Data, passphrase: String) async throws -> LocalIdentity
    /// Local strength estimate for the backup-passphrase UI meter.
    func backupPassphraseStrength(_ passphrase: String) -> PassphraseStrength

    // MARK: Session durability

    /// Persists dirty Double Ratchet session snapshots to the encrypted
    /// store. Runs automatically (debounced) and on app backgrounding;
    /// exposed so the app can force a flush at lifecycle boundaries.
    func flushSessions() async
}

extension CryptoService {
    /// Default: persistence not configured (previews/mocks).
    func flushSessions() async {}
}
