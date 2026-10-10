// AttachmentCrypto — per-file encryption for attachments.
//
// Framing decision (settles the open question in
// Aegis/INTEGRATION_NOTES.md §3): **the 12-byte GCM nonce is prepended to
// the ciphertext file.** The stored blob is self-describing:
//
//   nonce(12) || ciphertext || tag(16)
//
// The message envelope carries only `wrappedKey` (the file key, wrapped
// for the conversation's session) and `byteCount`. There is no separate
// nonce field on the wire and no nonce parameter with independent
// meaning: `decryptAttachment`'s `nonce` argument is vestigial (the app
// passes empty `Data`) and is ignored — the nonce is read from the file.
// Rationale: a blob that cannot be decrypted without sidecar metadata is
// a blob that will eventually fail to decrypt. Self-contained wins.
//
// Key lifecycle:
//   - `generateFileKey()` → 32 fresh random bytes per attachment.
//   - The file key is wrapped with the conversation's session by the
//     caller (the live crypto adapter encrypts it as a 1:1/group message
//     payload) and travels *inside* the message envelope as `wrappedKey`.
//   - Ciphertext chunks travel over the transport as ordinary sealed
//     frames; the transport never sees the key.
//   - Keys are `SymmetricKey` handles; callers should let them deallocate
//     promptly after use.

import CryptoKit
import Foundation

/// Errors specific to attachment file cryptography.
public enum AttachmentCryptoError: Error, Sendable, Equatable {
    /// The file is larger than `maxFileBytes`.
    case fileTooLarge(Int64)
    /// The ciphertext file is shorter than nonce + tag.
    case truncatedCiphertext
}

public enum AttachmentCrypto {
    /// Hard cap per attachment. AES-GCM needs the whole plaintext in
    /// memory; beyond this the adapter must refuse rather than OOM a
    /// phone. 100 MiB is generous for a messenger — larger files should
    /// be split by the caller or rejected in UI.
    public static let maxFileBytes: Int64 = 100 * 1024 * 1024

    /// 12-byte GCM nonce, the prefix length of every ciphertext blob.
    public static let nonceLength = 12
    /// 16-byte GCM tag, the suffix length of every ciphertext blob.
    public static let tagLength = 16

    /// Fresh random 256-bit file key. One per attachment, never reused.
    public static func generateFileKey(
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SymmetricKey {
        let raw = try provider.randomBytes(count: 32)
        return SymmetricKey(data: raw)
    }

    /// Encrypts the file at `sourceURL`, writing `nonce || ciphertext ||
    /// tag` to a new temporary file and returning its URL. The source file
    /// is left untouched; the caller deletes the plaintext staging copy.
    public static func encryptFile(
        at sourceURL: URL,
        key: SymmetricKey,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> URL {
        let plaintext = try readBounded(sourceURL)
        let sealed = try AEAD.seal(
            plaintext: plaintext,
            key: key,
            associatedData: Data("AegisAttachment_v1".utf8),
            provider: provider
        )
        var blob = Data()
        blob.reserveCapacity(nonceLength + sealed.ciphertext.count + tagLength)
        blob.append(sealed.nonce)
        blob.append(sealed.ciphertext)
        blob.append(sealed.tag)
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: false)
            .appendingPathExtension("aegisblob")
        try blob.write(to: destination, options: .completeFileProtection)
        return destination
    }

    /// Decrypts a blob produced by `encryptFile`, writing the plaintext to
    /// `destinationURL`. The nonce is read from the blob's 12-byte prefix.
    public static func decryptFile(
        at ciphertextURL: URL,
        key: SymmetricKey,
        to destinationURL: URL,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        let blob = try readBounded(ciphertextURL)
        guard blob.count >= nonceLength + tagLength else {
            throw AttachmentCryptoError.truncatedCiphertext
        }
        let sealed = SealedMessage(
            nonce: blob.prefix(nonceLength),
            ciphertext: blob.dropFirst(nonceLength).dropLast(tagLength),
            tag: blob.suffix(tagLength)
        )
        let plaintext = try AEAD.open(
            sealed,
            key: key,
            associatedData: Data("AegisAttachment_v1".utf8),
            provider: provider
        )
        try plaintext.write(to: destinationURL, options: .completeFileProtection)
    }

    // MARK: - Internal

    private static func readBounded(_ url: URL) throws -> Data {
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        if let size = values.fileSize, Int64(size) > maxFileBytes {
            throw AttachmentCryptoError.fileTooLarge(Int64(size))
        }
        let data = try Data(contentsOf: url)
        guard Int64(data.count) <= maxFileBytes else {
            throw AttachmentCryptoError.fileTooLarge(Int64(data.count))
        }
        return data
    }
}
