// AegisCrypto — end-to-end encryption core for the Aegis messenger.
//
// This module implements the cryptographic protocol layer: identity keys,
// X3DH key agreement, the Double Ratchet, group sender keys, sealed sender,
// safety numbers, call-signaling helpers, and passphrase-protected key backup.
//
// The complete protocol specification lives in docs/CRYPTO.md. The honest
// assessment of what this protects — and what it cannot — lives in
// docs/THREAT_MODEL.md. Read both before touching this code.
//
// Conventions used throughout:
//  - No force-unwraps in cryptographic paths. Failable operations throw
//    `AegisCryptoError`.
//  - Every deliberate simplification is marked `// TODO(security-audit):`
//    with a note describing what an independent audit must verify.
//  - Domain-separation strings are versioned (`..._v1`) so a future
//    protocol revision cannot cross-wire with this one.

import Foundation

/// Version of the AegisCrypto Swift API.
public enum AegisCrypto {
    public static let version = "1.0.0"

    /// Wire-protocol version. Bump whenever any serialized format changes.
    /// Decoders reject unknown versions loudly instead of misparsing.
    public static let protocolVersion: UInt8 = 1
}

/// Errors thrown by AegisCrypto. Cases are stable and safe to persist or
/// switch on; none of them leak key material or plaintext.
public enum AegisCryptoError: Error, Equatable, CustomStringConvertible {
    /// The platform CSPRNG failed. Treat as fatal: never fall back to a
    /// weaker randomness source.
    case randomnessFailure
    /// A key's serialized form was malformed or the wrong length.
    case invalidKeyData
    /// An Ed25519 signature did not verify.
    case invalidSignature
    /// A serialized envelope, header, bundle, or backup failed to parse.
    /// Bounds-checked; never traps on hostile input.
    case invalidWireFormat
    /// AES-GCM authentication failed (forgery, corruption, or wrong key).
    /// Deliberately coarse: callers must not distinguish "wrong key" from
    /// "tampered ciphertext".
    case authenticationFailed
    /// A ratchet message arrived more than `maxSkip` messages ahead of the
    /// current chain position. Likely replay / DoS; the peer must re-send.
    case messageTooFarInFuture
    /// A message arrived for a chain position whose key was already consumed
    /// and is not in the skipped-keys store.
    case messageTooOld
    /// Encrypt called before a sending chain exists (responder that has not
    /// yet received the first message).
    case noSendingChain
    /// Decrypt called before a receiving chain exists.
    case noReceivingChain
    /// No sender-key state for this (sender, epoch); the distribution
    /// message was never received or was evicted.
    case unknownSenderKey
    /// Group message epoch is older than the oldest retained epoch.
    case staleEpoch
    /// A sealed-sender certificate is outside its validity window.
    case certificateExpired
    /// Wire `version` byte is not one this build understands.
    case unsupportedVersion(UInt8)
    /// A session snapshot's format version is newer than this build
    /// understands. Callers must fall back to X3DH re-establishment.
    case unsupportedSnapshotVersion(Int)
    /// A KDF was given invalid parameters (programmer error).
    case kdfFailed(String)

    public var description: String {
        switch self {
        case .randomnessFailure: return "platform randomness source failed"
        case .invalidKeyData: return "malformed key data"
        case .invalidSignature: return "signature verification failed"
        case .invalidWireFormat: return "malformed wire encoding"
        case .authenticationFailed: return "message authentication failed"
        case .messageTooFarInFuture: return "message too far ahead of ratchet position"
        case .messageTooOld: return "message key already consumed"
        case .noSendingChain: return "no sending chain established yet"
        case .noReceivingChain: return "no receiving chain established yet"
        case .unknownSenderKey: return "no sender key for (sender, epoch)"
        case .staleEpoch: return "group message from an evicted epoch"
        case .certificateExpired: return "sealed-sender certificate outside validity window"
        case .unsupportedVersion(let v): return "unsupported wire version \(v)"
        case .unsupportedSnapshotVersion(let v): return "unsupported session snapshot version \(v)"
        case .kdfFailed(let why): return "key derivation failed: \(why)"
        }
    }
}
