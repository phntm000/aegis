import Foundation

/// The local user's identity.
///
/// There is no account, no phone number, no email. The identity IS the keypair.
/// Private key material never leaves AegisCrypto (Keychain / Secure Enclave) —
/// this struct carries only public, displayable facts across the app boundary.
struct LocalIdentity: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    var displayName: String
    /// Ed25519/X25519 public identity key.
    let publicKey: Data
    let createdAt: Date
}

/// A remote party's identity, as parsed from an invite code or QR payload.
/// Contains no private material by construction.
struct RemoteIdentity: Sendable, Hashable {
    let displayName: String?
    let publicKey: Data
}

extension LocalIdentity {
    /// Short human handle derived from the key, e.g. "aegis:8f3k…9d2q".
    /// Never a username — there is no namespace to squat.
    var shortHandle: String {
        let b64 = publicKey.base64EncodedString()
            .replacingOccurrences(of: "+", with: "")
            .replacingOccurrences(of: "/", with: "")
            .replacingOccurrences(of: "=", with: "")
        let head = b64.prefix(4).lowercased()
        let tail = b64.suffix(4).lowercased()
        return "aegis:\(head)…\(tail)"
    }
}
