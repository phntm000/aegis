// RoutingMailbox — derivation of the 32-byte frame-routing mailbox.
//
// This reconciles the two mailbox concepts that previously disagreed:
//
//   16-byte identity mailbox  (`Identity.mailboxID`)
//       Stable per identity. Used INSIDE the sealed-sender construction as
//       the KDF salt and certificate binding (see SealedSender.swift).
//       It addresses a *recipient identity*, never a conversation.
//
//   32-byte routing mailbox  (this file, `AegisTransport.MailboxID`,
//       `AegisFrame`, `relay.py`, docs/NETWORKING.md)
//       The anonymous routing label on the wire frame. Rotates per
//       conversation per epoch so the relay cannot link a conversation's
//       traffic over time. Carries no identity semantics.
//
// Layering: an `AegisFrame` is addressed by the 32-byte routing mailbox;
// its payload is a `SealedEnvelope` addressed (cryptographically) to the
// recipient's 16-byte identity mailbox. The relay routes on the outer
// label; only the recipient can open the inner envelope.
//
// Unlinkability argument: every derivation below is a one-way hash of
// secret or high-entropy inputs. The relay observes successive 32-byte
// labels but cannot compute the derivation (it lacks the group ID /
// session key) and therefore cannot tell that two labels belong to the
// same conversation — rotation is observable, linkage is not.

import CryptoKit
import Foundation

/// Derivation of 32-byte wire-routing mailboxes.
public enum RoutingMailbox {
    // MARK: - Identity route (pre-session)

    /// The routing label used before a 1:1 session exists (the first
    /// prekey message). Deterministic and stable per identity — the relay
    /// *can* link pre-session traffic, but a prekey message is a single
    /// handshake; everything after it moves to `directRoute`.
    ///
    ///   route = SHA256("AegisIdentityRoute_v1" || fingerprint)
    public static func identityRoute(fingerprint: Data) -> Data {
        precondition(fingerprint.count == 32, "fingerprint must be 32 bytes")
        var context = Data("AegisIdentityRoute_v1".utf8)
        context.append(fingerprint)
        return Data(SHA256.hash(data: context))
    }

    // MARK: - 1:1 route (post-session)

    /// The routing label for an established 1:1 session. Derived from the
    /// X3DH ephemeral public key (visible to both parties in the
    /// `PreKeyMessage`) and both fingerprints — never from ratchet state,
    /// which the two sides cannot keep synchronized for addressing
    /// purposes. Stable for the session's lifetime; a fresh X3DH handshake
    /// (the adapter re-handshakes on a rotation policy) yields a fresh,
    /// unlinkable label.
    ///
    ///   route = SHA256("AegisDirectRoute_v1" || min(fpA,fpB) ||
    ///                  max(fpA,fpB) || ephemeralPub)
    ///
    /// Honest limitation, stated plainly: within one session the relay
    /// observes a single stable label for the conversation. That is the
    /// same exposure Signal's server has by design, and it is strictly
    /// less than any phone-number-addressed system. Rotation happens at
    /// session re-establishment, not per message.
    public static func directRoute(
        localFingerprint: Data,
        remoteFingerprint: Data,
        ephemeralPublicKey: Data
    ) -> Data {
        precondition(localFingerprint.count == 32 && remoteFingerprint.count == 32)
        precondition(ephemeralPublicKey.count == 32)
        let (first, second): (Data, Data) =
            localFingerprint.lexicographicallyPrecedes(remoteFingerprint)
            ? (localFingerprint, remoteFingerprint)
            : (remoteFingerprint, localFingerprint)
        var context = Data("AegisDirectRoute_v1".utf8)
        context.append(first)
        context.append(second)
        context.append(ephemeralPublicKey)
        return Data(SHA256.hash(data: context))
    }

    // MARK: - Group route

    /// The routing label for a group epoch. The group ID is 32 bytes of
    /// randomness created at group inception and known only to members
    /// (distributed inside 1:1 sessions); the epoch bumps on every
    /// membership change, which members already track via `GroupSession`.
    ///
    ///   route = SHA256("AegisGroupRoute_v1" || groupID || epochBE)
    public static func groupRoute(groupID: Data, epoch: UInt32) -> Data {
        precondition(groupID.count == 32, "groupID must be 32 bytes")
        var context = Data("AegisGroupRoute_v1".utf8)
        context.append(groupID)
        withUnsafeBytes(of: epoch.bigEndian) { context.append(contentsOf: $0) }
        return Data(SHA256.hash(data: context))
    }
}
