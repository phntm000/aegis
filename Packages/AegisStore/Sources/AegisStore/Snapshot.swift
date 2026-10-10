// AegisStore — Store snapshot for encrypted backup.
//
// Backup scope decision (settles Aegis/INTEGRATION_NOTES.md §3/§5):
//
//   AegisCrypto exports: identity key material + signed prekey (+ sessions
//       when durable session persistence lands).
//   AegisStore exports:  THIS snapshot — every conversation, message,
//       contact, membership, attachment *metadata*, and call record.
//   The APP assembles both halves into one blob and AegisCrypto encrypts
//       it under the passphrase-derived key (see KeyBackup).
//
// Why the split: the crypto layer must never see message plaintext, and
// the store must never see key material. The app is the only layer that
// legitimately touches both, so it owns backup assembly.
//
// Attachment *ciphertext* is not in the snapshot — it lives as files.
// `Attachment.localRelativePath` lets the backup assembler copy the
// ciphertext blobs alongside this snapshot; on restore, blobs are copied
// back before `restore(_:)` is called. Keychain keys (`keychainKeyID`)
// are re-created on restore by re-wrapping... no — keys are NOT in the
// backup. Attachment file keys travel in the message envelopes' wrapped
// keys, which ARE in the snapshot's messages, so attachments remain
// decryptable after restore as long as the ciphertext blobs are copied.

import Foundation

/// A complete, portable export of everything the store persists.
/// Codable so the app can serialize it straight into the backup blob.
public struct StoreSnapshot: Codable, Sendable, Equatable {
    /// Snapshot format version. Bump if any model changes incompatibly.
    public static let currentVersion = 1

    public var version: Int
    public var exportedAt: Date
    public var conversations: [Conversation]
    public var messages: [Message]
    public var contacts: [Contact]
    public var memberships: [GroupMembership]
    public var attachments: [Attachment]
    public var callRecords: [CallRecord]

    public init(
        version: Int = StoreSnapshot.currentVersion,
        exportedAt: Date = Date(),
        conversations: [Conversation] = [],
        messages: [Message] = [],
        contacts: [Contact] = [],
        memberships: [GroupMembership] = [],
        attachments: [Attachment] = [],
        callRecords: [CallRecord] = []
    ) {
        self.version = version
        self.exportedAt = exportedAt
        self.conversations = conversations
        self.messages = messages
        self.contacts = contacts
        self.memberships = memberships
        self.attachments = attachments
        self.callRecords = callRecords
    }
}
