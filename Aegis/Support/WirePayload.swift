import AegisCrypto
import Foundation

/// The app's own envelope payload format.
///
/// Flow: app builds a `WirePayload` → JSON-encodes → AegisCrypto encrypts →
/// AegisTransport sends ciphertext. Inbound is the reverse. The transport and
/// crypto layers are agnostic to this schema; it is versioned so future app
/// releases can evolve it without breaking the other packages.
///
/// Signed events: `reaction`, `edit`, `delete`, `ballot`, `pin`, and `unpin`
/// carry an Ed25519 `signature` over `signableBytes()`, made with the
/// sender's long-term identity key. The AEAD channel already authenticates
/// the session; the identity signature additionally binds the event to the
/// long-term identity, so events stay attributable across session resets
/// and can't be forged by a compromised session key alone.
struct WirePayload: Codable, Sendable {
    static let currentVersion = 1

    enum Kind: String, Codable, Sendable {
        case text
        case reaction
        case edit
        case delete
        case readReceipt
        case typing
        case screenshotNotice
        /// A request to join a group/channel, sent 1:1 (X3DH) to the
        /// inviter after redeeming an `aegis-group:` invite code. The
        /// inviter's app surfaces it for approval; approval triggers the
        /// normal `inviteMember` flow (real invite + sender-key
        /// distributions). Never rendered as a chat message.
        case groupJoinRequest
        /// A poll creation. Renders as a message carrying a `PollMessage`.
        case poll
        /// A signed vote on a poll. `targetMessageID` is the poll message.
        case ballot
        /// A signed pin of a message. `targetMessageID` is the pinned message.
        case pin
        /// A signed unpin of a message.
        case unpin
    }

    /// Event kinds that must carry an identity signature. Unsigned events
    /// of these kinds are dropped on receipt.
    static let signedKinds: Set<Kind> = [.reaction, .edit, .delete, .ballot, .pin, .unpin]

    var version: Int
    var kind: Kind

    // Message fields
    var messageID: UUID?
    var body: String?
    var replyToID: UUID?
    /// Frozen quote of the replied-to message (advisory; the live pointer
    /// is `replyToID`).
    var quote: QuoteSnapshot?
    /// Threading: set on `.text`/`.poll` for replies inside a thread.
    var threadRootID: UUID?
    var attachment: Attachment?
    var voiceNote: VoiceNote?
    var expiresIn: TimeInterval?
    /// When true, the disappearing timer starts on read, not on send.
    var disappearAfterRead: Bool?

    // Reaction / edit / delete fields
    var targetMessageID: UUID?
    var emoji: String?
    var editedBody: String?

    // Poll fields (kind == .poll)
    var pollQuestion: String?
    var pollOptions: [String]?
    var pollAllowsMultipleChoice: Bool?
    var pollAnonymous: Bool?
    var pollClosesAt: Date?
    var pollEligibleVoterCount: Int?

    // Ballot fields (kind == .ballot)
    /// Chosen option indices.
    var ballotChoices: [Int]?

    // Pin fields (kind == .pin)
    /// Optional pin expiry; nil = until unpinned.
    var pinExpiresAt: Date?

    // Read receipt fields
    var messageIDs: [UUID]?

    // Typing fields
    var isTyping: Bool?

    /// Ed25519 signature over `signableBytes()` by the sender's identity
    /// key. Required for `signedKinds`.
    var signature: Data?

    /// Identity-rotation hint: fingerprint (32 bytes) of the sender's
    /// previous identity, included (encrypted) when this device replaced its
    /// identity. Lets the recipient link the new key to the existing contact
    /// and show "safety number changed" instead of an unknown sender. It is
    /// only a hint — the recipient still verifies out-of-band before trusting
    /// the new key.
    var previousFingerprint: Data?

    // Group join-request fields (kind == .groupJoinRequest only).
    /// The inviter's conversation UUID (from the redeemed invite code).
    var joinGroupReference: String?
    /// The requester's display name, for the approval UI.
    var joinRequesterName: String?
    /// The invite generation the code was issued at (nil for legacy
    /// codes). Requests from revoked generations are declined: the
    /// generation is the revocation mechanism.
    var joinInviteGeneration: Int?

    init(kind: Kind) {
        self.version = Self.currentVersion
        self.kind = kind
    }

    // MARK: - Constructors

    static func text(
        id: UUID,
        body: String?,
        replyToID: UUID?,
        quote: QuoteSnapshot?,
        threadRootID: UUID?,
        attachment: Attachment?,
        voiceNote: VoiceNote?,
        expiresIn: TimeInterval?,
        disappearAfterRead: Bool?
    ) -> WirePayload {
        var p = WirePayload(kind: .text)
        p.messageID = id
        p.body = body
        p.replyToID = replyToID
        p.quote = quote
        p.threadRootID = threadRootID
        p.attachment = attachment
        p.voiceNote = voiceNote
        p.expiresIn = expiresIn
        p.disappearAfterRead = disappearAfterRead
        return p
    }

    static func reaction(targetMessageID: UUID, emoji: String) -> WirePayload {
        var p = WirePayload(kind: .reaction)
        p.targetMessageID = targetMessageID
        p.emoji = emoji
        return p
    }

    static func edit(targetMessageID: UUID, editedBody: String) -> WirePayload {
        var p = WirePayload(kind: .edit)
        p.targetMessageID = targetMessageID
        p.editedBody = editedBody
        return p
    }

    static func delete(targetMessageID: UUID) -> WirePayload {
        var p = WirePayload(kind: .delete)
        p.targetMessageID = targetMessageID
        return p
    }

    static func poll(
        id: UUID,
        question: String,
        options: [String],
        allowsMultipleChoice: Bool,
        anonymous: Bool,
        closesAt: Date?,
        eligibleVoterCount: Int?,
        expiresIn: TimeInterval?,
        disappearAfterRead: Bool?
    ) -> WirePayload {
        var p = WirePayload(kind: .poll)
        p.messageID = id
        p.pollQuestion = question
        p.pollOptions = options
        p.pollAllowsMultipleChoice = allowsMultipleChoice
        p.pollAnonymous = anonymous
        p.pollClosesAt = closesAt
        p.pollEligibleVoterCount = eligibleVoterCount
        p.expiresIn = expiresIn
        p.disappearAfterRead = disappearAfterRead
        return p
    }

    static func ballot(targetMessageID: UUID, choices: [Int]) -> WirePayload {
        var p = WirePayload(kind: .ballot)
        p.targetMessageID = targetMessageID
        p.ballotChoices = choices
        return p
    }

    static func pin(targetMessageID: UUID, expiresAt: Date?) -> WirePayload {
        var p = WirePayload(kind: .pin)
        p.targetMessageID = targetMessageID
        p.pinExpiresAt = expiresAt
        return p
    }

    static func unpin(targetMessageID: UUID) -> WirePayload {
        var p = WirePayload(kind: .unpin)
        p.targetMessageID = targetMessageID
        return p
    }

    // MARK: - Signed events

    /// Canonical bytes covered by the identity signature. Domain-separated
    /// per kind so a signature can never be replayed as another event kind.
    /// Field order is fixed; every field is length-delimited by structure
    /// (never by parsing), so encoding is deterministic.
    func signableBytes() -> Data {
        var parts: [String] = [
            "AegisMsgEventSig_v1",
            String(version),
            kind.rawValue,
            messageID?.uuidString ?? "-",
            targetMessageID?.uuidString ?? "-",
            threadRootID?.uuidString ?? "-",
            replyToID?.uuidString ?? "-",
        ]
        parts.append(body ?? "-")
        parts.append(editedBody ?? "-")
        parts.append(emoji ?? "-")
        parts.append((ballotChoices ?? []).map { String($0) }.joined(separator: ","))
        parts.append(pollQuestion ?? "-")
        parts.append((pollOptions ?? []).joined(separator: "\u{1F}"))
        parts.append(pollAllowsMultipleChoice.map(String.init) ?? "-")
        parts.append(pollAnonymous.map(String.init) ?? "-")
        parts.append(pollClosesAt.map { String($0.timeIntervalSince1970) } ?? "-")
        parts.append(pinExpiresAt.map { String($0.timeIntervalSince1970) } ?? "-")
        parts.append(expiresIn.map { String($0) } ?? "-")
        return Data(parts.joined(separator: "\u{1E}").utf8)
    }

    /// Attaches an identity signature (Ed25519 over `signableBytes()`).
    /// The signing key never leaves the crypto layer: the caller passes a
    /// signing closure.
    mutating func attachSignature(_ signature: Data) {
        self.signature = signature
    }

    /// Verifies the identity signature against the sender's 32-byte Ed25519
    /// signing public key. Returns false when the signature is missing or
    /// invalid. Kinds outside `signedKinds` are not signature-gated.
    func verifySignature(signingPublicKey: Data) -> Bool {
        guard Self.signedKinds.contains(kind) else { return true }
        guard let signature, signature.count == 64, signingPublicKey.count == 32 else {
            return false
        }
        return Ed25519KeyPair.verify(
            signature: signature,
            for: signableBytes(),
            publicKey: signingPublicKey
        )
    }

    static func readReceipt(messageIDs: [UUID]) -> WirePayload {
        var p = WirePayload(kind: .readReceipt)
        p.messageIDs = messageIDs
        return p
    }

    static func typing(isTyping: Bool) -> WirePayload {
        var p = WirePayload(kind: .typing)
        p.isTyping = isTyping
        return p
    }

    static func screenshotNotice() -> WirePayload {
        WirePayload(kind: .screenshotNotice)
    }

    // MARK: - Coders

    func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func decoded(from data: Data) throws -> WirePayload {
        try JSONDecoder().decode(WirePayload.self, from: data)
    }
}
