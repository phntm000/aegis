import Foundation

/// A completed (or missed) call in history. Signaling metadata only —
/// there is no call content to store; media is E2EE and never recorded.
struct CallRecord: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    let contactID: UUID
    let contactName: String
    let kind: CallKind
    let direction: CallDirection
    let startedAt: Date
    let duration: TimeInterval?
    let endReason: CallEndReason
    /// The conversation this call belongs to. Set by the live transport
    /// adapter; nil for records created by previews or older versions.
    let conversationID: UUID?

    init(
        id: UUID = UUID(),
        contactID: UUID,
        contactName: String,
        kind: CallKind,
        direction: CallDirection,
        startedAt: Date = Date(),
        duration: TimeInterval? = nil,
        endReason: CallEndReason,
        conversationID: UUID? = nil
    ) {
        self.id = id
        self.contactID = contactID
        self.contactName = contactName
        self.kind = kind
        self.direction = direction
        self.startedAt = startedAt
        self.duration = duration
        self.endReason = endReason
        self.conversationID = conversationID
    }
}

/// An inbound ringing call delivered by the transport.
struct IncomingCall: Sendable, Hashable {
    let id: UUID
    let contactID: UUID
    let contactName: String
    let kind: CallKind
    let receivedAt: Date
}

/// Verification ceremony state for the call's Short Authentication String.
enum CallSASVerification: String, Sendable, Hashable {
    /// SAS not yet compared (or not available).
    case unverified
    /// Both parties confirmed the SAS matches.
    case verified
    /// The SAS did not match — possible media-path interception.
    case mismatch
}

/// UI state for the active-call screen.
struct ActiveCall: Sendable, Hashable {
    let id: UUID
    let contactID: UUID
    let contactName: String
    let kind: CallKind
    let direction: CallDirection
    var state: ActiveCallState
    var isMuted: Bool
    var isSpeakerOn: Bool
    var isVideoEnabled: Bool
    var isScreenSharing: Bool
    var connectedAt: Date?
    /// The 4-character SAS, once both DTLS fingerprints are known.
    /// Nil while unavailable — the UI shows no ceremony then.
    var callSAS: String?
    var sasVerification: CallSASVerification = .unverified

    var elapsed: TimeInterval {
        guard let connectedAt else { return 0 }
        return Date().timeIntervalSince(connectedAt)
    }
}
