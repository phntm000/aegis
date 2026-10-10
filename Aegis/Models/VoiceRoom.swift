import AegisCrypto
import Foundation

// MARK: - Voice Rooms
//
// A voice room is a persistent audio space attached to a group conversation
// (the Discord "voice channel" model). Members join/leave freely; audio is a
// full-mesh WebRTC session: every participant negotiates one audio-only peer
// connection with every other participant, signaled over the group's existing
// E2EE sender-key channel (no new trust assumptions).
//
// Glare avoidance is deterministic: of any pair, the participant whose
// identity fingerprint sorts lower initiates the WebRTC offer. Heartbeats keep
// the roster live; a participant unheard for 45s is expired locally.

/// One participant in a voice room.
struct VoiceRoomParticipant: Identifiable, Hashable, Sendable {
    var id: String { fingerprintHex }
    let fingerprintHex: String
    var displayName: String
    var isMuted: Bool
    var isDeafened: Bool
    var joinedAt: Date
    var lastHeartbeat: Date
    /// True for the local user (never signaled; set locally).
    var isLocal: Bool = false

    var isStale: Bool {
        Date().timeIntervalSince(lastHeartbeat) > VoiceRoom.staleAfter
    }
}

/// The state of one voice room, published to the UI.
struct VoiceRoom: Sendable {
    /// Attached group conversation.
    let conversationID: UUID
    let groupName: String
    var participants: [VoiceRoomParticipant]
    var localMuted: Bool
    var localDeafened: Bool
    var joinedAt: Date?

    static let heartbeatInterval: TimeInterval = 15
    static let staleAfter: TimeInterval = 45

    /// True while the local user is in the room.
    var isJoined: Bool { joinedAt != nil }

    var activeCount: Int { participants.count }

    /// Display-sorted: local first, then by name.
    var sortedParticipants: [VoiceRoomParticipant] {
        participants.sorted {
            if $0.isLocal != $1.isLocal { return $0.isLocal }
            return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }
    }
}

/// Wire kinds for voice-room signaling (sent as GroupControlMessage kind
/// "voiceRoom"; the body is a JSON-encoded VoiceRoomSignal).
enum VoiceRoomSignalKind: String, Codable, Sendable {
    /// Announce presence (carries display name + mute state).
    case join
    /// Voluntary departure.
    case leave
    /// Periodic liveness + mute/deafen state refresh.
    case heartbeat
    /// Mute/deafen state changed (also covered by heartbeat; sent eagerly).
    case muteState
    /// WebRTC mesh signaling, addressed to one peer.
    case offer
    case answer
    case ice
}

/// One voice-room signaling message. Presence kinds (join/leave/heartbeat/
/// muteState) are broadcast to the room; offer/answer/ice are addressed to
/// `targetFingerprintHex`.
struct VoiceRoomSignal: Codable, Sendable {
    var kind: VoiceRoomSignalKind
    /// Conversation UUID string identifying the room.
    var roomID: String
    var senderFingerprintHex: String
    var senderDisplayName: String? = nil
    var isMuted: Bool? = nil
    var isDeafened: Bool? = nil
    var targetFingerprintHex: String? = nil
    /// UUID string identifying this peer pair's WebRTC session. Chosen by
    /// the offerer and echoed by the answerer so ICE trickles to the right
    /// peer connection on both sides.
    var callID: String? = nil
    var sdp: String? = nil
    var ice: IceCandidate? = nil

    /// True when this signal is addressed to the given local fingerprint.
    func isForLocal(_ localFingerprintHex: String) -> Bool {
        switch kind {
        case .offer, .answer, .ice:
            return targetFingerprintHex == localFingerprintHex
        case .join, .leave, .heartbeat, .muteState:
            return true
        }
    }
}

/// Events the voice-room layer publishes for the UI.
enum VoiceRoomEvent: Sendable {
    /// Full room snapshot (join/leave/heartbeat/expiry/mute changes).
    case updated(VoiceRoom?)
    /// A remote participant started/stopped producing audible signal.
    /// (WebRTC-level speaking detection is not implemented; reserved.)
    case speakingChanged(fingerprintHex: String, isSpeaking: Bool)
}
