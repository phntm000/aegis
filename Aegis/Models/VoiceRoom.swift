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
    /// Whether this participant is publishing camera video. Signaled via
    /// the `cameraState` kind so tiles can render remote video.
    var isCameraOn: Bool = false
    /// Stage mode: true when this participant may transmit (host or
    /// approved speaker). Signaled via `speakerApproval`.
    var isSpeaker: Bool = false
    /// Stage mode: true when this participant asked to speak. Signaled via
    /// `handRaise`.
    var hasHandRaised: Bool = false
    /// Local-only: computed from WebRTC audio levels on this device, never
    /// transmitted. Drives the speaking ring in the UI.
    var isSpeaking: Bool = false
    /// Local-only: this device has muted the participant (their remote
    /// audio track is disabled here). Never transmitted.
    var isMutedByMe: Bool = false
    /// Local-only: WebRTC connectivity for this participant's peer
    /// connection. Drives "connecting/reconnecting" tile badges.
    var mediaState: ParticipantMediaState = .connecting

    var isStale: Bool {
        Date().timeIntervalSince(lastHeartbeat) > VoiceRoom.staleAfter
    }
}

/// WebRTC connectivity for one voice-room peer connection (local-only UI
/// state; never signaled).
enum ParticipantMediaState: String, Sendable, Hashable {
    case connecting
    case connected
    case reconnecting
    case failed
}

/// How a voice room gates who may transmit.
enum VoiceRoomMode: String, Codable, Sendable, Hashable {
    /// Everyone unmuted may talk (classic voice channel).
    case openFloor = "open"
    /// Only the host and approved speakers may transmit; everyone else is
    /// capture-muted. Audience members raise a hand to request the floor.
    case stage = "stage"
}

/// Local join lifecycle for the room UI (never signaled).
enum RoomJoinState: Sendable, Hashable {
    case idle
    case joining
    case joined
    case failed(String)
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
    /// Open-floor vs stage. Set by the host; converges via signaling.
    var mode: VoiceRoomMode = .openFloor
    /// Fingerprint of the participant currently hosting the stage
    /// (approves speakers, changes mode). Deterministically elected.
    var stageHostFingerprintHex: String? = nil
    /// Fingerprint of the participant who created the room (first joiner).
    var createdByFingerprintHex: String? = nil
    /// Local-only join lifecycle for the room UI.
    var joinState: RoomJoinState = .idle
    /// Local-only: camera publishing state for the local user.
    var localCameraOn: Bool = false
    /// Local-only: fingerprint hex → this side's WebRTC session UUID, so
    /// the UI can register per-participant video sinks.
    var videoCallIDs: [String: UUID] = [:]
    /// Local-only: microphone permission was denied; the UI shows a
    /// rationale + Settings link.
    var micPermissionDenied: Bool = false
    /// Local-only: camera permission was denied; the UI shows a rationale
    /// + Settings link.
    var cameraPermissionDenied: Bool = false

    static let heartbeatInterval: TimeInterval = 15
    static let staleAfter: TimeInterval = 45

    /// True while the local user is in the room.
    var isJoined: Bool { joinedAt != nil }

    var activeCount: Int { participants.count }

    /// Fingerprint hex of the local participant, if present.
    var localFingerprintHex: String? {
        participants.first(where: \.isLocal)?.fingerprintHex
    }

    /// True when the local user is the current stage host.
    var isLocalHost: Bool {
        guard let local = localFingerprintHex, let host = stageHostFingerprintHex else { return false }
        return local == host
    }

    /// Participants with a raised hand (stage mode), oldest request first.
    var raisedHands: [VoiceRoomParticipant] {
        participants.filter { $0.hasHandRaised && !$0.isLocal }
            .sorted { $0.joinedAt < $1.joinedAt }
    }

    /// Display-sorted: local first, then speakers, then by name.
    var sortedParticipants: [VoiceRoomParticipant] {
        participants.sorted {
            if $0.isLocal != $1.isLocal { return $0.isLocal }
            if $0.isSpeaker != $1.isSpeaker { return $0.isSpeaker }
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
    /// Camera publish state changed (carries isCameraOn; sent eagerly).
    case cameraState
    /// Room mode changed (carries roomMode + stage host). Host-only.
    case modeChanged
    /// Audience member raised/lowered their hand (carries handRaised).
    case handRaise
    /// Host approved/denied a speaker (addressed; carries speakerApproved).
    case speakerApproval
    /// Membership changed; every member re-establishes its mesh peer
    /// connections on fresh DTLS identities (forward secrecy). Carries
    /// mediaEpoch so late/duplicate bumps converge instead of looping.
    case epochBump
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
    /// Camera publishing state (cameraState kind; also on join/heartbeat).
    var isCameraOn: Bool? = nil
    /// Room mode (modeChanged kind; also on join/heartbeat for convergence).
    var roomMode: VoiceRoomMode? = nil
    /// Current stage host fingerprint (modeChanged / join / heartbeat).
    var stageHostFingerprintHex: String? = nil
    /// Room creator fingerprint (join kind; lets late joiners converge).
    var createdByFingerprintHex: String? = nil
    /// Hand-raise state (handRaise kind).
    var handRaised: Bool? = nil
    /// Speaker approval (speakerApproval kind, addressed to target).
    var speakerApproved: Bool? = nil
    /// Stage speaking right (join/heartbeat; converges late joiners).
    var isSpeaker: Bool? = nil
    /// Membership epoch for epochBump convergence.
    var mediaEpoch: UInt64? = nil
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
        case .offer, .answer, .ice, .speakerApproval:
            return targetFingerprintHex == localFingerprintHex
        case .join, .leave, .heartbeat, .muteState, .cameraState,
             .modeChanged, .handRaise, .epochBump:
            return true
        }
    }
}

/// Events the voice-room layer publishes for the UI.
enum VoiceRoomEvent: Sendable {
    /// Full room snapshot (join/leave/heartbeat/expiry/mute changes).
    case updated(VoiceRoom?)
    /// A participant started/stopped producing audible signal. Computed
    /// locally from WebRTC audio levels; also delivered via `updated`.
    case speakingChanged(fingerprintHex: String, isSpeaking: Bool)
    /// The OS denied camera access; the UI shows a rationale + Settings link.
    case cameraPermissionDenied
}

// MARK: - Pure helpers (unit-tested in AegisTests/VoiceRoomPlusTests)

/// Deterministically elects the stage host: the room creator while present,
/// otherwise the longest-tenured participant. Every member computes the
/// same answer from the roster, so no extra signaling round is needed.
func electStageHost(
    participants: [VoiceRoomParticipant],
    createdBy: String?
) -> String? {
    if let createdBy,
       participants.contains(where: { $0.fingerprintHex == createdBy }) {
        return createdBy
    }
    return participants.min(by: { $0.joinedAt < $1.joinedAt })?.fingerprintHex
}

/// Whether a participant may capture audio right now. Stage mode gates
/// transmission to the host and approved speakers; open floor lets anyone
/// unmuted talk.
func canTransmit(mode: VoiceRoomMode, participant: VoiceRoomParticipant) -> Bool {
    switch mode {
    case .openFloor:
        return true
    case .stage:
        return participant.isSpeaker
    }
}

/// Local speaking detection over polled WebRTC audio levels.
///
/// Levels are 0.0–1.0 linear energy from WebRTC stats (RFC 6464 audio
/// level on "track"-type stats), computed on this device. Hysteresis avoids flicker: two consecutive polls above the start
/// threshold assert speaking, four consecutive polls below the stop
/// threshold release it. Nothing here is transmitted — input and output
/// stay on the device, so no voice biometrics ever leave it.
struct SpeakingDetector {
    /// Level that starts counting toward "speaking".
    var startThreshold: Float = 0.08
    /// Consecutive polls above the start threshold needed to assert.
    var startPolls = 2
    /// Level that starts counting toward "silent".
    var stopThreshold: Float = 0.05
    /// Consecutive polls below the stop threshold needed to release.
    var stopPolls = 4

    private var aboveCount: [String: Int] = [:]
    private var belowCount: [String: Int] = [:]
    private var speaking: Set<String> = []

    /// Feeds one poll of `(participantID, level)` pairs. Returns the
    /// `(id, isSpeaking)` transitions since the last poll.
    mutating func update(levels: [(id: String, level: Float)]) -> [(String, Bool)] {
        var changes: [(String, Bool)] = []
        for (id, level) in levels {
            if speaking.contains(id) {
                if level < stopThreshold {
                    belowCount[id, default: 0] += 1
                    if belowCount[id, default: 0] >= stopPolls {
                        speaking.remove(id)
                        belowCount[id] = 0
                        changes.append((id, false))
                    }
                } else {
                    belowCount[id] = 0
                }
            } else {
                if level > startThreshold {
                    aboveCount[id, default: 0] += 1
                    if aboveCount[id, default: 0] >= startPolls {
                        speaking.insert(id)
                        aboveCount[id] = 0
                        changes.append((id, true))
                    }
                } else {
                    aboveCount[id] = 0
                }
            }
        }
        return changes
    }

    /// Drops a participant (leave/expiry) so stale counters can't fire later.
    mutating func remove(id: String) {
        aboveCount.removeValue(forKey: id)
        belowCount.removeValue(forKey: id)
        speaking.remove(id)
    }
}
