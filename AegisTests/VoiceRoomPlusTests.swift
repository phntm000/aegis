import CoreGraphics
import Foundation
import XCTest
@testable import Aegis

// MARK: - Voice rooms plus: pure-logic unit tests
//
// Covers the pieces that don't need WebRTC, a camera, or the network:
// signaling wire format, stage host election, transmit gating, speaking
// detection hysteresis, and redaction-rect normalization. The media engine,
// mixer, and UI are verified on macOS CI runners and on-device.

final class VoiceRoomPlusTests: XCTestCase {

    // MARK: - Signaling wire format

    func testSignalRoundTripWithNewFields() throws {
        var signal = VoiceRoomSignal(
            kind: .modeChanged,
            roomID: UUID().uuidString,
            senderFingerprintHex: "aa",
            senderDisplayName: "Test"
        )
        signal.isCameraOn = true
        signal.roomMode = .stage
        signal.stageHostFingerprintHex = "aa"
        signal.createdByFingerprintHex = "aa"
        signal.handRaised = true
        signal.isSpeaker = true
        signal.speakerApproved = true
        signal.mediaEpoch = 7

        let data = try JSONEncoder().encode(signal)
        let decoded = try JSONDecoder().decode(VoiceRoomSignal.self, from: data)

        XCTAssertEqual(decoded.kind, .modeChanged)
        XCTAssertEqual(decoded.isCameraOn, true)
        XCTAssertEqual(decoded.roomMode, .stage)
        XCTAssertEqual(decoded.stageHostFingerprintHex, "aa")
        XCTAssertEqual(decoded.handRaised, true)
        XCTAssertEqual(decoded.speakerApproved, true)
        XCTAssertEqual(decoded.mediaEpoch, 7)
    }

    func testOldSignalsStillDecode() throws {
        // Wire compatibility: older clients send only the original fields.
        let json = """
        {"kind":"heartbeat","roomID":"r","senderFingerprintHex":"bb","isMuted":true}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(VoiceRoomSignal.self, from: json)
        XCTAssertEqual(decoded.kind, .heartbeat)
        XCTAssertNil(decoded.roomMode)
        XCTAssertNil(decoded.isCameraOn)
        XCTAssertNil(decoded.mediaEpoch)
    }

    func testSpeakerApprovalIsAddressed() {
        var signal = VoiceRoomSignal(kind: .speakerApproval, roomID: "r", senderFingerprintHex: "host")
        signal.targetFingerprintHex = "peer"
        XCTAssertTrue(signal.isForLocal("peer"))
        XCTAssertFalse(signal.isForLocal("other"))
        // Presence kinds are still broadcast.
        XCTAssertTrue(VoiceRoomSignal(kind: .cameraState, roomID: "r", senderFingerprintHex: "x").isForLocal("anyone"))
    }

    // MARK: - Stage host election

    private func participant(_ fp: String, joinedAt: TimeInterval) -> VoiceRoomParticipant {
        VoiceRoomParticipant(
            fingerprintHex: fp, displayName: fp,
            isMuted: false, isDeafened: false,
            joinedAt: Date(timeIntervalSince1970: joinedAt),
            lastHeartbeat: Date()
        )
    }

    func testHostIsCreatorWhilePresent() {
        let roster = [participant("a", joinedAt: 1), participant("b", joinedAt: 2)]
        XCTAssertEqual(electStageHost(participants: roster, createdBy: "b"), "b")
    }

    func testHostFallsBackToLongestTenured() {
        let roster = [participant("a", joinedAt: 5), participant("b", joinedAt: 2)]
        XCTAssertEqual(electStageHost(participants: roster, createdBy: "gone"), "b")
        XCTAssertEqual(electStageHost(participants: roster, createdBy: nil), "b")
    }

    func testHostElectionEmpty() {
        XCTAssertNil(electStageHost(participants: [], createdBy: "x"))
    }

    // MARK: - Transmit gating

    func testCanTransmit() {
        var p = participant("a", joinedAt: 1)
        XCTAssertTrue(canTransmit(mode: .openFloor, participant: p))
        XCTAssertFalse(canTransmit(mode: .stage, participant: p))
        p.isSpeaker = true
        XCTAssertTrue(canTransmit(mode: .stage, participant: p))
    }

    // MARK: - Speaking detector

    func testSpeakingDetectorHysteresis() {
        var detector = SpeakingDetector(
            startThreshold: 0.08, startPolls: 2,
            stopThreshold: 0.05, stopPolls: 4
        )
        // One loud poll isn't enough (needs 2 consecutive).
        XCTAssertTrue(detector.update(levels: [("a", 0.5)]).isEmpty)
        let asserted = detector.update(levels: [("a", 0.5)])
        XCTAssertEqual(asserted.count, 1)
        XCTAssertEqual(asserted[0].0, "a")
        XCTAssertEqual(asserted[0].1, true)

        // A single quiet poll doesn't release (needs 4 consecutive).
        XCTAssertTrue(detector.update(levels: [("a", 0.0)]).isEmpty)
        XCTAssertTrue(detector.update(levels: [("a", 0.0)]).isEmpty)
        XCTAssertTrue(detector.update(levels: [("a", 0.0)]).isEmpty)
        let released = detector.update(levels: [("a", 0.0)])
        XCTAssertEqual(released.count, 1)
        XCTAssertEqual(released[0].1, false)
    }

    func testSpeakingDetectorIgnoresSubThreshold() {
        var detector = SpeakingDetector()
        for _ in 0..<10 {
            XCTAssertTrue(detector.update(levels: [("a", 0.07)]).isEmpty)
        }
    }

    func testSpeakingDetectorRemove() {
        var detector = SpeakingDetector(startPolls: 1, stopPolls: 100)
        _ = detector.update(levels: [("a", 0.9)])
        detector.remove(id: "a")
        // After removal the peer is unknown; a fresh loud poll re-asserts
        // rather than acting on stale counters.
        let changes = detector.update(levels: [("a", 0.9)])
        XCTAssertEqual(changes.count, 1)
        XCTAssertTrue(changes[0].1)
    }

    // MARK: - Redaction rects

    func testRedactionClamp() {
        let clamped = CGRect(x: -0.5, y: 1.5, width: 2, height: 2).clampedToUnit()
        XCTAssertEqual(clamped.minX, 0, accuracy: 0.001)
        XCTAssertEqual(clamped.minY, 1, accuracy: 0.001)
        XCTAssertEqual(clamped.width, 1, accuracy: 0.001)
        XCTAssertEqual(clamped.height, 0, accuracy: 0.001)
    }

    func testDegenerateRect() {
        XCTAssertTrue(CGRect(x: 0.1, y: 0.1, width: 0.005, height: 0.5).isDegenerate)
        XCTAssertFalse(CGRect(x: 0.1, y: 0.1, width: 0.02, height: 0.5).isDegenerate)
    }

    // MARK: - Room model

    func testRaisedHandsOrdering() {
        var room = VoiceRoom(
            conversationID: UUID(), groupName: "g",
            participants: [], localMuted: false, localDeafened: false,
            joinedAt: nil
        )
        var a = participant("a", joinedAt: 2); a.hasHandRaised = true
        var b = participant("b", joinedAt: 1); b.hasHandRaised = true
        var c = participant("c", joinedAt: 3) // hand down
        room.participants = [a, b, c]
        XCTAssertEqual(room.raisedHands.map(\.fingerprintHex), ["b", "a"])
    }

    func testSortedParticipantsSpeakersAfterLocal() {
        var room = VoiceRoom(
            conversationID: UUID(), groupName: "g",
            participants: [], localMuted: false, localDeafened: false,
            joinedAt: nil, mode: .stage
        )
        var local = participant("local", joinedAt: 1); local.isLocal = true
        var speaker = participant("Zed", joinedAt: 2); speaker.isSpeaker = true
        let audience = participant("Amy", joinedAt: 3)
        room.participants = [audience, speaker, local]
        XCTAssertEqual(room.sortedParticipants.map(\.fingerprintHex), ["local", "Zed", "Amy"])
    }
}
