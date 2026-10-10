import CryptoKit
import Foundation
import XCTest
@testable import Aegis
@testable import AegisCrypto

/// Unit tests for Phase-3 additions: voice-room signaling models and the
/// device-link pairing crypto. All pure Swift — no camera, network, or
/// keychain required.
final class Phase3Tests: XCTestCase {

    // MARK: - VoiceRoomSignal

    func testVoiceRoomSignalRoundTrip() throws {
        var signal = VoiceRoomSignal(
            kind: .offer,
            roomID: UUID().uuidString,
            senderFingerprintHex: "aa",
            senderDisplayName: "Alice",
            isMuted: false,
            isDeafened: false,
            targetFingerprintHex: "bb",
            callID: UUID().uuidString,
            sdp: "v=0\r\n",
            ice: nil
        )
        let data = try JSONEncoder().encode(signal)
        let decoded = try JSONDecoder().decode(VoiceRoomSignal.self, from: data)
        XCTAssertEqual(decoded.kind, .offer)
        XCTAssertEqual(decoded.roomID, signal.roomID)
        XCTAssertEqual(decoded.senderFingerprintHex, "aa")
        XCTAssertEqual(decoded.targetFingerprintHex, "bb")
        XCTAssertEqual(decoded.sdp, "v=0\r\n")
        // Unknown-kind forward compatibility is via JSON; every current kind
        // must survive the trip.
        for kind in [VoiceRoomSignalKind.join, .leave, .heartbeat, .muteState, .answer, .ice] as [VoiceRoomSignalKind] {
            signal.kind = kind
            let roundTripped = try JSONDecoder().decode(
                VoiceRoomSignal.self,
                from: JSONEncoder().encode(signal)
            )
            XCTAssertEqual(roundTripped.kind, kind)
        }
    }

    func testVoiceRoomSignalAddressing() {
        let local = "aa"
        var offer = VoiceRoomSignal(kind: .offer, roomID: "r", senderFingerprintHex: "bb")
        offer.targetFingerprintHex = "aa"
        XCTAssertTrue(offer.isForLocal(local))
        offer.targetFingerprintHex = "cc"
        XCTAssertFalse(offer.isForLocal(local))
        // Presence signals are broadcasts.
        for kind in [VoiceRoomSignalKind.join, .leave, .heartbeat, .muteState] as [VoiceRoomSignalKind] {
            let presence = VoiceRoomSignal(kind: kind, roomID: "r", senderFingerprintHex: "bb")
            XCTAssertTrue(presence.isForLocal(local))
        }
    }

    func testParticipantStaleness() {
        var fresh = VoiceRoomParticipant(
            fingerprintHex: "aa", displayName: "A",
            isMuted: false, isDeafened: false,
            joinedAt: Date(), lastHeartbeat: Date()
        )
        XCTAssertFalse(fresh.isStale)
        fresh.lastHeartbeat = Date().addingTimeInterval(-(VoiceRoom.staleAfter + 1))
        XCTAssertTrue(fresh.isStale)
    }

    func testVoiceRoomSorting() {
        let peer = VoiceRoomParticipant(
            fingerprintHex: "bb", displayName: "Zed",
            isMuted: false, isDeafened: false,
            joinedAt: Date(), lastHeartbeat: Date()
        )
        var me = peer
        me = VoiceRoomParticipant(
            fingerprintHex: "aa", displayName: "Amy",
            isMuted: false, isDeafened: false,
            joinedAt: Date(), lastHeartbeat: Date(), isLocal: true
        )
        let room = VoiceRoom(
            conversationID: UUID(), groupName: "g",
            participants: [peer, me],
            localMuted: false, localDeafened: false, joinedAt: Date()
        )
        XCTAssertTrue(room.sortedParticipants.first?.isLocal == true)
        XCTAssertTrue(room.isJoined)
    }

    // MARK: - Pairing SAS

    func testPairingSASWordsDeterministic() {
        let secret = Data((0..<32).map { UInt8($0) })
        let a = PairingSAS.words(for: secret)
        let b = PairingSAS.words(for: secret)
        XCTAssertEqual(a.count, 4)
        XCTAssertEqual(a, b)
        for w in a {
            XCTAssertTrue(PairingSAS.wordlist.contains(w), "word \(w) not in list")
        }
        // Different secrets overwhelmingly give different words.
        let other = PairingSAS.words(for: Data((0..<32).map { UInt8(31 - $0) }))
        XCTAssertNotEqual(a, other)
    }

    // MARK: - Device-link seal/open

    func testDeviceLinkSealOpenRoundTrip() throws {
        let provider = CryptoKitProvider.shared
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("provisioning-bundle-bytes".utf8)
        let sealed = try DeviceLinkManager.seal(plaintext, key: key, provider: provider)
        // Envelope layout: nonce(12) || ciphertext || tag(16).
        XCTAssertEqual(sealed.count, 12 + plaintext.count + 16)
        let opened = try DeviceLinkManager.open(sealed, key: key, provider: provider)
        XCTAssertEqual(opened, plaintext)
    }

    func testDeviceLinkOpenRejectsWrongKey() throws {
        let provider = CryptoKitProvider.shared
        let sealed = try DeviceLinkManager.seal(
            Data("secret".utf8),
            key: SymmetricKey(size: .bits256),
            provider: provider
        )
        XCTAssertThrowsError(
            try DeviceLinkManager.open(sealed, key: SymmetricKey(size: .bits256), provider: provider)
        )
    }

    func testDeviceLinkOpenRejectsTruncated() throws {
        let provider = CryptoKitProvider.shared
        XCTAssertThrowsError(
            try DeviceLinkManager.open(Data([1, 2, 3]), key: SymmetricKey(size: .bits256), provider: provider)
        )
    }

    func testPairingMailboxDerivation() {
        let id = Data((0..<16).map { UInt8($0) })
        let m1 = DeviceLinkManager.pairingMailbox(pairingID: id)
        let m2 = DeviceLinkManager.pairingMailbox(pairingID: id)
        XCTAssertEqual(m1, m2)
        XCTAssertEqual(m1.count, 32)
        let other = DeviceLinkManager.pairingMailbox(pairingID: Data((1..<17).map { UInt8($0) }))
        XCTAssertNotEqual(m1, other)
    }

    // MARK: - Provisioning bundle

    func testProvisioningBundleRoundTrip() throws {
        let bundle = ProvisioningBundle(
            primaryDeviceID: UUID(),
            primaryDeviceName: "iPhone",
            displayName: "Alice",
            contacts: [LinkedContact(id: UUID(), displayName: "Bob", fingerprintHex: "bb")],
            conversations: [LinkedConversation(
                id: UUID(), title: "Bob", kind: "direct",
                lastMessagePreview: "hi", lastMessageAt: Date(), unreadCount: 0
            )],
            recentMessages: [:],
            assignedDevice: DeviceInfo(
                deviceID: UUID(), deviceName: "iPad",
                deviceModel: nil, pairedAt: Date(), lastSeen: Date()
            )
        )
        let decoded = try JSONDecoder().decode(
            ProvisioningBundle.self,
            from: JSONEncoder().encode(bundle)
        )
        XCTAssertEqual(decoded.displayName, "Alice")
        XCTAssertEqual(decoded.contacts.count, 1)
        XCTAssertEqual(decoded.contacts[0].displayName, "Bob")
    }
}
