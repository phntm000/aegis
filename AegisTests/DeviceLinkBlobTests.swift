import Foundation
import XCTest
@testable import Aegis

/// Unit tests for the linked-device blob sync models: the new sync kinds,
/// attachment/voice-note metadata on LinkedMessage, and the sync progress
/// model. Pure Swift — no keychain, network, or file IO.
final class DeviceLinkBlobTests: XCTestCase {

    func testNewSyncKindsDecode() throws {
        for raw in ["attachmentManifest", "attachmentChunk", "attachmentRequest", "attachmentFailure"] {
            let data = "\"\(raw)\"".data(using: .utf8)!
            let kind = try JSONDecoder().decode(DeviceSyncKind.self, from: data)
            XCTAssertEqual(kind.rawValue, raw)
        }
    }

    func testExistingSyncKindsUnaffected() throws {
        // The text path must keep working exactly as-is.
        for raw in ["sendMessage", "incomingMessage", "messageStatus", "unpair", "heartbeat", "provisioningApplied"] {
            let data = "\"\(raw)\"".data(using: .utf8)!
            XCTAssertEqual(try JSONDecoder().decode(DeviceSyncKind.self, from: data).rawValue, raw)
        }
    }

    func testLinkedMessageCarriesAttachmentMeta() throws {
        var message = LinkedMessage(
            id: UUID(), conversationID: UUID(), body: nil, replyToID: nil,
            isFromMe: false, senderName: "Ana", status: "delivered",
            sentAt: Date(), expiresAt: nil
        )
        message.attachment = LinkedAttachmentMeta(
            id: UUID(), filename: "photo.jpg", mimeType: "image/jpeg",
            byteCount: 1_024_000, thumbnailData: Data([1, 2, 3])
        )
        let decoded = try JSONDecoder().decode(
            LinkedMessage.self, from: JSONEncoder().encode(message))
        XCTAssertEqual(decoded.attachment?.filename, "photo.jpg")
        XCTAssertEqual(decoded.attachment?.byteCount, 1_024_000)
        XCTAssertNil(decoded.voiceNote)
        // Text-only messages still decode (backward compatible).
        XCTAssertNil(message.voiceNote)
    }

    func testLinkedMessageCarriesVoiceNoteMetaWithTranscript() throws {
        var message = LinkedMessage(
            id: UUID(), conversationID: UUID(), body: nil, replyToID: nil,
            isFromMe: true, senderName: nil, status: "sent",
            sentAt: Date(), expiresAt: nil
        )
        message.voiceNote = LinkedVoiceNoteMeta(
            id: UUID(), duration: 12.5, levels: [0.2, 0.8],
            transcript: "see you at six"
        )
        let decoded = try JSONDecoder().decode(
            LinkedMessage.self, from: JSONEncoder().encode(message))
        XCTAssertEqual(decoded.voiceNote?.transcript, "see you at six")
        XCTAssertEqual(decoded.voiceNote?.duration ?? 0, 12.5, accuracy: 0.001)
        XCTAssertNil(decoded.attachment)
    }

    func testLinkedMessageWithoutMediaStillDecodes() throws {
        // Old payloads without the new fields must decode (new fields are
        // optional in the memberwise init — encoded JSON simply omits them
        // when nil... so simulate by decoding minimal JSON).
        let json = """
        {"id":"\(UUID().uuidString)","conversationID":"\(UUID().uuidString)",\
        "isFromMe":true,"status":"sent","sentAt":\(Date().timeIntervalSince1970)}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(LinkedMessage.self, from: json)
        XCTAssertNil(decoded.attachment)
        XCTAssertNil(decoded.voiceNote)
        XCTAssertNil(decoded.body)
    }

    func testDeviceSyncProgressStates() {
        let id = UUID()
        let streaming = DeviceSyncProgress(
            id: id, filename: "a.pdf", deviceName: "iPad",
            progress: 0.5, state: .streaming)
        let done = DeviceSyncProgress(
            id: id, filename: "a.pdf", deviceName: "iPad",
            progress: 1, state: .done)
        XCTAssertNotEqual(streaming, done)
        XCTAssertEqual(
            DeviceSyncProgress.State.failed("x"), DeviceSyncProgress.State.failed("x"))
    }

    func testVoiceNoteTranscriptDefaultsNil() {
        let note = VoiceNote(duration: 3, levels: [0.5])
        XCTAssertNil(note.transcript)
        let withTranscript = VoiceNote(duration: 3, levels: [0.5], transcript: "hi")
        XCTAssertEqual(withTranscript.transcript, "hi")
    }
}
