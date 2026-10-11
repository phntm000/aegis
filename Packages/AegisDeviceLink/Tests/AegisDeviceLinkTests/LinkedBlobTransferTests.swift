import CryptoKit
import Foundation
import XCTest
@testable import AegisDeviceLink

/// Unit tests for the paired-channel blob transfer protocol: wire
/// round-trips, chunk math, reassembly, dedupe, resume offsets, and hash
/// verification. All pure Swift — no keychain, network, or file IO.
final class LinkedBlobTransferTests: XCTestCase {

    private func sampleManifest(chunkCount: Int = 4) -> LinkedBlobManifest {
        LinkedBlobManifest(
            attachmentID: UUID(),
            messageID: UUID(),
            conversationID: UUID(),
            kind: .attachment,
            filename: "photo.jpg",
            mimeType: "image/jpeg",
            byteCount: Int64(chunkCount * BlobTransfer.chunkSize),
            chunkSize: BlobTransfer.chunkSize,
            chunkCount: chunkCount,
            blobSHA256: Data(repeating: 0xAB, count: 32),
            relayLocator: "relay:test-locator",
            fileKey: Data(repeating: 0xCD, count: 32),
            thumbnail: Data([1, 2, 3])
        )
    }

    // MARK: - Wire round-trips

    func testManifestRoundTrip() throws {
        let manifest = sampleManifest()
        let data = try JSONEncoder().encode(manifest)
        let decoded = try JSONDecoder().decode(LinkedBlobManifest.self, from: data)
        XCTAssertEqual(decoded, manifest)
    }

    func testVoiceNoteManifestRoundTrip() throws {
        var manifest = sampleManifest()
        manifest.kind = .voiceNote
        manifest.voiceDuration = 12.5
        manifest.voiceLevels = [0.1, 0.9, 0.4]
        manifest.transcript = "hello world"
        let decoded = try JSONDecoder().decode(
            LinkedBlobManifest.self, from: try JSONEncoder().encode(manifest))
        XCTAssertEqual(decoded.voiceDuration, 12.5)
        XCTAssertEqual(decoded.voiceLevels, [0.1, 0.9, 0.4])
        XCTAssertEqual(decoded.transcript, "hello world")
    }

    func testChunkRoundTrip() throws {
        let chunk = LinkedBlobChunk(
            transferID: UUID(), index: 7, bytes: Data((0..<100).map { UInt8($0 % 256) }))
        let decoded = try JSONDecoder().decode(
            LinkedBlobChunk.self, from: try JSONEncoder().encode(chunk))
        XCTAssertEqual(decoded, chunk)
    }

    func testRequestRoundTrip() throws {
        let req = LinkedBlobRequest(
            transferID: UUID(), attachmentID: UUID(), messageID: UUID(),
            conversationID: UUID(), fromIndex: 3)
        let decoded = try JSONDecoder().decode(
            LinkedBlobRequest.self, from: try JSONEncoder().encode(req))
        XCTAssertEqual(decoded, req)
        XCTAssertEqual(decoded.fromIndex, 3)
    }

    func testFailureRoundTrip() throws {
        let failure = LinkedBlobFailure(transferID: UUID(), reason: "gone")
        let decoded = try JSONDecoder().decode(
            LinkedBlobFailure.self, from: try JSONEncoder().encode(failure))
        XCTAssertEqual(decoded, failure)
    }

    // MARK: - Chunk math

    func testChunkCount() {
        XCTAssertEqual(BlobTransfer.chunkCount(byteCount: 0), 1)
        XCTAssertEqual(BlobTransfer.chunkCount(byteCount: 1), 1)
        XCTAssertEqual(BlobTransfer.chunkCount(byteCount: Int64(BlobTransfer.chunkSize)), 1)
        XCTAssertEqual(BlobTransfer.chunkCount(byteCount: Int64(BlobTransfer.chunkSize) + 1), 2)
        XCTAssertEqual(BlobTransfer.chunkCount(byteCount: Int64(BlobTransfer.chunkSize) * 3), 3)
    }

    func testChunkRangesCoverBlob() {
        let byteCount: Int64 = Int64(BlobTransfer.chunkSize) * 2 + 100
        var covered = 0
        let count = BlobTransfer.chunkCount(byteCount: byteCount)
        XCTAssertEqual(count, 3)
        for i in 0..<count {
            let range = BlobTransfer.range(forChunk: i, byteCount: byteCount)
            XCTAssertEqual(range.lowerBound, covered)
            covered = range.upperBound
        }
        XCTAssertEqual(covered, Int(byteCount))
    }

    // MARK: - Reassembly

    func testIngestOutOfOrderAndDedupe() async throws {
        let manifest = sampleManifest(chunkCount: 3)
        let transfer = InboundBlobTransfer(manifest: manifest)
        let c0 = LinkedBlobChunk(transferID: manifest.transferID, index: 0, bytes: Data([0]))
        let c2 = LinkedBlobChunk(transferID: manifest.transferID, index: 2, bytes: Data([2]))
        // Out of order is fine.
        XCTAssertNotNil(await transfer.ingest(c2))
        XCTAssertNotNil(await transfer.ingest(c0))
        // Duplicates are ignored (nil).
        XCTAssertNil(await transfer.ingest(c0))
        // Wrong transfer is ignored.
        let foreign = LinkedBlobChunk(transferID: UUID(), index: 1, bytes: Data([9]))
        XCTAssertNil(await transfer.ingest(foreign))
        // Out of range is ignored.
        let oob = LinkedBlobChunk(transferID: manifest.transferID, index: 99, bytes: Data([9]))
        XCTAssertNil(await transfer.ingest(oob))
        XCTAssertFalse(await transfer.isComplete)
        XCTAssertEqual(await transfer.nextMissingIndex, 1)
        let c1 = LinkedBlobChunk(transferID: manifest.transferID, index: 1, bytes: Data([1]))
        let progress = await transfer.ingest(c1)
        XCTAssertEqual(progress ?? -1, 1.0, accuracy: 0.001)
        XCTAssertTrue(await transfer.isComplete)
    }

    func testVerifiedDataChecksHash() async throws {
        var manifest = sampleManifest(chunkCount: 2)
        let bytes0 = Data(repeating: 0x01, count: BlobTransfer.chunkSize)
        let bytes1 = Data(repeating: 0x02, count: BlobTransfer.chunkSize)
        manifest.blobSHA256 = BlobTransfer.sha256(bytes0 + bytes1)
        let transfer = InboundBlobTransfer(manifest: manifest)
        await transfer.ingest(LinkedBlobChunk(transferID: manifest.transferID, index: 0, bytes: bytes0))
        await transfer.ingest(LinkedBlobChunk(transferID: manifest.transferID, index: 1, bytes: bytes1))
        let assembled = try await transfer.verifiedData()
        XCTAssertEqual(assembled, bytes0 + bytes1)
    }

    func testVerifiedDataRejectsTamperedBytes() async throws {
        var manifest = sampleManifest(chunkCount: 2)
        manifest.blobSHA256 = Data(repeating: 0xFF, count: 32) // wrong hash
        let transfer = InboundBlobTransfer(manifest: manifest)
        await transfer.ingest(LinkedBlobChunk(
            transferID: manifest.transferID, index: 0,
            bytes: Data(repeating: 0x01, count: BlobTransfer.chunkSize)))
        await transfer.ingest(LinkedBlobChunk(
            transferID: manifest.transferID, index: 1,
            bytes: Data(repeating: 0x02, count: BlobTransfer.chunkSize)))
        do {
            _ = try await transfer.verifiedData()
            XCTFail("expected hashMismatch")
        } catch BlobTransferError.hashMismatch {
            // Expected: corrupt bytes are never returned.
        }
    }

    func testVerifiedDataRejectsIncomplete() async throws {
        let manifest = sampleManifest(chunkCount: 3)
        let transfer = InboundBlobTransfer(manifest: manifest)
        await transfer.ingest(LinkedBlobChunk(
            transferID: manifest.transferID, index: 0, bytes: Data([1])))
        do {
            _ = try await transfer.verifiedData()
            XCTFail("expected incompleteTransfer")
        } catch BlobTransferError.incompleteTransfer {
            // Expected.
        }
    }

    // MARK: - Resume

    func testResumeOffsetSkipsReceived() async {
        let manifest = sampleManifest(chunkCount: 4)
        let transfer = InboundBlobTransfer(
            manifest: manifest, receivedIndexes: [0, 1, 3])
        // Restored placeholders resume as missing — bytes are re-fetched.
        XCTAssertEqual(await transfer.nextMissingIndex, 0)
        XCTAssertFalse(await transfer.isComplete)
        XCTAssertEqual(await transfer.progress, 0, accuracy: 0.001)
        let indexes = await transfer.receivedIndexes.sorted()
        XCTAssertEqual(indexes, [0, 1, 3])
    }

    func testProgressTracksBytes() async {
        let manifest = sampleManifest(chunkCount: 4)
        let transfer = InboundBlobTransfer(manifest: manifest)
        await transfer.ingest(LinkedBlobChunk(
            transferID: manifest.transferID, index: 0, bytes: Data([1])))
        XCTAssertEqual(await transfer.progress, 0.25, accuracy: 0.001)
        XCTAssertEqual(await transfer.receivedCount, 1)
    }
}
