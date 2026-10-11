// LinkedBlobTransfer — chunked attachment / voice-note transfer over the
// paired device-link channel.
//
// The primary device holds the conversation keys, so only it can unwrap an
// attachment's file key. To make attachments and voice notes viewable on a
// linked secondary, the primary forwards the *ciphertext* blob (framed
// exactly as AttachmentCrypto produces it: nonce(12) || ciphertext ||
// tag(16)) in small chunks over the paired channel. Every chunk frame is
// additionally sealed by the paired channel's AES-GCM envelope
// (DeviceLinkManager.seal), so the blob is encrypted twice on the wire.
//
// The manifest carries the raw 32-byte file key (unwrapped by the primary)
// so the linked device can decrypt with AttachmentCrypto after reassembly.
// The manifest itself only ever travels inside the paired channel's sealed
// envelope — it is never exposed to the relay.
//
// Resume: chunks are indexed; the receiver tracks which indexes arrived and
// re-requests from the first missing index (`LinkedBlobRequest.fromIndex`),
// so an interrupted transfer continues instead of restarting.
//
// Security notes (also documented at the call sites):
// - The paired channel key is static (Keychain) — the channel has NO
//   forward secrecy. A compromised channel key exposes past and future
//   paired traffic, including these blobs and file keys.
// - Unpairing wipes channel keys but cannot remote-wipe blobs already
//   synced to the other device.

import CryptoKit
import Foundation

/// What kind of blob a transfer carries.
public enum LinkedBlobKind: String, Codable, Sendable, Hashable {
    case attachment
    case voiceNote
}

/// Primary → linked: announces a blob available for download. Small enough
/// to fan out eagerly; the (large) chunks only flow after an explicit
/// `LinkedBlobRequest`.
public struct LinkedBlobManifest: Codable, Sendable, Hashable {
    /// One transfer per attachment: the transfer ID IS the attachment ID.
    /// Re-offers reuse the ID, so resume and dedupe work naturally.
    public var transferID: UUID
    public var attachmentID: UUID
    public var messageID: UUID
    public var conversationID: UUID
    public var kind: LinkedBlobKind
    public var filename: String
    public var mimeType: String
    /// Ciphertext byte count (AttachmentCrypto framing).
    public var byteCount: Int64
    public var chunkSize: Int
    public var chunkCount: Int
    /// SHA-256 over the ciphertext blob; the receiver verifies after
    /// reassembly, before decrypting.
    public var blobSHA256: Data
    /// Relay blob locator, so the primary can re-fetch the ciphertext from
    /// the relay when its staged copy was evicted (e.g. after a restart).
    /// Opaque to the relay; ignored by the linked device.
    public var relayLocator: String
    /// Raw 32-byte file key, unwrapped by the primary. Sealed inside the
    /// paired channel envelope — never sent in the clear.
    public var fileKey: Data
    /// JPEG thumbnail (attachments only).
    public var thumbnail: Data?
    // Voice-note extras.
    public var voiceDuration: TimeInterval?
    public var voiceLevels: [Float]?
    public var transcript: String?
    public var offeredAt: Date

    public init(
        transferID: UUID = UUID(),
        attachmentID: UUID,
        messageID: UUID,
        conversationID: UUID,
        kind: LinkedBlobKind,
        filename: String,
        mimeType: String,
        byteCount: Int64,
        chunkSize: Int,
        chunkCount: Int,
        blobSHA256: Data,
        relayLocator: String,
        fileKey: Data,
        thumbnail: Data? = nil,
        voiceDuration: TimeInterval? = nil,
        voiceLevels: [Float]? = nil,
        transcript: String? = nil,
        offeredAt: Date = Date()
    ) {
        self.transferID = transferID
        self.attachmentID = attachmentID
        self.messageID = messageID
        self.conversationID = conversationID
        self.kind = kind
        self.filename = filename
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.chunkSize = chunkSize
        self.chunkCount = chunkCount
        self.blobSHA256 = blobSHA256
        self.relayLocator = relayLocator
        self.fileKey = fileKey
        self.thumbnail = thumbnail
        self.voiceDuration = voiceDuration
        self.voiceLevels = voiceLevels
        self.transcript = transcript
        self.offeredAt = offeredAt
    }
}

/// Primary → linked: one indexed slice of the ciphertext blob.
public struct LinkedBlobChunk: Codable, Sendable, Hashable {
    public var transferID: UUID
    public var index: Int
    public var bytes: Data

    public init(transferID: UUID, index: Int, bytes: Data) {
        self.transferID = transferID
        self.index = index
        self.bytes = bytes
    }
}

/// Linked → primary: "send me this blob", optionally resuming. `fromIndex`
/// is the first chunk index the receiver still needs; the primary streams
/// from there to the end.
public struct LinkedBlobRequest: Codable, Sendable, Hashable {
    public var transferID: UUID
    public var attachmentID: UUID
    public var messageID: UUID
    public var conversationID: UUID
    public var fromIndex: Int

    public init(transferID: UUID, attachmentID: UUID, messageID: UUID, conversationID: UUID, fromIndex: Int) {
        self.transferID = transferID
        self.attachmentID = attachmentID
        self.messageID = messageID
        self.conversationID = conversationID
        self.fromIndex = fromIndex
    }
}

/// Primary → linked: the blob cannot be served (evicted, relay copy gone,
/// file key unavailable).
public struct LinkedBlobFailure: Codable, Sendable, Hashable {
    public var transferID: UUID
    public var attachmentID: UUID?
    public var reason: String

    public init(transferID: UUID, attachmentID: UUID? = nil, reason: String) {
        self.transferID = transferID
        self.attachmentID = attachmentID
        self.reason = reason
    }
}

public enum BlobTransferError: Error, Sendable, Equatable {
    /// Reassembled bytes don't match the manifest hash — the transfer is
    /// corrupt and must be discarded, never decrypted.
    case hashMismatch
    case chunkIndexOutOfRange(Int)
    case incompleteTransfer(missing: Int)
}

/// Pure chunking math + hashing shared by both sides.
public enum BlobTransfer {
    /// Ciphertext bytes per chunk frame. Small enough that the JSON +
    /// base64 + paired-channel seal stays far under the relay's frame
    /// limit, large enough that a 100 MiB blob is ~3.2k frames.
    public static let chunkSize = 32 * 1024

    /// Hard cap per blob, mirroring AttachmentCrypto.maxFileBytes: AES-GCM
    /// needs the whole plaintext in memory at decrypt time.
    public static let maxBlobBytes: Int64 = 100 * 1024 * 1024

    public static func chunkCount(byteCount: Int64, chunkSize: Int = BlobTransfer.chunkSize) -> Int {
        max(1, Int((byteCount + Int64(chunkSize) - 1) / Int64(chunkSize)))
    }

    /// Byte range of one chunk within the blob.
    public static func range(forChunk index: Int, byteCount: Int64, chunkSize: Int = BlobTransfer.chunkSize) -> Range<Int> {
        let start = index * chunkSize
        let end = min(start + chunkSize, Int(byteCount))
        return start..<end
    }

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

/// Linked-side reassembly state machine. Chunks may arrive out of order or
/// duplicated (relay redelivery); ingestion dedupes by index. Completion is
/// declared only after `verifiedData()` confirms the SHA-256.
public actor InboundBlobTransfer: Sendable {
    public let manifest: LinkedBlobManifest
    private var chunks: [Int: Data] = [:]

    public init(manifest: LinkedBlobManifest, receivedIndexes: [Int] = [], receivedChunks: [Int: Data] = [:]) {
        self.manifest = manifest
        // Restored progress only records *which* indexes arrived; the bytes
        // themselves are re-fetched via a resume request.
        for index in receivedIndexes where chunks[index] == nil {
            chunks[index] = Data()
        }
        for (index, bytes) in receivedChunks {
            chunks[index] = bytes
        }
    }

    /// Slots with bytes actually received (restored placeholders excluded).
    public var receivedCount: Int {
        (0..<manifest.chunkCount).filter { hasBytes(at: $0) }.count
    }
    public var chunkCount: Int { manifest.chunkCount }

    /// A slot counts as received only once its bytes arrived. Restored
    /// progress (from a previous launch) stores indexes with empty
    /// placeholders — those resume as missing, never as complete.
    private func hasBytes(at index: Int) -> Bool {
        guard let bytes = chunks[index] else { return false }
        return !bytes.isEmpty
    }

    /// 0...1 progress over the expected chunk count.
    public var progress: Double {
        guard manifest.chunkCount > 0 else { return 1 }
        let have = (0..<manifest.chunkCount).filter { hasBytes(at: $0) }.count
        return Double(have) / Double(manifest.chunkCount)
    }

    /// First missing chunk index (resume offset), or chunkCount when done.
    public var nextMissingIndex: Int {
        for i in 0..<manifest.chunkCount where !hasBytes(at: i) { return i }
        return manifest.chunkCount
    }

    public var isComplete: Bool {
        (0..<manifest.chunkCount).allSatisfy { hasBytes(at: $0) }
    }

    /// Indexes received so far (for persisting resume state).
    public var receivedIndexes: [Int] { Array(chunks.keys) }

    /// Ingests one chunk. Returns the new progress, or nil when the chunk
    /// is a duplicate / out of range / for another transfer.
    @discardableResult
    public func ingest(_ chunk: LinkedBlobChunk) -> Double? {
        guard chunk.transferID == manifest.transferID,
              chunk.index >= 0, chunk.index < manifest.chunkCount,
              !hasBytes(at: chunk.index)
        else { return nil }
        chunks[chunk.index] = chunk.bytes
        return progress
    }

    /// Reassembles and hash-verifies the blob. Throws on mismatch or when
    /// chunks are still missing — never returns corrupt bytes.
    public func verifiedData() throws -> Data {
        guard isComplete else {
            throw BlobTransferError.incompleteTransfer(missing: manifest.chunkCount - receivedCount)
        }
        var data = Data()
        data.reserveCapacity(Int(manifest.byteCount))
        for i in 0..<manifest.chunkCount {
            guard let bytes = chunks[i], !bytes.isEmpty else {
                throw BlobTransferError.incompleteTransfer(missing: manifest.chunkCount - receivedCount)
            }
            data.append(bytes)
        }
        guard BlobTransfer.sha256(data) == manifest.blobSHA256 else {
            throw BlobTransferError.hashMismatch
        }
        return data
    }
}
