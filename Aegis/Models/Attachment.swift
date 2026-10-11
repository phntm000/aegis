import Foundation

/// Metadata for an encrypted file attachment.
///
/// The file bytes are encrypted client-side with a fresh random key before
/// upload; the relay stores only ciphertext. The wrapped key travels inside
/// the message envelope, so only conversation members can decrypt.
struct Attachment: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    let filename: String
    let mimeType: String
    let byteCount: Int64
    /// Key wrapped for the conversation session (opaque to transport/store).
    let wrappedKey: Data?
    /// Relay blob locator for download; nil until upload completes.
    let remoteLocator: String?
    /// Relative path inside the app's encrypted attachments directory.
    let localRelativePath: String?
    let thumbnailData: Data?

    init(
        id: UUID = UUID(),
        filename: String,
        mimeType: String,
        byteCount: Int64,
        wrappedKey: Data? = nil,
        remoteLocator: String? = nil,
        localRelativePath: String? = nil,
        thumbnailData: Data? = nil
    ) {
        self.id = id
        self.filename = filename
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.wrappedKey = wrappedKey
        self.remoteLocator = remoteLocator
        self.localRelativePath = localRelativePath
        self.thumbnailData = thumbnailData
    }
}

extension Attachment {
    var isImage: Bool { mimeType.hasPrefix("image/") }
    var isVideo: Bool { mimeType.hasPrefix("video/") }
    var isAudio: Bool { mimeType.hasPrefix("audio/") }
    var sizeLabel: String { Formatters.bytes(byteCount) }
}

/// A voice note: encrypted audio plus a precomputed waveform so playback
/// renders instantly without decoding the audio first.
struct VoiceNote: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    let duration: TimeInterval
    /// Normalized 0...1 amplitude buckets for the waveform view.
    let levels: [Float]
    let wrappedKey: Data?
    let remoteLocator: String?
    let localRelativePath: String?
    /// On-device transcript, when one was produced. Synced to linked
    /// devices alongside the audio blob; nil when unavailable.
    let transcript: String?

    init(
        id: UUID = UUID(),
        duration: TimeInterval,
        levels: [Float],
        wrappedKey: Data? = nil,
        remoteLocator: String? = nil,
        localRelativePath: String? = nil,
        transcript: String? = nil
    ) {
        self.id = id
        self.duration = duration
        self.levels = levels
        self.wrappedKey = wrappedKey
        self.remoteLocator = remoteLocator
        self.localRelativePath = localRelativePath
        self.transcript = transcript
    }
}
