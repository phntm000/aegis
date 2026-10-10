import Foundation

/// Well-known app directories for encrypted attachment storage.
enum AegisPaths {
    /// Decrypted attachments live here (protected by Data Protection + app lock).
    static var attachmentsDirectory: URL {
        let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Attachments", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Ciphertext staged for upload.
    static var stagingDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("AegisStaging", isDirectory: true)
    }

    static func ensureStaging() -> URL {
        let url = stagingDirectory
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Recently-uploaded ciphertext blobs, kept for re-transmission when a
    /// downloader's chunks never arrive (LAN transports don't retain
    /// frames). Bounded by the uploader (see AegisCore.sentBlobCache).
    static var sentBlobDirectory: URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("AegisSentBlobs", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
