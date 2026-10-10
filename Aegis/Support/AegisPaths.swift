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
}
