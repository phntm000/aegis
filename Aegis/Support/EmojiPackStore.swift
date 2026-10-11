import Foundation
import UIKit

/// Local-only storage for custom emoji packs. Packs never sync over the
/// wire and never leave the device; reactions referencing a pack use the
/// key "pack:<packID>:<emojiID>" and render as images only when the pack
/// exists locally. A missing pack renders as a placeholder glyph, never
/// as attacker-controlled text.
actor EmojiPackStore {
    static let shared = EmojiPackStore()

    private let file: URL
    private var packs: [CustomEmojiPack] = []
    private var imageCache: [String: UIImage] = [:]

    init() {
        let base = (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )) ?? FileManager.default.temporaryDirectory
        file = base.appendingPathComponent("custom-emoji-packs.json")
        if let data = try? Data(contentsOf: file),
           let decoded = try? JSONDecoder().decode([CustomEmojiPack].self, from: data) {
            packs = decoded
        }
    }

    // MARK: - Reads

    func allPacks() -> [CustomEmojiPack] { packs }

    func pack(id: UUID) -> CustomEmojiPack? {
        packs.first { $0.id == id }
    }

    /// Decoded image for a custom-emoji reaction key, or nil when the
    /// pack/emoji is unknown or the data isn't a valid image.
    func image(forReactionKey key: String) -> UIImage? {
        guard let (packID, emojiID) = ReactionKey.parseCustomEmoji(key) else { return nil }
        let cacheKey = "\(packID.uuidString):\(emojiID)"
        if let cached = imageCache[cacheKey] { return cached }
        guard let emoji = packs.first(where: { $0.id == packID })?
            .emojis.first(where: { $0.id == emojiID }),
            let image = UIImage(data: emoji.imageData)
        else { return nil }
        imageCache[cacheKey] = image
        return image
    }

    // MARK: - Writes

    func createPack(name: String) throws -> CustomEmojiPack {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw EmojiPackError.emptyName
        }
        let pack = CustomEmojiPack(name: String(trimmed.prefix(40)))
        packs.append(pack)
        try persist()
        return pack
    }

    func renamePack(id: UUID, name: String) throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw EmojiPackError.emptyName }
        guard let idx = packs.firstIndex(where: { $0.id == id }) else {
            throw EmojiPackError.notFound
        }
        packs[idx].name = String(trimmed.prefix(40))
        try persist()
    }

    func deletePack(id: UUID) throws {
        packs.removeAll { $0.id == id }
        imageCache = imageCache.filter { !$0.key.hasPrefix(id.uuidString) }
        try persist()
    }

    /// Adds an emoji to a pack. The image is normalized to a ≤128px PNG so
    /// packs stay small and render consistently in reaction chips.
    func addEmoji(packID: UUID, name: String, imageData: Data) throws -> CustomEmoji {
        guard let idx = packs.firstIndex(where: { $0.id == packID }) else {
            throw EmojiPackError.notFound
        }
        guard let normalized = Self.normalize(imageData: imageData) else {
            throw EmojiPackError.invalidImage
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let emojiID = trimmed.isEmpty
            ? "emoji-\(packs[idx].emojis.count + 1)"
            : String(trimmed.lowercased().prefix(24))
                .replacingOccurrences(of: "[^a-z0-9_]", with: "", options: .regularExpression)
        guard !emojiID.isEmpty else { throw EmojiPackError.emptyName }
        guard !packs[idx].emojis.contains(where: { $0.id == emojiID }) else {
            throw EmojiPackError.duplicateName
        }
        let emoji = CustomEmoji(id: emojiID, imageData: normalized)
        packs[idx].emojis.append(emoji)
        try persist()
        return emoji
    }

    func deleteEmoji(packID: UUID, emojiID: String) throws {
        guard let idx = packs.firstIndex(where: { $0.id == packID }) else {
            throw EmojiPackError.notFound
        }
        packs[idx].emojis.removeAll { $0.id == emojiID }
        imageCache.removeValue(forKey: "\(packID.uuidString):\(emojiID)")
        try persist()
    }

    // MARK: - Private

    private func persist() throws {
        let data = try JSONEncoder().encode(packs)
        try data.write(to: file, options: [.atomic, .completeFileProtection])
    }

    /// Downscales to ≤128px and re-encodes as PNG. Returns nil when the
    /// input isn't a decodable image.
    private static func normalize(imageData: Data) -> Data? {
        guard let image = UIImage(data: imageData) else { return nil }
        let maxSide: CGFloat = 128
        let scale = min(1, maxSide / max(image.size.width, image.size.height))
        let target = CGSize(
            width: max(1, image.size.width * scale),
            height: max(1, image.size.height * scale)
        )
        let renderer = UIGraphicsImageRenderer(size: target)
        let resized = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: target))
        }
        return resized.pngData()
    }
}

enum EmojiPackError: LocalizedError, Sendable {
    case emptyName
    case notFound
    case duplicateName
    case invalidImage

    var errorDescription: String? {
        switch self {
        case .emptyName: return "Give the pack (or emoji) a name first."
        case .notFound: return "That emoji pack no longer exists."
        case .duplicateName: return "An emoji with that name already exists in this pack."
        case .invalidImage: return "That file isn't a readable image."
        }
    }
}
