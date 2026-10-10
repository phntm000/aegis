import Foundation

/// A person the user communicates with, keyed by their identity key.
/// Contacts are created explicitly (QR / invite code) — there is no discovery,
/// no directory, no phone-number lookup. That is a privacy feature.
struct Contact: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    var displayName: String
    /// The contact's long-term identity public key. This is the trust anchor.
    var identityKey: Data
    var verification: VerificationState
    var isBlocked: Bool
    var lastSeenAt: Date?
    let addedAt: Date
    var notes: String?

    init(
        id: UUID = UUID(),
        displayName: String,
        identityKey: Data,
        verification: VerificationState = .unverified,
        isBlocked: Bool = false,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date(),
        notes: String? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.identityKey = identityKey
        self.verification = verification
        self.isBlocked = isBlocked
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
        self.notes = notes
    }
}

extension Contact {
    /// Initials for the avatar fallback (max 2 characters).
    var initials: String {
        let parts = displayName.split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }
        return String(letters).uppercased()
    }

    /// Deterministic avatar hue derived from the identity key, so a contact's
    /// color is stable across devices without storing anything extra.
    var avatarHue: Double {
        guard let first = identityKey.first else { return 0.6 }
        return Double(first) / 255.0
    }
}
