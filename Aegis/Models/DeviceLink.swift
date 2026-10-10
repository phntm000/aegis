import Foundation

// MARK: - Linked Devices
//
// Multi-device via the paired-device relay model.
//
// A linked (secondary) device holds no identity keys of its own. Instead it
// pairs with the primary device over an E2EE paired channel (X25519
// ephemeral-ephemeral, QR + SAS verification) and relays all traffic through
// the primary: outbound messages go linked→primary→contact, inbound messages
// are forwarded primary→linked. The contact-facing cryptography is untouched,
// so E2EE guarantees are preserved end to end.
//
// Honest limits (documented, not hidden):
// - The linked device needs the primary reachable (same LAN or via the blind
//   relay's sealed inbox). This mirrors the pre-multi-device WhatsApp Web
//   model; true independent multi-device (per-device sender keys) would need
//   a wire-format revision for device-addressed ratchet sessions.
// - Pairing transfers contacts, conversations, and recent history so the
//   linked device is immediately useful.

/// A device in the link set. The primary stores one per linked device; a
/// linked device stores exactly one (its primary).
struct DeviceInfo: Codable, Sendable, Hashable, Identifiable {
    var id: UUID { deviceID }
    let deviceID: UUID
    var deviceName: String
    var deviceModel: String?
    var pairedAt: Date
    var lastSeen: Date
}

/// Pairing handshake messages, exchanged on the pairing mailbox (derived from
/// the QR payload). The ephemeral public keys are public by design; the SAS
/// (from the DH shared secret) is what the user verifies.
enum PairingMessageKind: String, Codable, Sendable {
    /// Linked → primary: "I scanned your QR". Carries the linked device's
    /// ephemeral public key, device ID, and human-readable name.
    case hello
    /// Primary → linked: provisioning bundle, AES-GCM encrypted with the
    /// pairing key. The user must confirm the SAS match BEFORE the primary
    /// sends this (enforced in the UI flow, not the wire).
    case provisioning
    /// Either → other: pairing aborted by the user.
    case abort
}

struct PairingMessage: Codable, Sendable {
    var kind: PairingMessageKind
    /// 16-byte pairing ID (hex) — lets the primary match concurrent attempts.
    var pairingIDHex: String
    /// 32-byte ephemeral public key (hello only).
    var ephemeralPublicKey: Data?
    var deviceID: UUID?
    var deviceName: String?
    var deviceModel: String?
    /// AES-GCM sealed provisioning bundle (provisioning only).
    var sealedBundle: Data?
}

/// Everything a fresh linked device needs to become useful, encrypted with
/// the pairing key and sent once after SAS confirmation.
struct ProvisioningBundle: Codable, Sendable {
    var primaryDeviceID: UUID
    var primaryDeviceName: String
    var displayName: String
    var contacts: [LinkedContact]
    var conversations: [LinkedConversation]
    /// conversationID → up to N recent messages (bounded at send time).
    var recentMessages: [String: [LinkedMessage]]
    /// The linked device's own record (so both sides agree on IDs).
    var assignedDevice: DeviceInfo
}

/// Public contact fields safe to sync (no key material beyond what's already
/// public to the account owner).
struct LinkedContact: Codable, Sendable, Hashable {
    var id: UUID
    var displayName: String
    var fingerprintHex: String
}

/// Conversation metadata for the linked device's list.
struct LinkedConversation: Codable, Sendable, Hashable {
    var id: UUID
    var title: String
    var kind: String
    var lastMessagePreview: String?
    var lastMessageAt: Date?
    var unreadCount: Int
}

/// A message snapshot for sync/provisioning.
struct LinkedMessage: Codable, Sendable, Hashable {
    var id: UUID
    var conversationID: UUID
    var body: String?
    var replyToID: UUID?
    var isFromMe: Bool
    /// Display name of the sender (for group messages on the linked device).
    var senderName: String?
    var status: String
    var sentAt: Date
    var expiresAt: Date?
}

/// Sync traffic on the long-term paired channel (AES-GCM with the paired key).
enum DeviceSyncKind: String, Codable, Sendable {
    /// Linked → primary: "send this for me".
    case sendMessage
    /// Primary → linked: a message arrived (or was sent) — upsert it.
    case incomingMessage
    /// Primary → linked: delivery/read status changed.
    case messageStatus
    /// Either → other: "forget me" (unpair + wipe channel keys).
    case unpair
    /// Primary → linked: heartbeat (keeps lastSeen fresh).
    case heartbeat
    /// Internal: the secondary applied a provisioning bundle (delivered via
    /// the sync event stream so the app layer can persist it).
    case provisioningApplied
}

struct DeviceSyncMessage: Codable, Sendable {
    var kind: DeviceSyncKind
    var senderDeviceID: UUID
    /// JSON-encoded kind-specific body.
    var body: Data
}

/// Body for `.sendMessage` (linked → primary).
struct LinkedSendRequest: Codable, Sendable {
    var conversationID: UUID
    var body: String
    var replyToID: UUID?
    /// Message ID chosen by the linked device so the ack can match it.
    var messageID: UUID
}

/// Body for `.incomingMessage` / provisioning (primary → linked).
struct LinkedIncomingMessage: Codable, Sendable {
    var message: LinkedMessage
    var conversation: LinkedConversation?
}

/// Body for `.messageStatus`.
struct LinkedMessageStatus: Codable, Sendable {
    var messageID: UUID
    var conversationID: UUID
    var status: String
}

/// SAS words for pairing verification (4 words from a fixed list, derived
/// from the pairing shared secret — both sides must display the same words).
enum PairingSAS {
    static let wordlist = [
        "amber", "brave", "coral", "drift", "ember", "frost", "glade", "harbor",
        "ivory", "juniper", "kelp", "lumen", "meadow", "north", "onyx", "prairie",
        "quartz", "ridge", "sable", "tundra", "umber", "vale", "willow", "xenon",
        "yarrow", "zephyr", "acorn", "birch", "clover", "dune", "elm", "fern",
        "grove", "heath", "iris", "jade", "knoll", "lark", "moss", "nectar",
        "orchid", "pine", "quill", "reed", "spruce", "thistle", "ulva", "vetch",
        "wren", "xylem", "yew", "zinc", "atlas", "beacon", "comet", "delta",
        "echo", "flint", "garnet", "halo", "indigo", "jolt", "karma", "lotus",
        "magma", "nomad", "opal", "pioneer", "quasar", "raven", "solar", "tempo"
    ]

    /// Four words from the first 8 bytes of the secret (11 bits per word).
    static func words(for secret: Data) -> [String] {
        var bytes = Array(secret.prefix(8))
        while bytes.count < 8 { bytes.append(0) }
        var words: [String] = []
        var acc: UInt64 = 0
        var bits = 0
        for b in bytes {
            acc = (acc << 8) | UInt64(b)
            bits += 8
            while bits >= 11 && words.count < 4 {
                bits -= 11
                let idx = Int((acc >> bits) & 0x7FF) % wordlist.count
                words.append(wordlist[idx])
            }
        }
        while words.count < 4 { words.append(wordlist[0]) }
        return words
    }
}
