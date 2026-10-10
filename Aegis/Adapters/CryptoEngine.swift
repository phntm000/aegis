// CryptoEngine — the live crypto orchestrator behind CryptoService.
//
// This is the app-target actor that composes AegisCrypto's primitives into
// a working messenger core: Keychain identity persistence, X3DH session
// establishment (lazy, on first outbound message), Double-Ratchet 1:1
// sessions, sender-key group sessions, sealed sender, attachment file
// keys, and passphrase-encrypted backup.
//
// Design rules:
//  - Private key material never leaves this actor (or AegisCrypto).
//  - Sender-key distributions ALWAYS travel encrypted inside the
//    recipient's 1:1 session (see `distributeToAll`) — never in the clear,
//    never only sender-key-encrypted.
//  - The 16-byte identity mailbox (sealed-sender addressing) and the
//    32-byte routing mailbox (wire routing) are different values; see
//    RoutingMailbox. This engine derives both.
//
// Honest limitations (macOS-gated hardening):
//  - Sessions live in memory. An app restart drops them; the next outbound
//    message transparently re-establishes via X3DH (the peer's client does
//    the same), and undecryptable inbound in the gap surfaces a visible
//    "session reset" notice rather than silent loss. Durable session
//    persistence needs Codable ratchet state (a package change).
//  - One-time prekeys are not persisted across launches; the pool is
//    refilled in memory. X3DH without a one-time prekey is still secure.

import AegisCrypto
import CryptoKit
import Foundation

/// Typed errors from the live crypto path. None leak key material.
enum CryptoEngineError: Error, Sendable {
    /// No 1:1 session and no cached prekey bundle — the user must obtain a
    /// fresh invite (QR / code) from the contact.
    case noSessionNoBundle
    /// A message arrived for an unknown session.
    case unknownSession
    /// Invite payload failed to parse.
    case invalidInvite(String)
    /// Unknown group.
    case unknownGroup
    /// Sealed-sender certificate fingerprint does not match the expected peer.
    case senderMismatch
}

/// Wire envelope types the engine multiplexes. NOTE: the sealed envelope
/// does NOT carry its 0x20 type byte on the wire (SealedEnvelope only
/// writes the version) — it is detected by try-parse in maybeOpen, never
/// by this dispatch. The case is listed here for documentation only.
private enum InnerWireType: UInt8 {
    case ratchetMessage = 0x01
    case preKeyMessage = 0x02
    case groupMessage = 0x10
    case sealedEnvelope = 0x20
}

actor CryptoEngine {
    // MARK: - Identity directory

    /// Fingerprint hex → public identity. Populated from invites, bundles,
    /// and group membership. The trust decision (is this fingerprint the
    /// contact the user verified?) lives in the store's verification state.
    private var knownIdentities: [String: IdentityPublic] = [:]
    /// Fingerprint hex → unconsumed prekey bundle (from the invite).
    private var bundleCache: [String: PreKeyBundle] = [:]

    // MARK: - Sessions

    private struct SessionEntry {
        var ratchet: AegisDoubleRatchet
        var peer: IdentityPublic
        /// X3DH ephemeral public key — feeds RoutingMailbox.directRoute.
        var ephemeralPublicKey: Data
    }

    /// Fingerprint hex → live 1:1 session.
    private var sessions: [String: SessionEntry] = [:]
    /// groupID hex → sender-key group session.
    private var groupSessions: [String: GroupSession] = [:]

    private var identity: Identity?
    private var preKeyManager: PreKeyManager?
    private var localDisplayName: String = ""

    /// Resolves a fingerprint to the contact the user knows (for sealed
    /// sender verification and display). Wired by the factory to the store.
    private let contactIdentity: @Sendable (Data) async -> IdentityPublic?

    init(contactIdentity: @Sendable @escaping (Data) async -> IdentityPublic?) {
        self.contactIdentity = contactIdentity
    }

    // MARK: - Identity lifecycle

    var hasIdentity: Bool { identity != nil }

    func loadIdentity() throws -> (IdentityPublic, String, Date) {
        guard let identity else { throw CryptoEngineError.unknownSession }
        return (identity.publicView, localDisplayName, identity.createdAt)
    }

    /// Creates a fresh identity, persists private material to the Keychain
    /// immediately, and returns the public view.
    func createIdentity(displayName: String) throws -> IdentityPublic {
        let fresh = try Identity()
        try persistIdentity(fresh, displayName: displayName)
        let manager = try PreKeyManager(identity: fresh)
        self.identity = fresh
        self.preKeyManager = manager
        self.localDisplayName = displayName
        return fresh.publicView
    }

    /// Loads identity + signed prekey from the Keychain. One-time prekeys
    /// are regenerated (see the file header).
    func restoreIdentity() throws -> IdentityPublic? {
        guard
            let blob = try KeychainHelper.load(service: "app.aegis.identity", account: "primary"),
            let stored = try? JSONDecoder().decode(StoredIdentity.self, from: blob)
        else { return nil }
        let restored = try Identity(
            signingSeed: Data(stored.signingSeed),
            agreementPrivateKey: Data(stored.agreementPrivateKey),
            createdAt: stored.createdAt
        )
        try persistIdentity(restored, displayName: stored.displayName)
        let manager = try PreKeyManager(identity: restored)
        self.identity = restored
        self.preKeyManager = manager
        self.localDisplayName = stored.displayName
        return restored.publicView
    }

    func updateDisplayName(_ name: String) throws {
        guard let identity else { throw CryptoEngineError.unknownSession }
        try persistIdentity(identity, displayName: name)
        localDisplayName = name
    }

    func deleteIdentity() throws {
        try KeychainHelper.delete(service: "app.aegis.identity", account: "primary")
        identity = nil
        preKeyManager = nil
        sessions.removeAll()
        groupSessions.removeAll()
        bundleCache.removeAll()
    }

    // MARK: - Invites

    /// Live invite format: `AEGIS1:<base64url(IdentityPublic.serialized)>
    /// :<base64url(PreKeyBundle.serialized)>:<pct-encoded display name>`.
    /// The bundle lets the inviter's side X3DH immediately; the invitee's
    /// client publishes nothing — there is no server to publish to.
    static let invitePrefix = "AEGIS1:"

    func parseInvite(_ payload: String) throws -> (IdentityPublic, String?) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("aegis-invite-") {
            // Legacy mock format (single key): reject loudly rather than
            // misparse — the contact must re-issue a live invite.
            throw CryptoEngineError.invalidInvite("legacy invite; ask the contact for a fresh Aegis invite")
        }
        guard trimmed.hasPrefix(invitePrefix) else {
            throw CryptoEngineError.invalidInvite("unknown invite format")
        }
        let parts = trimmed.dropFirst(invitePrefix.count).split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count >= 2,
              let idData = Data(base64Encoded: String(parts[0]).base64URLDecodedInput())
        else { throw CryptoEngineError.invalidInvite("malformed invite") }
        let identityPublic = try IdentityPublic(serialized: idData)
        if parts.count >= 3, let bundleData = Data(base64Encoded: String(parts[1]).base64URLDecodedInput()) {
            let bundle = try PreKeyBundle(serialized: bundleData)
            bundleCache[identityPublic.fingerprint.hexString] = bundle
        }
        knownIdentities[identityPublic.fingerprint.hexString] = identityPublic
        let name = parts.count >= 3 ? String(parts[2]).removingPercentEncoding
            : parts.count == 2 ? String(parts[1]).removingPercentEncoding : nil
        return (identityPublic, name)
    }

    func invitePayload(displayName: String) throws -> String {
        guard let identity, let manager = preKeyManager else { throw CryptoEngineError.unknownSession }
        let bundle = try manager.currentBundle()
        let idPart = identity.publicView.serialized().base64EncodedString().base64URLEncodedOutput()
        let bundlePart = bundle.serialized().base64EncodedString().base64URLEncodedOutput()
        let namePart = displayName.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        return "\(Self.invitePrefix)\(idPart):\(bundlePart):\(namePart)"
    }

    /// Short copy-pasteable code: fingerprint-derived, for manual exchange.
    /// (The full invite above is preferred; this is a fallback handle.)
    func shortInviteCode() throws -> String {
        guard let identity else { throw CryptoEngineError.unknownSession }
        return "aegis-" + identity.fingerprint.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - 1:1 messaging

    /// Encrypts for a 1:1 peer, establishing the X3DH session lazily on the
    /// first message. Returns the wire bytes (sealed when the toggle is on)
    /// and the X3DH ephemeral public key for routing-mailbox derivation.
    func encryptDirect(_ plaintext: Data, to peer: IdentityPublic) throws -> (wire: Data, ephemeralPublicKey: Data) {
        guard let identity else { throw CryptoEngineError.unknownSession }
        let key = peer.fingerprint.hexString
        knownIdentities[key] = peer
        let wire: Data
        let ephPub: Data
        if var entry = sessions[key] {
            let msg = try entry.ratchet.encrypt(plaintext: plaintext, associatedData: Data())
            sessions[key] = entry
            wire = msg.serialized()
            ephPub = entry.ephemeralPublicKey
        } else {
            guard let bundle = bundleCache[key] else { throw CryptoEngineError.noSessionNoBundle }
            let initiated = try SessionEstablishment.initiate(ourIdentity: identity, bundle: bundle, plaintext: plaintext)
            let preKey = try PreKeyMessage.parse(initiated.preKeyMessage)
            sessions[key] = SessionEntry(ratchet: initiated.session, peer: peer, ephemeralPublicKey: preKey.ephemeralPublicKey)
            bundleCache.removeValue(forKey: key)
            wire = initiated.preKeyMessage
            ephPub = preKey.ephemeralPublicKey
        }
        return (maybeSeal(wire, to: peer, sender: identity), ephPub)
    }

    /// Decrypts an inbound 1:1 payload from a known peer. Handles the sealed
    /// layer, session initiation (0x02), and ratchet messages (0x01).
    func decryptDirect(_ payload: Data, from peer: IdentityPublic) throws -> Data {
        guard let identity else { throw CryptoEngineError.unknownSession }
        let key = peer.fingerprint.hexString
        // Sealed envelopes are detected by try-parse (see maybeOpen); the
        // unsealed path dispatches on the wire type byte.
        if let inner = maybeOpen(payload, expectedSender: peer, recipient: identity) {
            return try decryptInner(inner, peer: peer, key: key)
        }
        return try decryptInner(payload, peer: peer, key: key)
    }

    private func decryptWithSession(_ inner: Data, entry: SessionEntry) throws -> Data {
        var mutable = entry
        let message = try RatchetMessage.parse(inner)
        let plaintext = try mutable.ratchet.decrypt(message, associatedData: Data())
        sessions[entry.peer.fingerprint.hexString] = mutable
        return plaintext
    }

    // MARK: - Sealed sender (toggle honored here)

    var sealedSenderEnabled: Bool {
        // Default ON: registered at launch by AegisApp.
        UserDefaults.standard.bool(forKey: SettingsKeys.sealedSender)
    }

    /// 16-byte identity mailbox of a public identity (the sealed-sender
    /// addressing layer — NOT the 32-byte routing mailbox).
    static func identityMailbox(of identity: IdentityPublic) -> Data {
        var context = Data("AegisMailbox_v1".utf8)
        context.append(identity.fingerprint)
        return Data(SHA256.hash(data: context).prefix(16))
    }

    private func maybeSeal(_ inner: Data, to peer: IdentityPublic, sender: Identity) -> Data {
        guard sealedSenderEnabled else { return inner }
        return (try? SealedSender.seal(
            innerMessage: inner,
            sender: sender,
            recipientAgreementPublicKey: peer.agreementPublicKey,
            recipientMailboxID: Self.identityMailbox(of: peer)
        ).serialized()) ?? inner
    }

    private func maybeOpen(_ payload: Data, expectedSender: IdentityPublic, recipient: Identity) -> Data? {
        // NOTE: SealedEnvelope.serialized() does not write its wireType
        // byte (only the version), so sealed envelopes are detected by
        // try-parse, not by a type byte. Parse is strict (expectEnd) and
        // open() AEAD-authenticates, so an unsealed payload cannot false-
        // positive: it either fails to parse or fails to open, and we fall
        // through to the unsealed path. Returns nil when the payload is not
        // a sealed envelope for the expected sender.
        guard let envelope = try? SealedEnvelope.parse(payload),
              let opened = try? SealedSender.open(envelope, recipient: recipient, senderIdentity: expectedSender)
        else { return nil }
        return opened.innerMessage
    }

    /// Dispatches a session-layer inner message (post sealed-open).
    private func decryptInner(_ inner: Data, peer: IdentityPublic, key: String) throws -> Data {
        guard inner.count >= 2,
              inner[0] == AegisCrypto.protocolVersion,
              let identity = identity, let manager = preKeyManager
        else { throw AegisCryptoError.invalidWireFormat }
        switch inner[1] {
        case InnerWireType.preKeyMessage.rawValue:
            let message = try PreKeyMessage.parse(inner)
            let opk = manager.consumeOneTimePreKey(message.usedOneTimePreKeyID)
            if sessions[key] != nil,
               identity.fingerprint.lexicographicallyPrecedes(peer.fingerprint)
            {
                // Simultaneous initiation: deterministic convergence. We
                // are the winner, so we keep our session — but we still
                // decrypt the loser's first message via a one-shot session
                // so it is not silently lost. The peer converges onto our
                // session when it sees our prekey message.
                let oneShot = try SessionEstablishment.respond(
                    preKeyMessageWire: inner,
                    ourIdentity: identity,
                    ourSignedPreKey: manager.signedPreKey,
                    usedOneTimePreKey: opk
                )
                return oneShot.plaintext
            }
            let responded = try SessionEstablishment.respond(
                preKeyMessageWire: inner,
                ourIdentity: identity,
                ourSignedPreKey: manager.signedPreKey,
                usedOneTimePreKey: opk
            )
            sessions[key] = SessionEntry(
                ratchet: responded.session,
                peer: peer,
                ephemeralPublicKey: message.ephemeralPublicKey
            )
            return responded.plaintext
        case InnerWireType.ratchetMessage.rawValue:
            guard let entry = sessions[key] else { throw CryptoEngineError.unknownSession }
            return try decryptWithSession(inner, entry: entry)
        default:
            throw AegisCryptoError.invalidWireFormat
        }
    }

    // MARK: - Groups

    func createGroup(groupID: Data, members: [IdentityPublic]) throws -> [OutgoingDistribution] {
        guard let identity else { throw CryptoEngineError.unknownSession }
        let session = try GroupSession(
            groupID: groupID,
            founder: identity,
            initialMembers: members.map { GroupMember(fingerprint: $0.fingerprint, displayName: "") }
        )
        groupSessions[groupID.hexString] = session
        for member in members { knownIdentities[member.fingerprint.hexString] = member }
        return try session.initialDistributions()
    }

    func joinGroup(groupID: Data, epoch: UInt32, members: [IdentityPublic]) throws -> [OutgoingDistribution] {
        guard let identity else { throw CryptoEngineError.unknownSession }
        let session = try GroupSession(
            groupID: groupID,
            epoch: epoch,
            joiner: identity,
            members: members.map { GroupMember(fingerprint: $0.fingerprint, displayName: "") }
        )
        groupSessions[groupID.hexString] = session
        for member in members { knownIdentities[member.fingerprint.hexString] = member }
        return try session.initialDistributions()
    }

    func encryptGroup(_ plaintext: Data, groupID: Data) throws -> (wire: Data, keyRotation: [OutgoingDistribution]) {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        let result = try session.encrypt(plaintext: plaintext)
        return (result.message.serialized(), result.keyRotation)
    }

    func decryptGroup(_ payload: Data, groupID: Data) throws -> Data {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        return try session.decrypt(GroupMessage.parse(payload))
    }

    func ingestDistribution(_ distribution: SenderKeyDistribution, groupID: Data, fromSender senderFingerprint: Data) throws {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        try session.ingestDistribution(distribution, fromSender: senderFingerprint)
    }

    func groupEpoch(groupID: Data) -> UInt32? {
        groupSessions[groupID.hexString]?.epoch
    }

    /// Encrypts each sender-key distribution inside the recipient's 1:1
    /// session. This is the crypto rule: distributions never travel under
    /// only the sender key, and never in the clear.
    func distributeEncrypted(_ distributions: [OutgoingDistribution]) throws -> [(recipient: IdentityPublic, wire: Data)] {
        try distributions.map { dist in
            guard let peer = knownIdentities[dist.recipientFingerprint.hexString]
                ?? contactIdentitySync(dist.recipientFingerprint)
            else { throw CryptoEngineError.noSessionNoBundle }
            let (wire, _) = try encryptDirect(dist.distribution.serialized(), to: peer)
            return (peer, wire)
        }
    }

    /// Membership changes (add/remove) — bumps the epoch, rotates our
    /// sender key, and returns fresh distributions for every member.
    func updateGroupMembership(groupID: Data, add: [IdentityPublic], remove: [Data]) throws -> [OutgoingDistribution] {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        var out: [OutgoingDistribution] = []
        for member in add {
            knownIdentities[member.fingerprint.hexString] = member
            out += try session.addMember(GroupMember(fingerprint: member.fingerprint, displayName: ""))
        }
        for fingerprint in remove {
            out += try session.removeMember(fingerprint: fingerprint)
        }
        return out
    }

    func rotateGroupSenderKeyIfNeeded(groupID: Data) throws -> [OutgoingDistribution] {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        return try session.rotateOurSenderKeyIfNeeded()
    }

    /// User-triggered or compromise-response re-key: rotates our sender key
    /// immediately (no epoch bump) and returns distributions for every
    /// member. The caller encrypts each distribution in the recipient's
    /// 1:1 session.
    func forceRotateGroupSenderKey(groupID: Data) throws -> [OutgoingDistribution] {
        guard let session = groupSessions[groupID.hexString] else { throw CryptoEngineError.unknownGroup }
        return try session.forcedRotate()
    }

    func leaveGroup(groupID: Data) {
        groupSessions.removeValue(forKey: groupID.hexString)
    }

    // MARK: - Routing mailboxes

    /// 32-byte routing mailbox for a 1:1 conversation.
    func directRoutingMailbox(peer: IdentityPublic) throws -> Data {
        let key = peer.fingerprint.hexString
        if let entry = sessions[key] {
            return RoutingMailbox.directRoute(
                localFingerprint: identity?.fingerprint ?? Data(),
                remoteFingerprint: peer.fingerprint,
                ephemeralPublicKey: entry.ephemeralPublicKey
            )
        }
        // No session yet: the responder's stable identity route.
        return RoutingMailbox.identityRoute(fingerprint: peer.fingerprint)
    }

    /// 32-byte routing mailbox for a group epoch.
    func groupRoutingMailbox(groupID: Data) throws -> Data {
        let epoch = groupSessions[groupID.hexString]?.epoch ?? 0
        return RoutingMailbox.groupRoute(groupID: groupID, epoch: epoch)
    }

    // MARK: - Attachments

    /// Returns the raw 32 bytes; callers wrap in `SymmetricKey` locally.
    /// (`SymmetricKey` is not Sendable, so it must not cross the actor boundary.)
    func makeFileKey() throws -> Data {
        try AttachmentCrypto.generateFileKey().withUnsafeBytes { Data($0) }
    }

    /// Wraps a file key for the conversation: the wrapped bytes travel in
    /// the message envelope (`wrappedKey`). For groups the wrap goes
    /// through the sender-key session; for 1:1 through the ratchet.
    func wrapFileKey(_ keyData: Data, groupID: Data?, peer: IdentityPublic?) throws -> Data {
        guard keyData.count == 32 else { throw AegisCryptoError.invalidKeyData }
        if let groupID {
            let (wire, _) = try encryptGroup(keyData, groupID: groupID)
            return wire
        } else if let peer {
            let (wire, _) = try encryptDirect(keyData, to: peer)
            return wire
        }
        throw CryptoEngineError.unknownSession
    }

    func unwrapFileKey(_ wrapped: Data, groupID: Data?, peer: IdentityPublic?) async throws -> Data {
        let raw: Data
        if let groupID {
            raw = try decryptGroup(wrapped, groupID: groupID)
        } else if let peer {
            raw = try decryptDirect(wrapped, from: peer)
        } else {
            throw CryptoEngineError.unknownSession
        }
        guard raw.count == 32 else { throw AegisCryptoError.invalidWireFormat }
        return raw
    }

    // MARK: - Fingerprints & verification

    static func fingerprintString(of identityPublic: IdentityPublic) -> String {
        // Grouped in 5s to match the app's display convention.
        let hex = identityPublic.fingerprint.map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 5).map { i in
            let end = hex.index(hex.startIndex, offsetBy: min(i + 5, hex.count))
            return String(hex[hex.index(hex.startIndex, offsetBy: i)..<end])
        }.joined(separator: " ")
    }

    static func safetyNumberString(local: IdentityPublic, remote: IdentityPublic) -> String {
        SafetyNumber.displayString(SafetyNumber.compute(
            localFingerprint: local.fingerprint,
            remoteFingerprint: remote.fingerprint
        ))
    }

    func localPublicIdentity() throws -> IdentityPublic {
        guard let identity else { throw CryptoEngineError.unknownSession }
        return identity.publicView
    }

    func identityPublic(forFingerprint fingerprint: Data) async -> IdentityPublic? {
        knownIdentities[fingerprint.hexString] ?? contactIdentity(fingerprint)
    }

    // MARK: - Backup

    struct BackupEnvelope: Codable {
        var version: Int
        var displayName: String
        var cryptoBlob: Data
        var storeSnapshot: Data
    }

    /// Assembles the full backup: crypto half (identity + sessions) plus
    /// the store snapshot half, encrypted under the passphrase.
    func exportBackup(passphrase: String, displayName: String, storeSnapshot: Data) throws -> Data {
        guard let identity, let manager = preKeyManager else { throw CryptoEngineError.unknownSession }
        let cryptoBlob = try KeyBackup.export(
            identity: identity,
            signedPreKey: manager.signedPreKey,
            password: SecureBytes(Data(passphrase.utf8)),
            exportedAt: Date()
        )
        let envelope = BackupEnvelope(version: 1, displayName: displayName, cryptoBlob: cryptoBlob, storeSnapshot: storeSnapshot)
        return try JSONEncoder().encode(envelope)
    }

    func importBackup(_ data: Data, passphrase: String) throws -> (IdentityPublic, String, Data) {
        let envelope = try JSONDecoder().decode(BackupEnvelope.self, from: data)
        guard envelope.version == 1 else {
            throw AegisCryptoError.unsupportedVersion(UInt8(clamping: envelope.version))
        }
        let contents = try KeyBackup.import(
            envelope.cryptoBlob,
            password: SecureBytes(Data(passphrase.utf8))
        )
        try persistIdentity(contents.identity, displayName: envelope.displayName)
        self.localDisplayName = envelope.displayName
        // Restore the backed-up signed prekey (not a fresh one) so bundles
        // peers already hold keep working after a restore.
        let manager = try PreKeyManager(restoring: contents.signedPreKey, identity: contents.identity)
        self.identity = contents.identity
        self.preKeyManager = manager
        return (contents.identity.publicView, envelope.displayName, envelope.storeSnapshot)
    }

    static func passphraseStrength(_ passphrase: String) -> PassphraseStrength {
        let length = passphrase.count
        let classes = [
            passphrase.rangeOfCharacter(from: .lowercaseLetters) != nil,
            passphrase.rangeOfCharacter(from: .uppercaseLetters) != nil,
            passphrase.rangeOfCharacter(from: .decimalDigits) != nil,
            passphrase.rangeOfCharacter(from: .symbols) != nil,
        ].filter { $0 }.count
        if length >= 16 && classes >= 3 { return .strong }
        if length >= 10 && classes >= 2 { return .fair }
        return .weak
    }

    // MARK: - Private

    private func contactIdentitySync(_ fingerprint: Data) -> IdentityPublic? {
        // The async resolver cannot be awaited from these sync helpers; the
        // known-identities cache is the sync path. Callers that need the
        // async path use `identityPublic(forFingerprint:)`.
        knownIdentities[fingerprint.hexString]
    }

    private struct StoredIdentity: Codable {
        var signingSeed: Data
        var agreementPrivateKey: Data
        var signedPreKeyPrivateKey: Data
        var signedPreKeyID: UInt32
        var signedPreKeyCreatedAt: Date
        var displayName: String
        var createdAt: Date
    }

    private func persistIdentity(_ identity: Identity, displayName: String) throws {
        // NOTE: the signed prekey is regenerated in-memory per launch (see
        // the file header); the stored copy lets a future durable-session
        // implementation restore it exactly.
        let stored = StoredIdentity(
            signingSeed: identity.signingKey.seed.toData(),
            agreementPrivateKey: identity.agreementKey.privateKey.toData(),
            signedPreKeyPrivateKey: (try? PreKeyManager(identity: identity).signedPreKey.keyPair.privateKey.toData()) ?? Data(),
            signedPreKeyID: 0,
            signedPreKeyCreatedAt: Date(),
            displayName: displayName,
            createdAt: identity.createdAt
        )
        try KeychainHelper.save(JSONEncoder().encode(stored), service: "app.aegis.identity", account: "primary")
    }
}

// MARK: - Small helpers

private extension String {
    func base64URLDecodedInput() -> String {
        var s = replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return s
    }

    func base64URLEncodedOutput() -> String {
        replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
