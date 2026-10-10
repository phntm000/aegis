// LiveAdapters — app-protocol implementations backed by the real packages.
//
// Three thin facades over one shared AegisCore:
//
//   LiveCryptoService   : CryptoService    (identity, sessions, attachments, backup)
//   LiveTransportService: TransportService (envelopes, blobs, calls, groups)
//   LiveStoreService    : StoreService     (persistence + mapping)
//
// The app talks ONLY to the protocols in Aegis/Protocols. Swapping the
// preview factory for LiveServiceFactory (see Bootstrap.swift) is the
// entire integration.

import AegisCrypto
import AegisStore
import AegisTransport
import CryptoKit
import Foundation
import os.log

// MARK: - Live crypto

struct LiveCryptoService: CryptoService {
    let core: AegisCore
    var engine: CryptoEngine { core.engine }

    // MARK: Identity

    func hasIdentity() async -> Bool {
        await engine.hasIdentity
    }

    func createIdentity(displayName: String) async throws -> LocalIdentity {
        let pub = try await engine.createIdentity(displayName: displayName)
        // Bind the identity route mailbox so first contact can reach us.
        await core.bindIdentityRoute()
        return LocalIdentity(
            id: core.localIdentityUUID,
            displayName: displayName,
            publicKey: pub.serialized(),
            createdAt: Date()
        )
    }

    func loadIdentity() async throws -> LocalIdentity {
        let (pub, displayName, createdAt) = try await engine.loadIdentity()
        return LocalIdentity(
            id: core.localIdentityUUID,
            displayName: displayName,
            publicKey: pub.serialized(),
            createdAt: createdAt
        )
    }

    func updateDisplayName(_ name: String) async throws -> LocalIdentity {
        try await engine.updateDisplayName(name)
        return try await loadIdentity()
    }

    func deleteIdentity() async throws {
        try await engine.deleteIdentity()
    }

    func flushSessions() async {
        await engine.flushSessions()
        await engine.flushGroupSessions()
    }

    // MARK: Fingerprints & invites

    nonisolated func fingerprint(of publicKey: Data) -> String {
        guard let pub = try? IdentityPublic(serialized: publicKey) else { return "invalid key" }
        return CryptoEngine.fingerprintString(of: pub)
    }

    nonisolated func safetyNumber(local localKey: Data, remote remoteKey: Data) -> String {
        guard
            let local = try? IdentityPublic(serialized: localKey),
            let remote = try? IdentityPublic(serialized: remoteKey)
        else { return "invalid keys" }
        return CryptoEngine.safetyNumberString(local: local, remote: remote)
    }

    func qrPayload(for identity: LocalIdentity) async throws -> String {
        try await engine.invitePayload(displayName: identity.displayName)
    }

    func inviteCode(for identity: LocalIdentity) async throws -> String {
        // The full invite is the code: it is copy-pasteable and parseable.
        // (The short "aegis-…" handle is display-only.)
        try await engine.invitePayload(displayName: identity.displayName)
    }

    func remoteIdentity(fromInvitePayload payload: String) async throws -> RemoteIdentity {
        let (pub, name) = try await engine.parseInvite(payload)
        return RemoteIdentity(displayName: name, publicKey: pub.serialized())
    }

    func supersededIdentityFingerprint() async -> Data? {
        await engine.supersededIdentityFingerprint
    }

    // MARK: Session encryption

    func encryptMessage(
        _ plaintext: Data,
        conversationID: UUID,
        recipientKeys: [Data]
    ) async throws -> Data {
        let sidecar = await core.sidecars.load(id: conversationID)
        if let groupID = sidecar.cryptoGroupID {
            let inner = GroupInnerPayload(kind: "message", body: plaintext)
            let (wire, rotation) = try await engine.encryptGroup(try JSONEncoder().encode(inner), groupID: groupID)
            if !rotation.isEmpty {
                // Sender-key rotation: the new key goes out encrypted in
                // each member's 1:1 session (the crypto rule).
                try await core.distribute(rotation)
            }
            return wire
        }
        guard let first = recipientKeys.first,
              let peer = try? IdentityPublic(serialized: first)
        else { throw CryptoEngineError.unknownSession }
        let (wire, _) = try await engine.encryptDirect(plaintext, to: peer)
        // Record the DM peer so inbound frames route to this conversation.
        var updated = sidecar
        if updated.dmPeerFingerprint == nil {
            updated.dmPeerFingerprint = peer.fingerprint
            try await core.sidecars.save(id: conversationID, sidecar: updated)
        }
        try await core.bindDirect(peer: peer)
        return wire
    }

    func decryptMessage(
        _ ciphertext: Data,
        conversationID: UUID,
        senderKey: Data
    ) async throws -> (plaintext: Data, senderIdentity: Data) {
        let sidecar = await core.sidecars.load(id: conversationID)
        if let groupID = sidecar.cryptoGroupID {
            let plaintext = try await engine.decryptGroup(ciphertext, groupID: groupID)
            // Group plaintext is a GroupInnerPayload; the app wants the body.
            // The sender is the group message's sender fingerprint.
            let sender: Data
            if let groupMessage = try? GroupMessage.parse(ciphertext) {
                sender = groupMessage.senderID
            } else {
                sender = senderKey
            }
            if let inner = try? JSONDecoder().decode(GroupInnerPayload.self, from: plaintext),
               inner.kind == "message"
            {
                return (inner.body, sender)
            }
            return (plaintext, sender)
        }
        guard let peer = await engine.identityPublic(forFingerprint: senderKey) else {
            throw CryptoEngineError.unknownSession
        }
        let (plaintext, sender) = try await engine.decryptDirect(ciphertext, from: peer)
        return (plaintext, sender.serialized())
    }

    // MARK: Attachments

    func encryptAttachment(at fileURL: URL, conversationID: UUID) async throws -> EncryptedFile {
        let sidecar = await core.sidecars.load(id: conversationID)
        let fileKeyData = try await engine.makeFileKey()
        let blobURL = try AttachmentCrypto.encryptFile(at: fileURL, key: SymmetricKey(data: fileKeyData))
        let byteCount = (try? FileManager.default.attributesOfItem(atPath: blobURL.path)[.size] as? Int64) ?? 0
        let groupID = sidecar.cryptoGroupID
        let peer: IdentityPublic?
        if groupID == nil, let fp = sidecar.dmPeerFingerprint {
            peer = await core.engine.identityPublic(forFingerprint: fp)
        } else {
            peer = nil
        }
        let wrapped = try await engine.wrapFileKey(fileKeyData, groupID: groupID, peer: peer)
        // Remember how to unwrap: the decrypt path has no conversation.
        await core.noteAttachmentContext(
            wrappedKey: wrapped,
            groupID: groupID,
            peerFingerprint: peer?.fingerprint
        )
        // Cache the raw file key now: after sender-key rotations or a
        // restart the wrapped key may become un-unwrappable, but the blob
        // on the relay is still ours to download.
        await core.noteFileKey(fileKeyData, wrappedKey: wrapped)
        return EncryptedFile(fileURL: blobURL, wrappedKey: wrapped, nonce: Data(), byteCount: byteCount)
    }

    func decryptAttachment(
        ciphertextURL: URL,
        wrappedKey: Data,
        nonce: Data,
        to destinationURL: URL
    ) async throws {
        // `nonce` is vestigial: AttachmentCrypto prepends the nonce to the
        // blob (see the framing decision in docs/INTEGRATION.md §3).
        _ = nonce
        // Fast path: the raw file key cached at send/receipt time. This
        // survives restarts and sender-key rotations, when the wrapped key
        // below would no longer unwrap.
        if let fileKeyData = await core.fileKey(forWrappedKey: wrappedKey) {
            try AttachmentCrypto.decryptFile(
                at: ciphertextURL, key: SymmetricKey(data: fileKeyData), to: destinationURL)
            return
        }
        let context = await core.attachmentContext(for: wrappedKey)
        let peer: IdentityPublic?
        if let fp = context?.peerFingerprint {
            peer = await core.engine.identityPublic(forFingerprint: fp)
        } else {
            peer = nil
        }
        let fileKeyData = try await engine.unwrapFileKey(wrappedKey, groupID: context?.groupID, peer: peer)
        try AttachmentCrypto.decryptFile(at: ciphertextURL, key: SymmetricKey(data: fileKeyData), to: destinationURL)
    }

    // MARK: Backup

    func exportEncryptedBackup(passphrase: String) async throws -> Data {
        let snapshot = try await core.pkgStore.snapshot()
        let snapshotData = try JSONEncoder().encode(snapshot)
        let (_, displayName, _) = try await engine.loadIdentity()
        return try await engine.exportBackup(passphrase: passphrase, displayName: displayName, storeSnapshot: snapshotData)
    }

    func importEncryptedBackup(_ data: Data, passphrase: String) async throws -> LocalIdentity {
        let (pub, displayName, snapshotData) = try await engine.importBackup(data, passphrase: passphrase)
        let snapshot = try JSONDecoder().decode(StoreSnapshot.self, from: snapshotData)
        try await core.pkgStore.restore(snapshot)
        try await core.rebuildRoutesFromStore()
        return LocalIdentity(
            id: core.localIdentityUUID,
            displayName: displayName,
            publicKey: pub.serialized(),
            createdAt: Date()
        )
    }

    nonisolated func backupPassphraseStrength(_ passphrase: String) -> PassphraseStrength {
        CryptoEngine.passphraseStrength(passphrase)
    }
}

// MARK: - Live transport

struct LiveTransportService: TransportService {
    let core: AegisCore

    /// Plugs the app's WebRTC stack into call signaling.
    func setMediaDelegate(_ delegate: (any CallMediaDelegate)?) async {
        await core.setMediaDelegate(delegate)
    }

    var connectionEvents: AsyncStream<ConnectionState> { core.connectionEvents }
    var incomingEnvelopes: AsyncStream<IncomingEnvelope> { core.incomingEnvelopes }
    var incomingCallEvents: AsyncStream<IncomingCall> { core.incomingCallEvents }
    var callStateEvents: AsyncStream<CallStateEvent> { core.callStateEvents }
    var groupEvents: AsyncStream<GroupEvent> { core.groupEvents }

    func currentConnectionState() async -> ConnectionState {
        await core.currentConnectionStateSync()
    }

    func configureRelay(_ config: RelayConfig) async throws {
        try await core.configureRelay(config)
    }

    func currentRelayConfig() async -> RelayConfig {
        await core.relayConfig
    }

    func retryConnection() async {
        await core.retryConnection()
    }

    func testRelay(url: String) async -> RelayTestResult {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized: URL
        switch RelayURLValidator.normalize(trimmed) {
        case .success(let url):
            normalized = url
        case .failure(let error):
            return RelayTestResult(reachable: false, latencyMs: nil, detail: error.description)
        }
        let result = await RelayProbe.handshake(url: normalized)
        if result.reachable {
            // A verified relay becomes automatic mode's fallback.
            UserDefaults.standard.set(normalized.absoluteString, forKey: SettingsKeys.relayLastKnownGoodURL)
        }
        return RelayTestResult(reachable: result.reachable, latencyMs: result.latencyMs, detail: result.detail)
    }

    func effectiveRelayURL() async -> String? {
        await core.getEffectiveRelayURL()
    }

    func relayHealth() async -> RelayHealth? {
        await core.getRelayHealth()
    }

    // MARK: Messaging

    func sendEnvelope(_ envelope: OutgoingEnvelope) async throws {
        try await core.sendCiphertext(envelope.ciphertext, conversationID: envelope.conversationID, kind: envelope.kind)
    }

    func sendTypingIndicator(conversationID: UUID, isTyping: Bool) async throws {
        var payload = WirePayload(kind: .typing)
        payload.isTyping = isTyping
        try await sendAppPayload(payload, conversationID: conversationID, kind: .typing)
    }

    func sendReadReceipt(conversationID: UUID, messageIDs: [UUID]) async throws {
        var payload = WirePayload(kind: .readReceipt)
        payload.messageIDs = messageIDs
        try await sendAppPayload(payload, conversationID: conversationID, kind: .readReceipt)
    }

    func sendScreenshotNotice(conversationID: UUID) async throws {
        let payload = WirePayload(kind: .screenshotNotice)
        try await sendAppPayload(payload, conversationID: conversationID, kind: .screenshotNotice)
    }

    private func sendAppPayload(_ payload: WirePayload, conversationID: UUID, kind: EnvelopeKind) async throws {
        let data = try JSONEncoder().encode(payload)
        let sidecar = await core.sidecars.load(id: conversationID)
        if let groupID = sidecar.cryptoGroupID {
            let inner = GroupInnerPayload(kind: "message", body: data)
            let (wire, rotation) = try await core.engine.encryptGroup(try JSONEncoder().encode(inner), groupID: groupID)
            if !rotation.isEmpty { try await core.distribute(rotation) }
            try await core.sendCiphertext(wire, conversationID: conversationID, kind: kind)
        } else if let fp = sidecar.dmPeerFingerprint,
                  let peer = await core.engine.identityPublic(forFingerprint: fp)
        {
            let (wire, _) = try await core.engine.encryptDirect(data, to: peer)
            try await core.sendCiphertext(wire, conversationID: conversationID, kind: kind)
        } else {
            throw CryptoEngineError.unknownSession
        }
    }

    // MARK: Blobs

    nonisolated func uploadBlob(from fileURL: URL, conversationID: UUID, id: UUID) -> AsyncStream<Double> {
        let (stream, continuation) = AsyncStream<Double>.makeStream()
        Task { [core] in
            for await progress in await core.uploadBlob(from: fileURL, id: id, conversationID: conversationID) {
                continuation.yield(progress)
            }
            continuation.finish()
        }
        return stream
    }

    nonisolated func downloadBlob(locator: String, id: UUID, to fileURL: URL) -> AsyncStream<Double> {
        let (stream, continuation) = AsyncStream<Double>.makeStream()
        Task { [core] in
            for await progress in await core.downloadBlob(locator: locator, to: fileURL) {
                continuation.yield(progress)
            }
            continuation.finish()
        }
        return stream
    }

    func blobLocator(attachmentID: UUID, conversationID: UUID) async throws -> String {
        try await core.blobLocator(attachmentID: attachmentID, conversationID: conversationID)
    }

    // MARK: Calls

    func placeCall(to contactID: UUID, kind: CallKind) async throws -> UUID {
        let peer = try await peerForContact(contactID)
        let conversationID = try await core.directConversationID(for: peer.fingerprint)
        return try await core.placeCall(to: peer, conversationID: conversationID, contactID: contactID, kind: kind)
    }

    func answerCall(_ callID: UUID) async throws {
        guard let context = await core.activeCallContext(callID),
              let peer = await core.engine.identityPublic(forFingerprint: context.peerFingerprint)
        else { throw CryptoEngineError.unknownSession }
        var sdp = "", dtls = ""
        if let delegate = await core.mediaDelegate {
            // Answer against the real inbound offer stored at knock time.
            let offerSDP = await core.remoteOfferSDP(for: callID)
            let answer = try await delegate.createAnswer(for: callID, offerSDP: offerSDP)
            sdp = answer.sdp; dtls = answer.dtlsFingerprint
        }
        let answer = CallAnswer(callID: callID.uuidString, sdp: sdp, dtlsFingerprint: dtls)
        await core.noteLocalDTLSFingerprint(dtls, for: callID)
        try await core.sendCallSignal(.answer(answer), to: peer)
    }

    func declineCall(_ callID: UUID) async throws {
        guard let context = await core.activeCallContext(callID),
              let peer = await core.engine.identityPublic(forFingerprint: context.peerFingerprint)
        else { return }
        try await core.sendCallSignal(.control(callID: callID.uuidString, control: .reject), to: peer)
        await core.dropCall(callID)
    }

    func endCall(_ callID: UUID) async throws {
        try await core.endCall(callID)
    }

    func setCallMuted(_ muted: Bool, callID: UUID) async throws {
        // Real media control: toggles the local audio track. Peers observe
        // it via the audio stream going silent.
        try await core.setCallMuted(muted, callID: callID)
    }

    func setCallVideoEnabled(_ enabled: Bool, callID: UUID) async throws {
        try await core.setCallVideoEnabled(enabled, callID: callID)
    }

    func setCallSpeaker(_ enabled: Bool, callID: UUID) async throws {
        try await core.setCallSpeaker(enabled, callID: callID)
    }

    func startScreenShare(callID: UUID) async throws {
        try await core.startScreenShare(callID: callID)
    }

    func stopScreenShare(callID: UUID) async throws {
        try await core.stopScreenShare(callID: callID)
    }

    nonisolated var screenShareSupported: Bool { true }

    func setVideoSink(_ sink: (any VideoSink)?, for callID: UUID) {
        Task { [core] in core.mediaRouter.setVideoSink(sink, for: callID) }
    }

    // MARK: Groups

    func createGroup(name: String, memberKeys: [Data]) async throws -> UUID {
        try await core.createGroup(name: name, topic: nil, announcementOnly: false, memberKeys: memberKeys)
    }

    func createChannel(name: String, topic: String?, announcementOnly: Bool) async throws -> UUID {
        try await core.createGroup(name: name, topic: topic, announcementOnly: announcementOnly, memberKeys: [])
    }

    func inviteMember(_ contactID: UUID, to conversationID: UUID) async throws {
        let peer = try await peerForContact(contactID)
        try await core.inviteMember(contactID, conversationID: conversationID, peer: peer)
    }

    func removeMember(_ contactID: UUID, from conversationID: UUID) async throws {
        let peer = try await peerForContact(contactID)
        try await core.removeMember(peer.fingerprint, conversationID: conversationID)
    }

    func setMemberRole(_ contactID: UUID, role: MemberRole, in conversationID: UUID) async throws {
        let peer = try await peerForContact(contactID)
        let sidecar = await core.sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        try await core.pkgStore.memberships.setRole(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(peer.fingerprint.hexString),
            role: StoreMapping.memberRole(from: role)
        )
        try await core.sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await core.engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "roleChanged",
                fingerprint: peer.fingerprint,
                role: role.rawValue
            )
        )
    }

    func setAnnouncementOnly(_ enabled: Bool, conversationID: UUID) async throws {
        let sidecar = await core.sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        var updated = sidecar
        updated.isAnnouncementOnly = enabled
        try await core.sidecars.save(id: conversationID, sidecar: updated)
        try await core.sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await core.engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "announcementModeChanged",
                announcementOnly: enabled
            )
        )
    }

    func setGroupTopic(_ topic: String?, conversationID: UUID) async throws {
        let sidecar = await core.sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        var updated = sidecar
        updated.subtitle = topic
        try await core.sidecars.save(id: conversationID, sidecar: updated)
        try await core.sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await core.engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "topicChanged",
                topic: topic
            )
        )
    }

    func rotateSenderKey(conversationID: UUID) async throws {
        let sidecar = await core.sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        let distributions = try await core.engine.forceRotateGroupSenderKey(groupID: groupID)
        try await core.distribute(distributions)
    }

    func leaveConversation(_ conversationID: UUID) async throws {
        let sidecar = await core.sidecars.load(id: conversationID)
        if let groupID = sidecar.cryptoGroupID {
            let mailbox = try await core.engine.groupRoutingMailbox(groupID: groupID)
            await core.unbindAndForget(mailbox: mailbox)
            await core.engine.leaveGroup(groupID: groupID)
            await core.engine.deletePersistedGroupSession(groupID: groupID)
        }
        try await core.pkgStore.conversations.delete(id: packageID(conversationID))
        await core.sidecars.delete(id: conversationID)
    }

    func requestGroupJoin(code: String) async throws {
        try await core.requestGroupJoin(code: code)
    }

    func approveJoinRequest(_ request: JoinRequest) async throws {
        guard let peer = await core.engine.identityPublic(forFingerprint: request.requesterFingerprint) else {
            throw CryptoEngineError.unknownSession
        }
        // The requester becomes a contact: the roster UI and future DMs
        // resolve names/keys through the contact list.
        let hex = request.requesterFingerprint.hexString
        let contacts = (try? await core.pkgStore.contacts.list(includeBlocked: true)) ?? []
        if contacts.contains(where: { $0.identityKeyFingerprint == hex }) == false {
            try await core.keyDirectory.store(fingerprintHex: hex, identityPublic: peer.serialized())
            let pkg = AegisStore.Contact(
                id: AegisStore.UserID(UUID().uuidString),
                displayName: request.requesterName,
                identityKeyFingerprint: hex
            )
            try await core.pkgStore.contacts.upsert(pkg)
        }
        let contactID = await core.resolveContactID(for: request.requesterFingerprint) ?? UUID()
        try await core.inviteMember(contactID, conversationID: request.conversationID, peer: peer)
    }

    // MARK: Identity-change tracking

    func noteIdentityChange(_ change: PendingIdentityChange, conversationID: UUID) async {
        await core.noteIdentityChange(change, conversationID: conversationID)
    }

    func resolveIdentityChange(conversationID: UUID, adoptNewKey: Bool) async {
        await core.resolveIdentityChange(conversationID: conversationID, adoptNewKey: adoptNewKey)
    }

    func pendingIdentityChange(for conversationID: UUID) async -> PendingIdentityChange? {
        await core.pendingIdentityChange(for: conversationID)
    }

    // MARK: - Private

    private func peerForContact(_ contactID: UUID) async throws -> IdentityPublic {
        let contacts = try await core.pkgStore.contacts.list(includeBlocked: true)
        guard let contact = contacts.first(where: { $0.id.rawValue == contactID.uuidString }),
              let keyData = await core.keyDirectory.load(fingerprintHex: contact.identityKeyFingerprint),
              let peer = try? IdentityPublic(serialized: keyData)
        else { throw CryptoEngineError.unknownSession }
        return peer
    }
}

// MARK: - Live store

struct LiveStoreService: StoreService {
    let core: AegisCore
    var pkgStore: any AegisDatabase { core.pkgStore }

    private var localUserID: UUID { core.localIdentityUUID }

    // MARK: Conversations

    func fetchConversations() async throws -> [Conversation] {
        let list = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        var out: [Conversation] = []
        for pkg in list {
            let id = appUUID(pkg.id)
            out.append(StoreMapping.toApp(pkg, sidecar: await core.sidecars.load(id: id)))
        }
        return out
    }

    func fetchConversation(id: UUID) async throws -> Conversation? {
        guard let pkg = try await pkgStore.conversations.fetch(id: packageID(id)) else { return nil }
        return StoreMapping.toApp(pkg, sidecar: await core.sidecars.load(id: id))
    }

    func saveConversation(_ conversation: Conversation) async throws {
        let (pkg, sidecar) = StoreMapping.toPackage(conversation)
        // Preserve crypto fields the app doesn't know about.
        var mergedSidecar = await core.sidecars.load(id: conversation.id)
        let cryptoGroupID = mergedSidecar.cryptoGroupID
        let dmPeerFingerprint = mergedSidecar.dmPeerFingerprint
        mergedSidecar = sidecar
        mergedSidecar.cryptoGroupID = cryptoGroupID
        mergedSidecar.dmPeerFingerprint = dmPeerFingerprint
        if (try? await pkgStore.conversations.fetch(id: pkg.id)) != nil {
            try await pkgStore.conversations.update(pkg)
        } else {
            try await pkgStore.conversations.create(pkg)
        }
        try await core.sidecars.save(id: conversation.id, sidecar: mergedSidecar)
    }

    func deleteConversation(id: UUID) async throws {
        try await pkgStore.conversations.delete(id: packageID(id))
        await core.sidecars.delete(id: id)
    }

    // MARK: Messages

    func fetchMessages(conversationID: UUID, limit: Int, before: Date?) async throws -> [Message] {
        // The package pages by message ID; the app pages by date. Walk
        // newest-first pages until we pass `before` (bounded: 10 pages).
        var collected: [AegisStore.Message] = []
        var cursor: AegisStore.MessageID? = nil
        for _ in 0..<10 {
            let page = try await pkgStore.messages.list(in: packageID(conversationID), limit: limit, before: cursor)
            if page.messages.isEmpty { break }
            collected.append(contentsOf: page.messages)
            cursor = page.messages.last?.id
            if let before, let oldest = page.messages.last?.sentAt, oldest < before { break }
            if !page.hasMore { break }
        }
        var out: [Message] = []
        for pkg in collected {
            if let before, let sentAt = pkg.sentAt, sentAt < before { continue }
            out.append(try await mapMessage(pkg))
            if out.count >= limit { break }
        }
        return out
    }

    /// The offline outbox: outgoing messages still marked `.sending`.
    func pendingOutbox() async throws -> [Message] {
        let pkgs = try await pkgStore.messages.pendingOutbox(now: Date())
        var out: [Message] = []
        for pkg in pkgs {
            // Only our own unsent messages belong in the outbox; anything
            // else is a store inconsistency, not a send candidate.
            if let appMessage = try? await mapMessage(pkg), appMessage.isFromMe {
                out.append(appMessage)
            }
        }
        return out
    }

    private func mapMessage(_ pkg: AegisStore.Message) async throws -> Message {
        var attachment: Attachment? = nil
        var voiceNote: VoiceNote? = nil
        let conversationID = appUUID(pkg.conversationID)
        let sidecar = await core.sidecars.load(id: conversationID)
        for attachmentID in pkg.attachmentIDs {
            if let pkgAttachment = try await pkgStore.attachments.fetch(id: attachmentID) {
                let wrappedKey = try? KeychainHelper.load(
                    service: "app.aegis.wrappedkeys",
                    account: StoreMapping.attachmentKeychainID(appUUID(attachmentID))
                )
                let extra = sidecar.voiceNoteExtras?[attachmentID.rawValue]
                let mapped = StoreMapping.toApp(pkgAttachment, wrappedKey: wrappedKey, voiceNoteExtra: extra)
                attachment = mapped.attachment ?? attachment
                voiceNote = mapped.voiceNote ?? voiceNote
            }
        }
        return StoreMapping.toApp(pkg, localUserID: localUserID, attachment: attachment, voiceNote: voiceNote)
    }

    /// Eagerly unwraps an inbound attachment's file key while the sender's
    /// sender key is current, and caches it. Without this, later rotations
    /// or a restart could strand the blob even though its ciphertext is
    /// still on the relay (see noteFileKey).
    private func cacheInboundFileKey(wrappedKey: Data, conversationID: UUID) async {
        // Skip when we already have it (e.g. our own sent attachments —
        // encryptAttachment cached the key at wrap time).
        if await core.fileKey(forWrappedKey: wrappedKey) != nil { return }
        let sidecar = await core.sidecars.load(id: conversationID)
        let peer: IdentityPublic?
        if let fp = sidecar.dmPeerFingerprint {
            peer = await core.engine.identityPublic(forFingerprint: fp)
        } else {
            peer = nil
        }
        if let fileKey = try? await core.engine.unwrapFileKey(
            wrappedKey, groupID: sidecar.cryptoGroupID, peer: peer)
        {
            await core.noteFileKey(fileKey, wrappedKey: wrappedKey)
        }
    }

    func saveMessage(_ message: Message) async throws {
        let pkg = StoreMapping.toPackage(message, localUserID: localUserID)
        if (try? await pkgStore.messages.fetch(id: pkg.id)) != nil {
            try await pkgStore.messages.update(pkg)
        } else {
            try await pkgStore.messages.insert(pkg)
        }
        // Attachments: package row + Keychain wrapped key + sidecar extras.
        var sidecar = await core.sidecars.load(id: message.conversationID)
        if let appAttachment = message.attachment {
            let pkgAttachment = StoreMapping.toPackage(appAttachment, messageID: message.id, conversationID: message.conversationID)
            try? await pkgStore.attachments.insert(pkgAttachment)
            if let wrappedKey = appAttachment.wrappedKey {
                try? KeychainHelper.save(
                    wrappedKey,
                    service: "app.aegis.wrappedkeys",
                    account: StoreMapping.attachmentKeychainID(appAttachment.id)
                )
                await core.noteAttachmentContext(
                    wrappedKey: wrappedKey,
                    groupID: sidecar.cryptoGroupID,
                    peerFingerprint: sidecar.dmPeerFingerprint
                )
                // Eagerly cache the file key while the sender key is current.
                await cacheInboundFileKey(wrappedKey: wrappedKey, conversationID: message.conversationID)
            }
        }
        if let note = message.voiceNote {
            let (pkgAttachment, extra) = StoreMapping.voiceNoteToPackage(
                note, messageID: message.id, conversationID: message.conversationID
            )
            try? await pkgStore.attachments.insert(pkgAttachment)
            var extras = sidecar.voiceNoteExtras ?? [:]
            extras[pkgAttachment.id.rawValue] = extra
            sidecar.voiceNoteExtras = extras
            if let wrappedKey = note.wrappedKey {
                try? KeychainHelper.save(
                    wrappedKey,
                    service: "app.aegis.wrappedkeys",
                    account: StoreMapping.attachmentKeychainID(note.id)
                )
                await core.noteAttachmentContext(
                    wrappedKey: wrappedKey,
                    groupID: sidecar.cryptoGroupID,
                    peerFingerprint: sidecar.dmPeerFingerprint
                )
                // Eagerly cache the file key while the sender key is current.
                await cacheInboundFileKey(wrappedKey: wrappedKey, conversationID: message.conversationID)
            }
        }
        try await core.sidecars.save(id: message.conversationID, sidecar: sidecar)
    }

    func updateMessage(_ message: Message) async throws {
        try await saveMessage(message)
    }

    func deleteMessage(id: UUID, conversationID: UUID) async throws {
        // Tombstone rather than hard delete (position preserved).
        if let pkg = try await pkgStore.messages.fetch(id: packageID(id)) {
            try await pkgStore.messages.applyTombstone(id: pkg.id, at: Date())
        }
    }

    func purgeExpiredMessages() async throws -> Int {
        try await pkgStore.messages.expungeDisappeared(now: Date())
    }

    func searchMessages(query: String, limit: Int) async throws -> [Message] {
        let results = try await pkgStore.messages.search(query: query, in: nil, limit: limit)
        return try await withThrowingTaskGroup(of: Message.self) { group in
            for pkg in results { group.addTask { try await self.mapMessage(pkg) } }
            var out: [Message] = []
            for try await message in group { out.append(message) }
            return out
        }
    }

    // MARK: Contacts

    func fetchContacts() async throws -> [Contact] {
        let list = try await pkgStore.contacts.list(includeBlocked: true)
        var out: [Contact] = []
        for pkg in list {
            let id = UUID(uuidString: pkg.id.rawValue) ?? UUID()
            let keyData = await core.keyDirectory.load(fingerprintHex: pkg.identityKeyFingerprint) ?? Data()
            out.append(StoreMapping.toApp(pkg, identityKey: keyData, id: id))
        }
        return out
    }

    func saveContact(_ contact: Contact) async throws {
        let fingerprintHex: String
        if let pub = try? IdentityPublic(serialized: contact.identityKey) {
            fingerprintHex = pub.fingerprint.map { String(format: "%02x", $0) }.joined()
            try await core.keyDirectory.store(fingerprintHex: fingerprintHex, identityPublic: contact.identityKey)
        } else {
            fingerprintHex = contact.identityKey.map { String(format: "%02x", $0) }.joined()
        }
        let pkg = StoreMapping.toPackage(contact, fingerprintHex: fingerprintHex)
        try await pkgStore.contacts.upsert(pkg)
    }

    func deleteContact(id: UUID) async throws {
        if let existing = try await pkgStore.contacts.fetch(id: packageID(id)) {
            try await core.keyDirectory.remove(fingerprintHex: existing.identityKeyFingerprint)
        }
        try await pkgStore.contacts.delete(id: packageID(id))
    }

    // MARK: Call history

    func fetchCallHistory(limit: Int) async throws -> [CallRecord] {
        // The package lists per conversation; walk conversations (bounded).
        var out: [CallRecord] = []
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        for conversation in conversations.prefix(50) {
            let records = try await pkgStore.calls.list(in: conversation.id, limit: limit)
            for pkg in records {
                out.append(mapCallRecord(pkg))
                if out.count >= limit { break }
            }
            if out.count >= limit { break }
        }
        return out.sorted { $0.startedAt > $1.startedAt }.prefix(limit).map { $0 }
    }

    private func mapCallRecord(_ pkg: AegisStore.CallRecord) -> CallRecord {
        let contactID = UUID(uuidString: pkg.participants.first?.rawValue ?? "") ?? UUID()
        return CallRecord(
            id: appUUID(pkg.id),
            contactID: contactID,
            contactName: "",
            kind: pkg.kind == .video ? .video : .audio,
            direction: pkg.direction == .incoming ? .incoming : .outgoing,
            startedAt: pkg.startedAt,
            duration: pkg.endedAt.map { $0.timeIntervalSince(pkg.startedAt) },
            endReason: pkg.wasAnswered ? .completed : .missed,
            conversationID: UUID(uuidString: pkg.conversationID.rawValue)
        )
    }

    func saveCallRecord(_ record: CallRecord) async throws {
        try await pkgStore.calls.insert(StoreMapping.toPackage(record))
    }

    func clearCallHistory() async throws {
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        for conversation in conversations.prefix(200) {
            let records = try await pkgStore.calls.list(in: conversation.id, limit: 10_000)
            for record in records {
                try await pkgStore.calls.delete(id: record.id)
            }
        }
    }

    // MARK: Group memberships

    func fetchMembershipRoles(conversationID: UUID) async throws -> [String: MemberRole] {
        let members = try await pkgStore.memberships.members(of: packageID(conversationID))
        var out: [String: MemberRole] = [:]
        out.reserveCapacity(members.count)
        for member in members {
            out[member.userID.rawValue] = StoreMapping.memberRole(from: member.role)
        }
        return out
    }

    // MARK: Storage

    func storageUsage() async throws -> StorageUsage {
        // Estimated: the package doesn't track byte sizes per row.
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        var messagesBytes: Int64 = 0
        var attachmentsBytes: Int64 = 0
        for conversation in conversations.prefix(200) {
            let page = try await pkgStore.messages.list(in: conversation.id, limit: 10_000, before: nil)
            messagesBytes += Int64(page.messages.count) * 512
            for message in page.messages {
                for attachmentID in message.attachmentIDs {
                    if let attachment = try? await pkgStore.attachments.fetch(id: attachmentID) {
                        attachmentsBytes += attachment.byteCount
                    }
                }
            }
        }
        return StorageUsage(messagesBytes: messagesBytes, attachmentsBytes: attachmentsBytes, voiceNotesBytes: 0)
    }

    func clearCaches() async throws {
        // Live store has no separate cache tier; thumbnails live with rows.
    }

    // MARK: Backup

    func exportAll() async throws -> Data {
        try JSONEncoder().encode(try await pkgStore.snapshot())
    }

    func importAll(_ data: Data) async throws {
        let snapshot = try JSONDecoder().decode(StoreSnapshot.self, from: data)
        try await pkgStore.restore(snapshot)
    }
}

// MARK: - Factory

/// Builds the live service graph. Call `boot()` once at launch (after the
/// user has an identity, or to restore one) before handing the services
/// to the app.
final class LiveServiceFactory: ServiceFactory, Sendable {
    private let core: AegisCore
    private let cryptoService: LiveCryptoService
    private let transportService: LiveTransportService
    private let storeService: LiveStoreService
    /// Retained for the app's lifetime: owns all WebRTC peer connections.
    private let mediaEngine: WebRTCMediaEngine

    init() throws {
        // Production persistence: SQLCipher-encrypted database at
        // Application Support/Aegis/aegis.db, unlocked with the
        // Keychain-held 256-bit database key (generated on first launch).
        // Conversations, messages, and contacts survive app restart.
        // (Previews and unit tests keep using InMemoryAegisStore.)
        let dbPath = try SQLCipherAegisStore.defaultDatabasePath()
        let pkgStore: any AegisDatabase = try SQLCipherAegisStore.openSync(at: dbPath)
        let sidecars = try ConversationSidecarStore()
        let keyDirectory = try ContactKeyDirectory()
        let engine = CryptoEngine { [pkgStore, keyDirectory] fingerprint in
            let hex = fingerprint.map { String(format: "%02x", $0) }.joined()
            let contacts = (try? await pkgStore.contacts.list(includeBlocked: true)) ?? []
            guard contacts.contains(where: { $0.identityKeyFingerprint == hex }),
                  let keyData = await keyDirectory.load(fingerprintHex: hex)
            else { return nil }
            return try? IdentityPublic(serialized: keyData)
        }
        let core = AegisCore(engine: engine, pkgStore: pkgStore, sidecars: sidecars, keyDirectory: keyDirectory)
        self.core = core
        self.cryptoService = LiveCryptoService(core: core)
        self.transportService = LiveTransportService(core: core)
        self.storeService = LiveStoreService(core: core)
        // Real-time media: the WebRTC engine implements both the SDP/ICE
        // delegate and the five media controls. Trickle-ICE candidates are
        // signaled back through the core's E2EE call-signaling path.
        let mediaEngine = WebRTCMediaEngine()
        self.mediaEngine = mediaEngine
        mediaEngine.onLocalIceCandidate = { [core] candidate, callID in
            Task {
                do {
                    try await core.sendIceCandidate(candidate, for: callID)
                } catch {
                    Logger(subsystem: "app.aegis.ios", category: "signaling")
                        .error("Failed to signal ICE candidate: \(error.localizedDescription)")
                }
            }
        }
        Task {
            await core.setMediaDelegate(mediaEngine)
            mediaEngine.attachFrameRouter(core.mediaRouter)
        }
    }

    /// The core self-boots its transports on init (see AegisCore), so the
    /// factory needs no separate boot step. Identity creation/relay
    /// configuration happen through the services themselves.
    func makeCrypto() -> any CryptoService { cryptoService }
    func makeTransport() -> any TransportService { transportService }
    func makeStore() -> any StoreService { storeService }
    func makeVoiceRoom() -> any VoiceRoomService { LiveVoiceRoomService(core: core) }
    func makeDeviceLink() -> any DeviceLinkService { LiveDeviceLinkService(core: core) }
}

// MARK: - Voice rooms (live)

/// Live VoiceRoomService: thin wrapper over AegisCore.voiceRooms.
struct LiveVoiceRoomService: VoiceRoomService {
    let core: AegisCore

    var events: AsyncStream<VoiceRoomEvent> {
        get async { core.voiceRooms.events }
    }

    func currentRoom() async -> VoiceRoom? {
        await core.voiceRooms.currentRoom
    }

    func joinRoom(conversationID: UUID, groupName: String) async {
        await core.voiceRooms.joinRoom(conversationID: conversationID, groupName: groupName)
    }

    func leaveRoom() async {
        await core.voiceRooms.leaveRoom()
    }

    func setMuted(_ muted: Bool) async {
        await core.voiceRooms.setLocalMuted(muted)
    }

    func setDeafened(_ deafened: Bool) async {
        await core.voiceRooms.setLocalDeafened(deafened)
    }
}

// MARK: - Linked devices (live)

/// Live DeviceLinkService: thin wrapper over AegisCore.deviceLink.
struct LiveDeviceLinkService: DeviceLinkService {
    let core: AegisCore

    func isLinkedDevice() async -> Bool {
        await core.deviceLink.isLinkedDevice
    }

    func localDeviceID() async -> UUID {
        await core.deviceLink.localDeviceID
    }

    func linkedDevices() async -> [DeviceInfo] {
        await core.deviceLink.linkedDevices
    }

    var pairingEvents: AsyncStream<DeviceLinkManager.PairingEvent> {
        get async { core.deviceLink.pairingEvents }
    }

    var syncEvents: AsyncStream<DeviceLinkManager.SyncEvent> {
        get async { core.deviceLink.syncEvents }
    }

    func beginPairingAsPrimary() async throws -> DeviceLinkManager.PrimaryPairingContext {
        try await core.deviceLink.beginPairingAsPrimary()
    }

    func pairingSASWords() async -> [String]? {
        await core.deviceLink.pairingSASWords()
    }

    func confirmPairing(provisioning: ProvisioningBundle) async throws {
        try await core.deviceLink.confirmPairing(provisioning: provisioning)
    }

    func cancelPairing() async {
        await core.deviceLink.cancelPairing()
    }

    func beginPairingAsSecondary(qrPayload: String, deviceName: String) async throws -> [String] {
        try await core.deviceLink.beginPairingAsSecondary(qrPayload: qrPayload, deviceName: deviceName)
    }

    func sendSync(kind: DeviceSyncKind, body: Data) async throws {
        try await core.deviceLink.sendSync(kind: kind, body: body)
    }

    func unpair(deviceID: UUID) async {
        await core.deviceLink.unpair(deviceID: deviceID)
    }
}
