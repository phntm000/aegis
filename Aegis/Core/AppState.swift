import AegisCrypto
import AegisDeviceLink
import AegisModeration
import Combine
import Foundation
import UIKit
import WebRTCBridge

/// A typing event rebroadcast to whichever conversation view is visible.
struct TypingEvent: Sendable {
    let conversationID: UUID
    let contactID: UUID
    let displayName: String
    let isTyping: Bool
}

/// Owns the app's lifecycle: identity bootstrap, phase routing, inbound
/// envelope dispatch, and call orchestration. View models never touch the
/// service protocols directly for cross-cutting concerns — they go through here.
@MainActor
final class AppState: ObservableObject {
    enum Phase: Equatable {
        case loading
        case onboarding
        case locked
        case main
    }

    // MARK: - Published state

    @Published private(set) var phase: Phase = .loading
    @Published private(set) var identity: LocalIdentity?
    @Published var connectionState: ConnectionState = .offline
    @Published var incomingCall: IncomingCall?
    @Published var activeCall: ActiveCall?
    @Published var bootstrapError: String?
    /// Pending group/channel join requests awaiting moderator approval.
    /// Kept in memory (a request is re-sendable by the requester pasting
    /// the code again); the invite code itself is the durable artifact.
    @Published private(set) var joinRequests: [JoinRequest] = []
    /// Message requests from unknown identities (A31): first contact from
    /// someone the user has never contacted. Persisted locally; the sender
    /// gets no receipts/typing/presence until a request is accepted.
    @Published private(set) var messageRequests: [MessageRequestItem] = []

    /// The conversation currently on screen (for screenshot notices, read receipts).
    var visibleConversationID: UUID?

    // MARK: - Local moderation (blocklist, reports, request persistence)

    /// Device-local blocklist: blocked identities are dropped silently on
    /// receipt. Local and silent by design — no "blocked" signal is ever
    /// emitted, to avoid confirming an active mailbox to a harasser.
    private var blocklist = LocalBlocklist()
    /// Device-local abuse reports. There is no central abuse desk to send
    /// them to — by design — so reports feed local heuristics only.
    private var reportStore = LocalReportStore()

    init(factory: any ServiceFactory) {
        self.crypto = factory.makeCrypto()
        self.transport = factory.makeTransport()
        self.store = factory.makeStore()
        self.voiceRoom = factory.makeVoiceRoom()
        self.deviceLink = factory.makeDeviceLink()
        self.appLock = AppLockManager()
        self.privacy = PrivacyController()
        self.notifications = NotificationManager()
        self.privacy.attach(appState: self)
        self.appLock.refreshBiometry()
        restoreLocalModeration()
    }

    // MARK: - Services

    let crypto: any CryptoService
    let transport: any TransportService
    let store: any StoreService
    let voiceRoom: any VoiceRoomService
    let deviceLink: any DeviceLinkService

    /// Paired-channel blob sync (attachments / voice notes). The actor is
    /// created lazily so the @Sendable progress callback can reference self.
    private lazy var blobRelay = DeviceLinkBlobRelay(
        deviceLink: deviceLink,
        transport: transport,
        crypto: crypto,
        onOutboundProgress: { [weak self] progress in
            Task { @MainActor [weak self] in
                self?.noteLinkedSyncProgress(progress)
            }
        }
    )

    let appLock: AppLockManager
    let privacy: PrivacyController
    let notifications: NotificationManager

    // MARK: - Typing broadcast

    private let typingSubject = PassthroughSubject<TypingEvent, Never>()
    var typingEvents: AnyPublisher<TypingEvent, Never> {
        typingSubject.eraseToAnyPublisher()
    }

    /// New/updated messages saved by the inbound dispatcher. Conversation view
    /// models subscribe and upsert into their visible thread.
    private let inboundSubject = PassthroughSubject<Message, Never>()
    var inboundMessages: AnyPublisher<Message, Never> {
        inboundSubject.eraseToAnyPublisher()
    }

    // MARK: - Bootstrap

    private var didStartListeners = false

    func bootstrap() async {
        phase = .loading
        bootstrapError = nil
        // Transport listeners are hot AsyncStreams; starting them twice would
        // double-deliver every envelope.
        if !didStartListeners {
            didStartListeners = true
            startTransportListeners()
            startVoiceRoomListeners()
            startDeviceLinkListeners()
        }
        await notifications.refreshStatus()

        // Linked secondary: no local identity keypair — the primary holds
        // the keys and relays everything over the paired channel.
        if await deviceLink.isLinkedDevice() {
            enterLinkedMain()
            return
        }

        guard await crypto.hasIdentity() else {
            phase = .onboarding
            return
        }
        do {
            identity = try await crypto.loadIdentity()
            // Apply the saved relay config before going live.
            let mode = RelayConfig.Mode(
                rawValue: UserDefaults.standard.string(forKey: SettingsKeys.relayMode) ?? ""
            ) ?? .automatic
            let url = UserDefaults.standard.string(forKey: SettingsKeys.relayCustomURL)
            try? await transport.configureRelay(RelayConfig(mode: mode, customRelayURL: url))
            // Sweep expired disappearing messages on every launch.
            _ = try? await store.purgeExpiredMessages()
            phase = appLock.isEnabled ? .locked : .main
            if phase == .main {
                // Flush the offline outbox now that we're live.
                Task { await flushOutbox() }
            }
        } catch {
            bootstrapError = error.localizedDescription
            phase = .onboarding
        }
    }

    /// Called by onboarding once the identity is created and backed up.
    func completeOnboarding(identity: LocalIdentity) {
        self.identity = identity
        self.bootstrapError = nil
        self.phase = .main
        Task { await flushOutbox() }
    }

    /// Enters the main UI as a linked secondary (no local identity keypair).
    /// Uses a stable synthesized identity so the UI has a "me" to render;
    /// it is never used for cryptography (all crypto happens on the primary).
    func enterLinkedMain() {
        let name = UserDefaults.standard.string(forKey: "aegis.linkedDisplayName") ?? "Aegis user"
        let id: UUID
        if let s = UserDefaults.standard.string(forKey: "aegis.linkedIdentityID"),
           let u = UUID(uuidString: s) {
            id = u
        } else {
            id = UUID()
            UserDefaults.standard.set(id.uuidString, forKey: "aegis.linkedIdentityID")
        }
        // A linked device that hasn't finished pairing yet has no name;
        // provisioning fills it in and re-enters.
        self.identity = LocalIdentity(id: id, displayName: name, publicKey: Data(), createdAt: Date())
        self.bootstrapError = nil
        self.phase = .main
    }

    /// Re-sends messages stuck in `.sending`/`.failed` (the offline outbox).
    /// Called on launch and when connectivity returns. Each message is
    /// re-encrypted fresh (ratchet/sender-key state may have advanced) but
    /// keeps its original ID, so recipients dedupe redeliveries.
    func flushOutbox() async {
        let pending: [Message]
        do { pending = try await store.pendingOutbox() } catch { return }
        for message in pending {
            await resendOutboxMessage(message)
        }
    }

    private func resendOutboxMessage(_ message: Message) async {
        guard let conversation = try? await store.fetchConversation(id: message.conversationID) else {
            // Conversation gone: mark failed so it leaves the outbox.
            var failed = message
            failed.status = .failed
            try? await store.updateMessage(failed)
            return
        }
        // Polls re-send as polls (a text rebuild would drop the ballot box).
        let envelopeKind: EnvelopeKind
        var payload: WirePayload
        if let poll = message.poll {
            payload = WirePayload.poll(
                id: message.id,
                question: poll.question,
                options: poll.options,
                allowsMultipleChoice: poll.allowsMultipleChoice,
                anonymous: poll.isAnonymous,
                closesAt: poll.closesAt,
                eligibleVoterCount: poll.eligibleVoterCount,
                expiresIn: conversation.disappearingInterval,
                disappearAfterRead: message.disappearAfterReadInterval == nil ? nil : true
            )
            envelopeKind = .poll
        } else {
            payload = WirePayload.text(
                id: message.id,
                body: message.body,
                replyToID: message.replyToID,
                quote: message.quoteSnapshot,
                threadRootID: message.threadRootID,
                attachment: message.attachment,
                voiceNote: message.voiceNote,
                expiresIn: conversation.disappearingInterval,
                disappearAfterRead: message.disappearAfterReadInterval == nil ? nil : true
            )
            envelopeKind = .message
        }
        payload.previousFingerprint = await crypto.supersededIdentityFingerprint()
        // Recipient keys: DM peer's key, or group members' keys.
        let contacts = (try? await store.fetchContacts()) ?? []
        let recipientKeys: [Data]
        if conversation.kind == .direct {
            // DM: the peer is the member who isn't us.
            let peerID = conversation.memberIDs.first { $0 != message.senderID }
            let peerKey = peerID.flatMap { id in contacts.first(where: { $0.id == id })?.identityKey }
            recipientKeys = peerKey.map { [$0] } ?? []
        } else {
            recipientKeys = conversation.memberIDs.compactMap { id in
                contacts.first { $0.id == id }?.identityKey
            }
        }
        do {
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: conversation.id,
                recipientKeys: recipientKeys
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: message.id,
                conversationID: conversation.id,
                ciphertext: ciphertext,
                kind: envelopeKind
            ))
            var sent = message
            sent.status = .sent
            try? await store.updateMessage(sent)
        } catch {
            // Remains queued; the next flush or a manual retry tries again.
            // (Never mark failed here: a transient outage must not look
            // like a permanent failure.)
        }
    }

    /// Full wipe: crypto identity + local store, then back to onboarding.
    func deleteIdentityAndReset() async {
        try? await crypto.deleteIdentity()
        identity = nil
        activeCall = nil
        incomingCall = nil
        phase = .onboarding
    }

    // MARK: - Transport listeners

    private func startTransportListeners() {
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await state in self.transport.connectionEvents {
                let wasSendable = self.connectionState.canSend
                self.connectionState = state
                // Connectivity regained after an outage: flush the offline
                // outbox so queued messages go out without manual retries.
                if !wasSendable, state.canSend, self.phase == .main {
                    Task { await self.flushOutbox() }
                }
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await envelope in self.transport.incomingEnvelopes {
                await self.handleIncoming(envelope)
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await call in self.transport.incomingCallEvents {
                self.incomingCall = call
                self.notifications.notifyIncomingCall(from: call.contactName)
                Haptics.notification(.warning)
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await event in self.transport.callStateEvents {
                await self.applyCallEvent(event)
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            // Single consumer of the group-event stream; re-broadcast via
            // NotificationCenter so any number of views can observe without
            // competing for the AsyncStream.
            for await event in self.transport.groupEvents {
                NotificationCenter.default.post(name: .aegisGroupEvent, object: event)
            }
        }
    }

    // MARK: - Inbound dispatch

    private func handleIncoming(_ envelope: IncomingEnvelope) async {
        do {
            let plaintext: Data
            let senderIdentity: Data
            if let pre = envelope.preDecrypted {
                // Unknown-sender rendezvous: the transport already decrypted
                // and X3DH-authenticated the sender. Never decrypt twice —
                // the prekey was consumed.
                plaintext = pre.plaintext
                senderIdentity = pre.senderIdentity
            } else {
                let decrypted = try await crypto.decryptMessage(
                    envelope.ciphertext,
                    conversationID: envelope.conversationID,
                    senderKey: envelope.senderKey
                )
                plaintext = decrypted.plaintext
                senderIdentity = decrypted.senderIdentity
            }
            // Identity-change detection runs BEFORE any message processing:
            // when the authenticated sender differs from the contact's
            // stored key, the message is held and the user is warned.
            if await handleIdentityChangeIfNeeded(
                senderIdentity: senderIdentity,
                expectedFingerprint: envelope.senderKey,
                conversationID: envelope.conversationID,
                supersedes: envelope.preDecrypted?.supersedesFingerprint,
                receivedAt: envelope.receivedAt
            ) {
                return
            }
            // While an identity change is pending for this conversation, new
            // peer messages are held (saved, but not displayed or notified)
            // until the user re-verifies or explicitly dismisses.
            if await isIdentityChangePending(for: envelope.conversationID, senderIdentity: senderIdentity) {
                await holdMessageForIdentityChange(
                    plaintext: plaintext,
                    envelope: envelope
                )
                return
            }
            // Blocked identities are dropped silently across every payload
            // kind: no display, no notification, no receipts. Block is local
            // and silent — no signal is ever emitted to the blocked party.
            if blocklist.isBlocked(envelope.senderKey) {
                return
            }
            let payload = try WirePayload.decoded(from: plaintext)
            // Full serialized identity when the decrypt layer authenticated
            // one (65 bytes); nil for group sender fingerprints.
            let fullSenderIdentity = senderIdentity.count == 65 ? senderIdentity : nil
            switch payload.kind {
            case .text:
                await handleIncomingText(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .reaction:
                await handleIncomingReaction(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .edit:
                await handleIncomingEdit(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .delete:
                await handleIncomingDelete(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .poll:
                await handleIncomingPoll(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .ballot:
                await handleIncomingBallot(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .pin:
                await handleIncomingPin(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .unpin:
                await handleIncomingUnpin(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .readReceipt:
                await handleIncomingReadReceipt(payload, from: envelope.senderKey)
            case .typing:
                await handleIncomingTyping(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .screenshotNotice:
                await handleIncomingScreenshotNotice(envelope: envelope, senderIdentity: fullSenderIdentity)
            case .groupJoinRequest:
                await handleIncomingJoinRequest(payload, envelope: envelope)
            }
        } catch {
            // Corrupt or undecryptable envelope: drop it loudly in debug, silently
            // in production. Never crash the listener loop.
            #if DEBUG
            print("[Aegis] Dropping undecryptable envelope: \(error)")
            #endif
        }
    }

    // MARK: - Identity-change detection

    /// Checks the authenticated sender against the conversation contact's
    /// stored key. Returns true when the message was consumed by
    /// identity-change handling: the contact is flagged `.identityChanged`,
    /// the conversation shows the "safety number changed" banner, and the
    /// message is held (not displayed) until the user re-verifies or
    /// explicitly dismisses.
    ///
    /// The `supersedes` hint (from the unknown-sender rendezvous path) links
    /// a new identity to an existing contact. Without it, an unknown sender
    /// is just an unknown sender — never attributed to a contact.
    private func handleIdentityChangeIfNeeded(
        senderIdentity: Data,
        expectedFingerprint: Data,
        conversationID: UUID,
        supersedes: Data?,
        receivedAt: Date
    ) async -> Bool {
        guard let senderFP = Self.fingerprint(ofSerializedIdentity: senderIdentity) else { return false }
        // 1:1 only: safety numbers are a 1:1 concept. Group membership
        // changes go through the group invite/distribution flow.
        guard let conversation = try? await store.fetchConversation(id: conversationID),
              conversation.kind == .direct
        else { return false }
        // The currently effective peer key: the pending new identity when a
        // change is already flagged (rotations chain: K1→K2→K3 re-flags),
        // else the contact's stored key.
        let pending = await transport.pendingIdentityChange(for: conversationID)
        let effectiveFP: Data
        let contact: Contact?
        if let pending {
            effectiveFP = pending.newFingerprint
            if let byPrevious = await contactForFingerprint(pending.previousFingerprint) {
                contact = byPrevious
            } else {
                contact = await contactForFingerprint(supersedes ?? expectedFingerprint)
            }
        } else {
            // The contact this conversation belongs to: the hinted previous
            // identity when the sender rotated, else the expected route peer
            // (covers prekeys arriving on an established peer's route).
            let contactFP = supersedes ?? expectedFingerprint
            contact = await contactForFingerprint(contactFP)
            guard let contact,
                  let storedFP = Self.fingerprint(ofSerializedIdentity: contact.identityKey)
            else { return false }
            effectiveFP = storedFP
        }
        guard let contact, effectiveFP != senderFP else { return false }
        // The authenticated sender differs from the effective key: flag the
        // contact, banner the conversation, and hold the message. The user
        // re-verifies (adopting the new key) or explicitly dismisses.
        var updated = contact
        updated.verification = .identityChanged
        try? await store.saveContact(updated)
        await transport.noteIdentityChange(
            PendingIdentityChange(
                previousFingerprint: effectiveFP,
                newFingerprint: senderFP,
                newIdentityKey: senderIdentity,
                detectedAt: receivedAt
            ),
            conversationID: conversationID
        )
        await insertNotice(
            conversationID: conversationID,
            text: "Safety number changed — tap to re-verify"
        )
        Haptics.notification(.warning)
        return true
    }

    /// Whether display is currently paused for this conversation: a pending,
    /// not-dismissed identity change whose new identity matches the sender.
    private func isIdentityChangePending(for conversationID: UUID, senderIdentity: Data) async -> Bool {
        guard let senderFP = Self.fingerprint(ofSerializedIdentity: senderIdentity),
              let pending = await transport.pendingIdentityChange(for: conversationID),
              !pending.dismissed
        else { return false }
        return pending.newFingerprint == senderFP
    }

    /// Saves a message that arrived while its sender's identity change is
    /// unverified. It is stored (never lost) but not displayed, notified,
    /// or counted as unread until the user re-verifies or dismisses.
    private func holdMessageForIdentityChange(
        plaintext: Data,
        envelope: IncomingEnvelope
    ) async {
        guard let payload = try? WirePayload.decoded(from: plaintext),
              payload.kind == .text,
              var conversation = try? await store.fetchConversation(id: envelope.conversationID),
              let pending = await transport.pendingIdentityChange(for: envelope.conversationID),
              let contact = await contactForFingerprint(pending.previousFingerprint)
        else { return }
        let message = Message(
            conversationID: conversation.id,
            senderID: contact.id,
            isFromMe: false,
            body: payload.body,
            replyToID: payload.replyToID,
            status: .delivered,
            sentAt: envelope.receivedAt
        )
        try? await store.saveMessage(message)
        // Deliberately: no inboundSubject, no notification, no unread bump.
        // The banner is the signal; the messages appear on resolve.
        conversation.lastMessageAt = message.sentAt
        try? await store.saveConversation(conversation)
    }

    /// Fingerprint of a serialized `IdentityPublic` (65 bytes). Nil when the
    /// data is not a valid serialized identity.
    static func fingerprint(ofSerializedIdentity data: Data) -> Data? {
        guard let pub = try? IdentityPublic(serialized: data) else { return nil }
        return pub.fingerprint
    }

    /// Finds a contact by identity fingerprint. `Contact.identityKey` is the
    /// 65-byte serialized public key; the lookup compares fingerprints (and
    /// also matches legacy placeholders that stored a bare fingerprint).
    private func contactForFingerprint(_ fingerprint: Data) async -> Contact? {
        let contacts = (try? await store.fetchContacts()) ?? []
        return contacts.first {
            Self.fingerprint(ofSerializedIdentity: $0.identityKey) == fingerprint
                || $0.identityKey == fingerprint
        }
    }

    /// Verifies the identity signature on signed event payloads
    /// (reaction, edit, delete, ballot, pin, unpin). Returns true for
    /// kinds that aren't signature-gated. A gated kind that is unsigned
    /// or badly signed is dropped (returns false) — the AEAD channel
    /// alone is not enough to attribute these events to the long-term
    /// identity.
    private func verifyEventSignature(
        _ payload: WirePayload,
        envelope: IncomingEnvelope,
        senderIdentity: Data?
    ) async -> Bool {
        guard WirePayload.signedKinds.contains(payload.kind) else { return true }
        let signingKey: Data?
        if let senderIdentity,
           let identity = try? IdentityPublic(serialized: senderIdentity) {
            signingKey = identity.signingPublicKey
        } else {
            // Group sender-key path: the decrypt layer doesn't hand us the
            // full identity, so resolve it from the roster/contact.
            let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
            signingKey = (try? IdentityPublic(serialized: contact.identityKey))?.signingPublicKey
        }
        guard let signingKey, payload.verifySignature(signingPublicKey: signingKey) else {
            #if DEBUG
            print("[Aegis] Dropping \(payload.kind) event: missing/invalid identity signature")
            #endif
            return false
        }
        return true
    }

    private func handleIncomingText(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard var conversation = try? await store.fetchConversation(id: envelope.conversationID),
              let messageID = payload.messageID else { return }
        // Message-requests inbox: a DM from an identity we have never
        // contacted is not a chat yet. (resolveContact below creates the
        // placeholder, so the "unknown" check must run first.)
        let wasUnknownSender = conversation.kind == .direct
            && (await contactForFingerprint(envelope.senderKey)) == nil
        let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        let afterRead = payload.disappearAfterRead ?? false
        let expiresAt = payload.expiresIn.flatMap { afterRead ? nil : Date().addingTimeInterval($0) }

        if conversation.kind == .direct,
           (wasUnknownSender || messageRequest(for: conversation.id) != nil)
        {
            await routeToMessageRequests(
                messageID: messageID,
                payload: payload,
                envelope: envelope,
                conversation: conversation,
                contact: contact,
                expiresAt: expiresAt
            )
            return
        }

        let message = Message(
            id: messageID,
            conversationID: conversation.id,
            senderID: contact.id,
            isFromMe: false,
            body: payload.body,
            replyToID: payload.replyToID,
            quoteSnapshot: payload.quote,
            status: .delivered,
            expiresAt: expiresAt,
            disappearAfterReadInterval: afterRead ? payload.expiresIn : nil,
            threadRootID: payload.threadRootID,
            attachment: payload.attachment,
            voiceNote: payload.voiceNote,
            sentAt: envelope.receivedAt
        )
        try? await store.saveMessage(message)
        // Primary: mirror inbound traffic to linked devices so their
        // threads stay in sync.
        await forwardToLinkedDevices(message, conversation: conversation, senderName: contact.displayName)

        conversation.unreadCount += (visibleConversationID == conversation.id) ? 0 : 1
        conversation.lastMessagePreview = previewText(for: message, senderName: contact.displayName)
        conversation.lastMessageAt = message.sentAt
        conversation.lastMessageIsFromMe = false
        try? await store.saveConversation(conversation)

        // Push to the visible thread if it's open.
        inboundSubject.send(message)

        // Notify only when the app isn't looking at this conversation.
        let isBackgrounded = UIApplication.shared.applicationState != .active
        if (isBackgrounded || visibleConversationID != conversation.id) && !conversation.isMuted {
            notifications.notifyMessage(
                from: contact.displayName,
                preview: previewText(for: message, senderName: nil),
                conversationID: conversation.id
            )
        }
        Haptics.impact(.light)
    }

    private func handleIncomingReaction(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID, let emoji = payload.emoji else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        let reactor = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        let conversations = (try? await store.fetchConversations()) ?? []
        for conversation in conversations {
            let messages = (try? await store.fetchMessages(conversationID: conversation.id, limit: 200, before: nil)) ?? []
            if var message = messages.first(where: { $0.id == target }) {
                var reactors = message.reactions[emoji] ?? []
                // Toggle semantics: a repeated reaction from the same sender removes it.
                if let idx = reactors.firstIndex(of: reactor.id) {
                    reactors.remove(at: idx)
                    if reactors.isEmpty {
                        message.reactions.removeValue(forKey: emoji)
                    } else {
                        message.reactions[emoji] = reactors
                    }
                } else {
                    reactors.append(reactor.id)
                    message.reactions[emoji] = reactors
                }
                try? await store.updateMessage(message)
                inboundSubject.send(message)
                return
            }
        }
    }

    private func handleIncomingEdit(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID, let editedBody = payload.editedBody else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        let editor = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        await mutateMessage(id: target) { message in
            // Only the author may edit their own message, and never a
            // tombstone. The edit window is the recipient's local policy;
            // late edits are still applied but flagged (the sender's
            // client enforces the window before sending).
            guard !message.isDeleted, message.senderID == editor.id else { return }
            if let previous = message.body, previous != editedBody {
                message.editHistory.append(MessageEdit(body: previous, editedAt: Date()))
            }
            message.body = editedBody
            message.editedAt = Date()
        }
    }

    private func handleIncomingDelete(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        let deleter = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        // Route through the store's tombstone path so attachment metadata
        // is dropped and out-of-band secrets (Keychain keys, cached files)
        // are cryptographically wiped — not just blanked in the UI.
        let conversations = (try? await store.fetchConversations()) ?? []
        for conversation in conversations {
            guard let message = try? await store.fetchMessage(id: target, conversationID: conversation.id) else {
                continue
            }
            // Only the author may tombstone their own message.
            guard message.senderID == deleter.id else {
                #if DEBUG
                print("[Aegis] Dropping delete: sender is not the message author")
                #endif
                return
            }
            try? await store.deleteMessage(id: target, conversationID: conversation.id)
            if let tombstoned = try? await store.fetchMessage(id: target, conversationID: conversation.id) {
                inboundSubject.send(tombstoned)
            } else {
                var fallback = message
                fallback.deletedAt = Date()
                inboundSubject.send(fallback)
            }
            return
        }
    }

    // MARK: - Polls

    private func handleIncomingPoll(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard var conversation = try? await store.fetchConversation(id: envelope.conversationID),
              let messageID = payload.messageID,
              let question = payload.pollQuestion,
              let options = payload.pollOptions, options.count >= 2 else { return }
        let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        let afterRead = payload.disappearAfterRead ?? false
        let poll = PollMessage(
            question: String(question.prefix(280)),
            options: options.map { String($0.prefix(100)) },
            allowsMultipleChoice: payload.pollAllowsMultipleChoice ?? false,
            isAnonymous: payload.pollAnonymous ?? false,
            closesAt: payload.pollClosesAt,
            tally: [:],
            voters: [],
            voterChoices: [:],
            myChoices: [],
            eligibleVoterCount: payload.pollEligibleVoterCount
        )
        let message = Message(
            id: messageID,
            conversationID: conversation.id,
            senderID: contact.id,
            isFromMe: false,
            body: nil,
            status: .delivered,
            expiresAt: afterRead ? nil : payload.expiresIn.map { Date().addingTimeInterval($0) },
            disappearAfterReadInterval: afterRead ? payload.expiresIn : nil,
            poll: poll,
            sentAt: envelope.receivedAt
        )
        try? await store.saveMessage(message)
        await forwardToLinkedDevices(message, conversation: conversation, senderName: contact.displayName)

        conversation.unreadCount += (visibleConversationID == conversation.id) ? 0 : 1
        conversation.lastMessagePreview = previewText(for: message, senderName: contact.displayName)
        conversation.lastMessageAt = message.sentAt
        conversation.lastMessageIsFromMe = false
        try? await store.saveConversation(conversation)

        inboundSubject.send(message)

        let isBackgrounded = UIApplication.shared.applicationState != .active
        if (isBackgrounded || visibleConversationID != conversation.id) && !conversation.isMuted {
            notifications.notifyMessage(
                from: contact.displayName,
                preview: previewText(for: message, senderName: nil),
                conversationID: conversation.id
            )
        }
        Haptics.impact(.light)
    }

    private func handleIncomingBallot(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID, let choices = payload.ballotChoices else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        let voter = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        await mutateMessage(id: target) { message in
            guard var poll = message.poll, !message.isDeleted else { return }
            // Client-side tally from signed ballots: invalid ballots
            // (double votes, closed polls, out-of-range) are ignored.
            if poll.applyBallot(voter: voter.id, choices: choices) {
                message.poll = poll
            }
        }
    }

    // MARK: - Pins

    /// Whether `pinner` may pin in `conversation`: anyone in a 1:1 chat,
    /// moderators+ in groups/channels. Membership roles are keyed by the
    /// contact's UUID string; unknown role fails closed (no pin).
    private func canPin(_ pinner: Contact, in conversation: Conversation) async -> Bool {
        switch conversation.kind {
        case .direct:
            return true
        case .group, .channel, .vault:
            // Our own pins use the conversation's cached role.
            if pinner.id == identity?.id {
                return conversation.myRole?.canModerate ?? false
            }
            let roles = (try? await store.fetchMembershipRoles(conversationID: conversation.id)) ?? [:]
            return roles[pinner.id.uuidString]?.canModerate ?? false
        }
    }

    private func handleIncomingPin(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        guard let conversation = try? await store.fetchConversation(id: envelope.conversationID) else { return }
        let pinner = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        guard await canPin(pinner, in: conversation) else { return }
        await mutateMessage(id: target) { message in
            guard !message.isDeleted else { return }
            message.pin = MessagePin(
                pinnedBy: pinner.id,
                pinnedByName: pinner.displayName,
                pinnedAt: Date(),
                expiresAt: payload.pinExpiresAt
            )
        }
    }

    private func handleIncomingUnpin(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard let target = payload.targetMessageID else { return }
        guard await verifyEventSignature(payload, envelope: envelope, senderIdentity: senderIdentity) else { return }
        guard let conversation = try? await store.fetchConversation(id: envelope.conversationID) else { return }
        let pinner = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        guard await canPin(pinner, in: conversation) else { return }
        await mutateMessage(id: target) { message in
            message.pin = nil
        }
    }

    private func handleIncomingReadReceipt(_ payload: WirePayload, from senderKey: Data) async {
        guard let ids = payload.messageIDs, !ids.isEmpty else { return }
        let conversations = (try? await store.fetchConversations()) ?? []
        for conversation in conversations {
            let messages = (try? await store.fetchMessages(conversationID: conversation.id, limit: 200, before: nil)) ?? []
            var changed = false
            for var message in messages where ids.contains(message.id) && message.isFromMe {
                message.status = .read
                // "Disappear after read": the sender's timer starts when the
                // recipient reads.
                if let interval = message.disappearAfterReadInterval, message.expiresAt == nil {
                    message.expiresAt = Date().addingTimeInterval(interval)
                }
                try? await store.updateMessage(message)
                changed = true
            }
            if changed { break }
        }
    }

    private func handleIncomingTyping(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        typingSubject.send(TypingEvent(
            conversationID: envelope.conversationID,
            contactID: contact.id,
            displayName: contact.displayName,
            isTyping: payload.isTyping ?? false
        ))
    }

    private func handleIncomingScreenshotNotice(envelope: IncomingEnvelope, senderIdentity: Data?) async {
        let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        await insertNotice(
            conversationID: envelope.conversationID,
            text: "\(contact.displayName) took a screenshot"
        )
    }

    /// The LOCAL user took a screenshot: warn the visible conversation if enabled.
    func reportLocalScreenshot() async {
        guard let conversationID = visibleConversationID else { return }
        try? await transport.sendScreenshotNotice(conversationID: conversationID)
        await insertNotice(conversationID: conversationID, text: "You took a screenshot")
    }

    // MARK: - Group join requests

    /// Posted when a join request arrives or the pending list changes.
    /// `object` is the `JoinRequest` for arrivals, nil for list changes.
    private func handleIncomingJoinRequest(_ payload: WirePayload, envelope: IncomingEnvelope) async {
        // The request references the inviter's conversation UUID; it must
        // be one of OUR group/channel conversations, otherwise someone is
        // probing with a forged reference.
        guard let ref = payload.joinGroupReference,
              let conversationID = UUID(uuidString: ref),
              let conversation = try? await store.fetchConversation(id: conversationID),
              conversation.kind == .group || conversation.kind == .channel
        else { return }
        // Revoked invites: a request whose generation predates the current
        // one is declined silently. The revocation itself is a signed event
        // in the group's audit log; legacy codes (no generation) predate
        // revocation and are still honored.
        if let generation = payload.joinInviteGeneration,
           let snapshot = await transport.channelModerationSnapshot(conversationID: conversationID),
           generation != snapshot.inviteGeneration
        {
            return
        }
        let requesterName: String
        if let rawName = payload.joinRequesterName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawName.isEmpty
        {
            requesterName = rawName
        } else {
            requesterName = "Unknown"
        }
        let request = JoinRequest(
            conversationID: conversationID,
            requesterFingerprint: envelope.senderKey,
            requesterName: requesterName
        )
        // De-duplicate: one pending request per requester per group.
        joinRequests.removeAll {
            $0.conversationID == conversationID && $0.requesterFingerprint == envelope.senderKey
        }
        joinRequests.append(request)
        joinRequests.sort { $0.receivedAt < $1.receivedAt }
        NotificationCenter.default.post(name: .aegisJoinRequest, object: request)
        Haptics.notification(.success)
    }

    /// Approves a join request: the requester becomes a contact and is
    /// invited (real invite + sender-key distributions). Only moderators
    /// can approve — the transport throws otherwise.
    func approveJoinRequest(_ request: JoinRequest) async throws {
        try await transport.approveJoinRequest(request)
        joinRequests.removeAll { $0.id == request.id }
        NotificationCenter.default.post(name: .aegisJoinRequest, object: nil)
        await transport.noteLocalAuditEvent(
            kind: .joinRequestApproved,
            conversationID: request.conversationID,
            detail: "Join request from \(request.requesterName) approved."
        )
    }

    /// Declines a join request. Local-only: the requester is simply never
    /// invited (no decline notice is sent — a declined request is
    /// indistinguishable from an unanswered one, which is the honest
    /// privacy posture for an invite-gated group). The decline is still
    /// recorded in the local audit log.
    func declineJoinRequest(_ request: JoinRequest) {
        joinRequests.removeAll { $0.id == request.id }
        NotificationCenter.default.post(name: .aegisJoinRequest, object: nil)
        Task {
            await transport.noteLocalAuditEvent(
                kind: .joinRequestDeclined,
                conversationID: request.conversationID,
                detail: "Join request from \(request.requesterName) declined."
            )
        }
    }

    func joinRequests(for conversationID: UUID) -> [JoinRequest] {
        joinRequests.filter { $0.conversationID == conversationID }
    }

    // MARK: - Message requests (A31)

    /// The pending request for a conversation, if any.
    func messageRequest(for conversationID: UUID) -> MessageRequestItem? {
        messageRequests.first { $0.conversationID == conversationID }
    }

    /// Routes an inbound DM from an unknown identity to the Requests inbox.
    /// The message is stored (never lost) but the conversation is archived
    /// (hidden from the chat list), produces no notification and no unread
    /// bump, is never pushed to the visible thread — and the sender gets no
    /// read receipts, typing indicators, or presence until accepted.
    private func routeToMessageRequests(
        messageID: UUID,
        payload: WirePayload,
        envelope: IncomingEnvelope,
        conversation: Conversation,
        contact: Contact,
        expiresAt: Date?
    ) async {
        var conv = conversation
        let message = Message(
            id: messageID,
            conversationID: conv.id,
            senderID: contact.id,
            isFromMe: false,
            body: payload.body,
            replyToID: payload.replyToID,
            status: .delivered,
            expiresAt: expiresAt,
            attachment: payload.attachment,
            voiceNote: payload.voiceNote,
            sentAt: envelope.receivedAt
        )
        try? await store.saveMessage(message)
        // Archived = hidden from the chat list. The Requests tab owns these
        // conversations until the user accepts (unarchives) or blocks
        // (deletes) them.
        conv.isArchived = true
        conv.lastMessagePreview = previewText(for: message, senderName: nil)
        conv.lastMessageAt = message.sentAt
        conv.lastMessageIsFromMe = false
        try? await store.saveConversation(conv)
        // Seal the presence leak: no receipts/typing/online to the sender.
        await transport.setPresenceSuppressed(true, conversationID: conv.id)

        if var existing = messageRequest(for: conv.id) {
            existing.messageCount += 1
            existing.preview = message.body
            existing.receivedAt = message.sentAt
            messageRequests.removeAll { $0.id == existing.id }
            messageRequests.append(existing)
        } else {
            messageRequests.append(MessageRequestItem(
                conversationID: conv.id,
                senderFingerprint: envelope.senderKey,
                // Placeholders are literally named "Unknown contact" — store
                // an empty name so the inbox falls back to a fingerprint
                // suffix instead.
                senderName: contact.displayName == "Unknown contact" ? "" : contact.displayName,
                preview: message.body,
                receivedAt: message.sentAt
            ))
        }
        messageRequests.sort { $0.receivedAt > $1.receivedAt }
        persistLocalModeration()
        NotificationCenter.default.post(name: .aegisMessageRequests, object: nil)
        Haptics.impact(.light)
    }

    /// Accepts a message request: the conversation joins the chat list and
    /// presence signals resume from now on. Accepting reveals nothing beyond
    /// what the user then chooses to share.
    func acceptMessageRequest(_ item: MessageRequestItem) async {
        messageRequests.removeAll { $0.id == item.id }
        await transport.setPresenceSuppressed(false, conversationID: item.conversationID)
        if var conv = try? await store.fetchConversation(id: item.conversationID) {
            conv.isArchived = false
            try? await store.saveConversation(conv)
        }
        persistLocalModeration()
        NotificationCenter.default.post(name: .aegisMessageRequests, object: nil)
        Haptics.notification(.success)
    }

    /// Blocks the sender of a message request, optionally filing a
    /// local-only report first. Local and silent: the conversation is
    /// deleted, the identity is blocklisted, and nothing is ever sent to
    /// the blocked party — not even a "blocked" notice.
    func blockMessageRequest(
        _ item: MessageRequestItem,
        report: (reason: ReportReason, detail: String?)? = nil
    ) async {
        blocklist.block(item.senderFingerprint)
        if let report {
            reportStore.add(AbuseReport(
                reportedFingerprint: item.senderFingerprint,
                reportedName: item.senderName,
                messagePreview: item.preview,
                reason: report.reason,
                detail: report.detail,
                alsoBlocked: true
            ))
        }
        messageRequests.removeAll { $0.id == item.id }
        try? await store.deleteConversation(id: item.conversationID)
        persistLocalModeration()
        NotificationCenter.default.post(name: .aegisMessageRequests, object: nil)
        Haptics.notification(.success)
    }

    // MARK: - Blocklist & reports (device-local)

    func isBlocked(fingerprint: Data) -> Bool {
        blocklist.isBlocked(fingerprint)
    }

    /// Blocked identities, newest-blocked first (unordered set — sorted by
    /// fingerprint for stable display; names resolve via contacts).
    func blockedFingerprints() -> [Data] {
        blocklist.fingerprints.sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// Blocks a contact's identity. Silent: no signal is emitted.
    func blockContact(_ contact: Contact) {
        if let fp = Self.fingerprint(ofSerializedIdentity: contact.identityKey) {
            blocklist.block(fp)
        } else if !contact.identityKey.isEmpty {
            blocklist.block(contact.identityKey)
        }
        persistLocalModeration()
    }

    func unblock(fingerprint: Data) {
        blocklist.unblock(fingerprint)
        persistLocalModeration()
    }

    func abuseReports() -> [AbuseReport] {
        reportStore.reports.sorted { $0.createdAt > $1.createdAt }
    }

    func reportCount(for fingerprint: Data) -> Int {
        reportStore.reportCount(for: fingerprint)
    }

    // MARK: - Local moderation persistence

    private struct LocalModerationState: Codable {
        var blocklist: LocalBlocklist
        var reports: LocalReportStore
        var requests: [MessageRequestItem]
    }

    private var localModerationURL: URL? {
        guard let base = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ) else { return nil }
        let dir = base.appendingPathComponent("AegisModeration", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("local-moderation.json")
    }

    private func persistLocalModeration() {
        guard let url = localModerationURL else { return }
        let state = LocalModerationState(
            blocklist: blocklist, reports: reportStore, requests: messageRequests
        )
        try? JSONEncoder().encode(state).write(to: url, options: .atomic)
    }

    private func restoreLocalModeration() {
        guard let url = localModerationURL,
              let data = try? Data(contentsOf: url),
              let state = try? JSONDecoder().decode(LocalModerationState.self, from: data)
        else { return }
        blocklist = state.blocklist
        reportStore = state.reports
        messageRequests = state.requests
    }

    // MARK: - Helpers

    /// Find the contact for an identity, creating an unverified placeholder
    /// for unknown senders rather than dropping their messages.
    /// `fingerprint` is the 32-byte identity fingerprint; `fullIdentity` is
    /// the 65-byte serialized public key when known (pre-decrypted
    /// rendezvous). Contacts are matched by fingerprint — `Contact.identityKey`
    /// is the full serialized key, which never equals a bare fingerprint.
    private func resolveContact(for fingerprint: Data, fullIdentity: Data? = nil) async -> Contact {
        if let existing = await contactForFingerprint(fingerprint) {
            return existing
        }
        // Unknown sender: create a placeholder the user can rename / verify / block.
        let placeholder = Contact(
            displayName: "Unknown contact",
            identityKey: fullIdentity ?? fingerprint,
            verification: .unverified
        )
        try? await store.saveContact(placeholder)
        return placeholder
    }

    private func mutateMessage(id: UUID, apply: (inout Message) -> Void) async {
        let conversations = (try? await store.fetchConversations()) ?? []
        for conversation in conversations {
            let messages = (try? await store.fetchMessages(conversationID: conversation.id, limit: 200, before: nil)) ?? []
            if var message = messages.first(where: { $0.id == id }) {
                apply(&message)
                try? await store.updateMessage(message)
                inboundSubject.send(message)
                return
            }
        }
    }

    private func insertNotice(conversationID: UUID, text: String) async {
        guard let me = identity else { return }
        let notice = Message(
            conversationID: conversationID,
            senderID: me.id,
            isFromMe: true,
            body: text,
            status: .read,
            sentAt: Date()
        )
        try? await store.saveMessage(notice)
        inboundSubject.send(notice)
    }

    private func previewText(for message: Message, senderName: String?) -> String {
        let prefix = senderName.map { "\($0): " } ?? ""
        if message.isDeleted { return prefix + "Message deleted" }
        if let poll = message.poll {
            return prefix + "📊 \(poll.question)"
        }
        if let voiceNote = message.voiceNote {
            return prefix + "🎤 Voice note (\(Formatters.duration(voiceNote.duration)))"
        }
        if let attachment = message.attachment {
            return prefix + "📎 \(attachment.filename)"
        }
        return prefix + (message.body ?? "New message")
    }

    // MARK: - Calls

    func answerIncomingCall() async {
        guard let call = incomingCall else { return }
        incomingCall = nil
        do {
            try await transport.answerCall(call.id)
            activeCall = ActiveCall(
                id: call.id,
                contactID: call.contactID,
                contactName: call.contactName,
                kind: call.kind,
                direction: .incoming,
                state: .connecting,
                isMuted: false,
                isSpeakerOn: call.kind == .video,
                isVideoEnabled: call.kind == .video,
                isScreenSharing: false
            )
        } catch {
            await recordCall(call, direction: .incoming, reason: .failed, duration: nil)
        }
    }

    func declineIncomingCall() async {
        guard let call = incomingCall else { return }
        incomingCall = nil
        try? await transport.declineCall(call.id)
        await recordCall(call, direction: .incoming, reason: .declined, duration: nil)
    }

    func placeCall(to contact: Contact, kind: CallKind) async {
        do {
            let callID = try await transport.placeCall(to: contact.id, kind: kind)
            activeCall = ActiveCall(
                id: callID,
                contactID: contact.id,
                contactName: contact.displayName,
                kind: kind,
                direction: .outgoing,
                state: .dialing,
                isMuted: false,
                isSpeakerOn: kind == .video,
                isVideoEnabled: kind == .video,
                isScreenSharing: false
            )
        } catch {
            await recordCall(
                IncomingCall(id: UUID(), contactID: contact.id, contactName: contact.displayName, kind: kind, receivedAt: Date()),
                direction: .outgoing,
                reason: .failed,
                duration: nil
            )
        }
    }

    func endActiveCall() async {
        guard let call = activeCall else { return }
        try? await transport.endCall(call.id)
        let duration = call.connectedAt.map { Date().timeIntervalSince($0) }
        await recordCall(
            IncomingCall(id: call.id, contactID: call.contactID, contactName: call.contactName, kind: call.kind, receivedAt: Date()),
            direction: call.direction,
            reason: .completed,
            duration: duration
        )
        activeCall = nil
    }

    private func applyCallEvent(_ event: CallStateEvent) async {
        await MainActor.run {
            if event.state == .ended {
                if activeCall?.id == event.callID { activeCall = nil }
                incomingCall = nil
            } else if activeCall?.id == event.callID {
                activeCall?.state = event.state
                if let sas = event.sas {
                    activeCall?.callSAS = sas
                }
                if event.state == .connected, activeCall?.connectedAt == nil {
                    activeCall?.connectedAt = Date()
                }
            }
        }
    }

    private func recordCall(_ call: IncomingCall, direction: CallDirection, reason: CallEndReason, duration: TimeInterval?) async {
        let record = CallRecord(
            id: call.id,
            contactID: call.contactID,
            contactName: call.contactName,
            kind: call.kind,
            direction: direction,
            startedAt: call.receivedAt,
            duration: duration,
            endReason: reason
        )
        try? await store.saveCallRecord(record)
    }

    // MARK: - Voice rooms

    /// The currently joined voice room (nil when not in one).
    @Published private(set) var voiceRoomState: VoiceRoom?

    func startVoiceRoomListeners() {
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await event in await self.voiceRoom.events {
                switch event {
                case .updated(let room):
                    self.voiceRoomState = room
                case .speakingChanged:
                    break // carried by the .updated snapshot as well
                case .cameraPermissionDenied:
                    self.voiceRoomCameraDeniedAlert = true
                }
            }
        }
    }

    /// Set when the OS denies camera access mid-room; the UI shows a
    /// rationale alert with a Settings link.
    @Published var voiceRoomCameraDeniedAlert = false

    func joinVoiceRoom(_ conversation: Conversation) async {
        voiceRoomCameraDeniedAlert = false
        await voiceRoom.joinRoom(conversationID: conversation.id, groupName: conversation.title)
    }

    func leaveVoiceRoom() async {
        await voiceRoom.leaveRoom()
    }

    func retryVoiceRoomJoin() async {
        await voiceRoom.retryJoin()
    }

    func setVoiceRoomMuted(_ muted: Bool) async {
        await voiceRoom.setMuted(muted)
    }

    func setVoiceRoomDeafened(_ deafened: Bool) async {
        await voiceRoom.setDeafened(deafened)
    }

    func setVoiceRoomCameraEnabled(_ enabled: Bool) async {
        await voiceRoom.setCameraEnabled(enabled)
    }

    func setVoiceRoomParticipantVolume(fingerprintHex: String, volume: Float) async {
        await voiceRoom.setParticipantVolume(fingerprintHex: fingerprintHex, volume: volume)
    }

    func setVoiceRoomMode(_ mode: VoiceRoomMode) async {
        await voiceRoom.setRoomMode(mode)
    }

    func raiseVoiceRoomHand(_ raised: Bool) async {
        await voiceRoom.raiseHand(raised)
    }

    func setVoiceRoomSpeakerApproval(fingerprintHex: String, approved: Bool) async {
        await voiceRoom.setSpeakerApproval(fingerprintHex: fingerprintHex, approved: approved)
    }

    func attachVoiceRoomLocalPreview(_ renderer: RTCVideoRenderer) async {
        await voiceRoom.attachLocalPreview(renderer)
    }

    func detachVoiceRoomLocalPreview(_ renderer: RTCVideoRenderer) async {
        await voiceRoom.detachLocalPreview(renderer)
    }

    // MARK: - Linked devices

    /// Devices linked to this one (primary: secondaries; secondary: primary).
    @Published private(set) var linkedDevices: [DeviceInfo] = []
    /// True when this device is a linked secondary relaying via its primary.
    @Published private(set) var isLinkedDevice = false
    /// QR payload for the in-progress primary pairing attempt.
    @Published var pairingQRPayload: String?
    /// SAS words to display (primary: after the new device scans; secondary:
    /// immediately after scanning).
    @Published var pairingSASWords: [String]?
    /// Primary-side outbound blob syncs (this device → linked devices),
    /// for the Linked devices settings screen.
    @Published private(set) var linkedSyncProgress: [DeviceSyncProgress] = []

    /// Records one outbound blob-sync progress event (primary side).
    /// Completed/failed rows linger briefly so the user sees the outcome,
    /// then are removed.
    private func noteLinkedSyncProgress(_ progress: DeviceSyncProgress) {
        if let idx = linkedSyncProgress.firstIndex(where: { $0.id == progress.id }) {
            linkedSyncProgress[idx] = progress
        } else {
            linkedSyncProgress.append(progress)
        }
        switch progress.state {
        case .streaming:
            break
        case .done, .failed:
            let id = progress.id
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                self?.linkedSyncProgress.removeAll { $0.id == id }
            }
        }
    }

    func startDeviceLinkListeners() {
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.isLinkedDevice = await self.deviceLink.isLinkedDevice()
            self.linkedDevices = await self.deviceLink.linkedDevices()
            if self.isLinkedDevice {
                // Rebuild in-flight blob reassembly after the paired
                // channel rebinds (app launch). No auto-download: waiters
                // resume, everything else waits for the next tap.
                await self.blobRelay.resumeIncomplete()
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await event in await self.deviceLink.pairingEvents {
                switch event {
                case .sasReady(let words):
                    self.pairingSASWords = words
                case .aborted:
                    self.pairingQRPayload = nil
                    self.pairingSASWords = nil
                case .provisioned:
                    self.pairingQRPayload = nil
                    self.pairingSASWords = nil
                    self.isLinkedDevice = await self.deviceLink.isLinkedDevice()
                    self.linkedDevices = await self.deviceLink.linkedDevices()
                    // Fresh secondary finishing pairing during onboarding:
                    // enter the main UI now that provisioning is applied.
                    if self.phase == .onboarding {
                        self.enterLinkedMain()
                    }
                }
            }
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for await (message, fromDevice) in await self.deviceLink.syncEvents {
                await self.handleDeviceSync(message, fromDevice: fromDevice)
            }
        }
    }

    func refreshLinkedDevices() async {
        linkedDevices = await deviceLink.linkedDevices()
        isLinkedDevice = await deviceLink.isLinkedDevice()
    }

    // MARK: Pairing orchestration

    /// Primary: starts pairing and returns the QR payload to display.
    func beginPrimaryPairing() async throws -> String {
        let ctx = try await deviceLink.beginPairingAsPrimary()
        pairingQRPayload = ctx.qrPayload
        pairingSASWords = nil
        return ctx.qrPayload
    }

    func cancelPairing() async {
        await deviceLink.cancelPairing()
        pairingQRPayload = nil
        pairingSASWords = nil
    }

    /// Primary: the user confirmed the SAS words match. Builds the
    /// provisioning bundle from the local store and sends it sealed.
    func confirmPairing() async throws {
        let bundle = await buildProvisioningBundle()
        try await deviceLink.confirmPairing(provisioning: bundle)
        pairingQRPayload = nil
        pairingSASWords = nil
        await refreshLinkedDevices()
    }

    /// Secondary: scans the QR, sends hello, returns SAS words to display.
    func beginSecondaryPairing(qrPayload: String) async throws -> [String] {
        let name = "\(UIDevice.current.model) (\(UIDevice.current.systemVersion))"
        let words = try await deviceLink.beginPairingAsSecondary(qrPayload: qrPayload, deviceName: name)
        pairingSASWords = words
        return words
    }

    func unpairDevice(_ device: DeviceInfo) async {
        await deviceLink.unpair(deviceID: device.deviceID)
        // Drop in-flight blob sync state (staged bytes, manifests). Channel
        // keys are wiped by DeviceLinkManager; already-synced files stay —
        // unpairing cannot remote-wipe (stated in the UI).
        await blobRelay.dropAll()
        await refreshLinkedDevices()
    }

    // MARK: Provisioning (primary builds, secondary applies)

    private func buildProvisioningBundle() async -> ProvisioningBundle {
        let contacts = (try? await store.fetchContacts()) ?? []
        let conversations = (try? await store.fetchConversations()) ?? []
        var recent: [String: [LinkedMessage]] = [:]
        for conv in conversations.prefix(50) {
            let messages = (try? await store.fetchMessages(conversationID: conv.id, limit: 50, before: nil)) ?? []
            recent[conv.id.uuidString] = messages.map { $0.asLinked() }
        }
        let myID = await deviceLink.localDeviceID()
        return ProvisioningBundle(
            primaryDeviceID: myID,
            primaryDeviceName: "\(UIDevice.current.model)",
            displayName: identity?.displayName ?? "Aegis user",
            contacts: contacts.map {
                LinkedContact(id: $0.id, displayName: $0.displayName, fingerprintHex: $0.identityKey.hexString)
            },
            conversations: conversations.map {
                LinkedConversation(
                    id: $0.id, title: $0.title, kind: "\($0.kind)",
                    lastMessagePreview: $0.lastMessagePreview,
                    lastMessageAt: $0.lastMessageAt,
                    unreadCount: $0.unreadCount
                )
            },
            recentMessages: recent,
            assignedDevice: DeviceInfo(
                deviceID: UUID(),
                deviceName: "Linked device",
                deviceModel: nil,
                pairedAt: Date(),
                lastSeen: Date()
            )
        )
    }

    private func applyProvisioningBundle(_ bundle: ProvisioningBundle) async {
        // The secondary adopts the primary's roster. Contacts and
        // conversations are upserted; recent messages fill the threads.
        // Identity keys are public material already known to the account.
        UserDefaults.standard.set(bundle.displayName, forKey: "aegis.linkedDisplayName")
        for lc in bundle.contacts {
            let contact = Contact(
                id: lc.id,
                displayName: lc.displayName,
                identityKey: Data(hexString: lc.fingerprintHex) ?? Data(),
                verification: .unverified,
                isBlocked: false,
                lastSeenAt: nil,
                notes: nil
            )
            try? await store.saveContact(contact)
        }
        for lconv in bundle.conversations {
            var conv = Conversation(
                id: lconv.id,
                kind: ConversationKind(linkedString: lconv.kind),
                title: lconv.title
            )
            conv.lastMessagePreview = lconv.lastMessagePreview
            conv.lastMessageAt = lconv.lastMessageAt
            conv.unreadCount = lconv.unreadCount
            try? await store.saveConversation(conv)
            for lm in bundle.recentMessages[lconv.id.uuidString] ?? [] {
                try? await store.saveMessage(lm.asMessage())
            }
        }
    }

    // MARK: Paired-channel sync

    private func handleDeviceSync(_ message: DeviceSyncMessage, fromDevice: UUID) async {
        switch message.kind {
        case .provisioningApplied:
            if let bundle = try? JSONDecoder().decode(ProvisioningBundle.self, from: message.body) {
                await applyProvisioningBundle(bundle)
            }
        case .incomingMessage:
            // A new message on the primary (received or sent): upsert it.
            if let incoming = try? JSONDecoder().decode(LinkedIncomingMessage.self, from: message.body) {
                try? await store.saveMessage(incoming.message.asMessage())
                if let conv = incoming.conversation {
                    if var existing = try? await store.fetchConversation(id: conv.id) {
                        existing.lastMessagePreview = conv.lastMessagePreview
                        existing.lastMessageAt = conv.lastMessageAt
                        try? await store.saveConversation(existing)
                    } else {
                        var created = Conversation(id: conv.id, kind: ConversationKind(linkedString: conv.kind), title: conv.title)
                        created.lastMessagePreview = conv.lastMessagePreview
                        created.lastMessageAt = conv.lastMessageAt
                        try? await store.saveConversation(created)
                    }
                }
                inboundSubject.send(incoming.message.asMessage())
            }
        case .messageStatus:
            if let status = try? JSONDecoder().decode(LinkedMessageStatus.self, from: message.body),
               let msgs = try? await store.fetchMessages(conversationID: status.conversationID, limit: 200, before: nil),
               var msg = msgs.first(where: { $0.id == status.messageID })
            {
                msg.status = MessageStatus(rawValue: status.status) ?? .sent
                try? await store.updateMessage(msg)
            }
        case .sendMessage:
            // Primary only: the linked device asks us to send a message.
            guard !isLinkedDevice else { return }
            if let req = try? JSONDecoder().decode(LinkedSendRequest.self, from: message.body) {
                await sendLinkedDeviceMessage(req)
            }
        case .unpair:
            await deviceLink.unpair(deviceID: fromDevice)
            await blobRelay.dropAll()
            await refreshLinkedDevices()
        case .heartbeat:
            await refreshLinkedDevices()
        case .attachmentManifest:
            // Primary → linked only: a blob is available for download.
            guard isLinkedDevice else { return }
            if let manifest = try? JSONDecoder().decode(LinkedBlobManifest.self, from: message.body) {
                await blobRelay.noteManifest(manifest)
            }
        case .attachmentChunk:
            // Primary → linked only: one indexed ciphertext chunk.
            guard isLinkedDevice else { return }
            if let chunk = try? JSONDecoder().decode(LinkedBlobChunk.self, from: message.body) {
                await blobRelay.ingest(chunk)
            }
        case .attachmentRequest:
            // Linked → primary only: serve (or re-offer) this blob.
            guard !isLinkedDevice else { return }
            if let req = try? JSONDecoder().decode(LinkedBlobRequest.self, from: message.body) {
                await handleLinkedBlobRequest(req, fromDevice: fromDevice)
            }
        case .attachmentFailure:
            // Primary → linked only: the blob can't be served.
            guard isLinkedDevice else { return }
            if let failure = try? JSONDecoder().decode(LinkedBlobFailure.self, from: message.body) {
                await blobRelay.noteFailure(failure)
            }
        }
    }

    /// Primary: sends a message on behalf of a linked device through the
    /// normal E2EE path, then forwards the sent message back so the linked
    /// device's thread matches.
    private func sendLinkedDeviceMessage(_ req: LinkedSendRequest) async {
        guard let me = identity,
              let conversation = try? await store.fetchConversation(id: req.conversationID)
        else { return }
        let message = Message(
            id: req.messageID,
            conversationID: req.conversationID,
            senderID: me.id,
            isFromMe: true,
            body: req.body,
            replyToID: req.replyToID,
            status: .sending,
            expiresAt: conversation.disappearingInterval.map { Date().addingTimeInterval($0) },
            attachment: nil,
            voiceNote: nil,
            sentAt: Date()
        )
        try? await store.saveMessage(message)
        var mutableMessage = message
        do {
            var payload = WirePayload.text(
                id: req.messageID,
                body: req.body,
                replyToID: req.replyToID,
                quote: nil,
                threadRootID: nil,
                attachment: nil,
                voiceNote: nil,
                expiresIn: conversation.disappearingInterval,
                disappearAfterRead: nil
            )
            payload.previousFingerprint = await crypto.supersededIdentityFingerprint()
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: req.conversationID,
                recipientKeys: await recipientKeys(for: conversation, excluding: me.id)
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: req.messageID,
                conversationID: req.conversationID,
                ciphertext: ciphertext,
                kind: .message
            ))
            mutableMessage.status = .sent
        } catch {
            mutableMessage.status = .failed
        }
        try? await store.updateMessage(mutableMessage)
        // Echo back to the linked device so its thread shows the message.
        let linked = LinkedIncomingMessage(
            message: mutableMessage.asLinked(senderName: me.displayName),
            conversation: LinkedConversation(
                id: conversation.id, title: conversation.title, kind: "\(conversation.kind)",
                lastMessagePreview: req.body, lastMessageAt: mutableMessage.sentAt, unreadCount: 0
            )
        )
        if let body = try? JSONEncoder().encode(linked) {
            try? await deviceLink.sendSync(kind: .incomingMessage, body: body)
        }
    }

    /// Forwards a newly sent/received message to linked devices (primary).
    func forwardToLinkedDevices(_ message: Message, conversation: Conversation, senderName: String?) async {
        guard !isLinkedDevice else { return }
        let linked = LinkedIncomingMessage(
            message: message.asLinked(senderName: senderName),
            conversation: LinkedConversation(
                id: conversation.id, title: conversation.title, kind: "\(conversation.kind)",
                lastMessagePreview: message.body, lastMessageAt: message.sentAt, unreadCount: 0
            )
        )
        guard let body = try? JSONEncoder().encode(linked) else { return }
        try? await deviceLink.sendSync(kind: .incomingMessage, body: body)
        // Attachments / voice notes: the linked device has no conversation
        // keys, so it can never fetch from the relay itself — offer the
        // blobs over the paired channel. Detached: staging ciphertext must
        // not delay the message forward.
        Task {
            await blobRelay.offerBlobs(for: message)
        }
    }

    /// Linked device: sends a text message via the primary.
    func sendAsLinkedDevice(conversationID: UUID, body: String, replyToID: UUID?) async throws {
        let req = LinkedSendRequest(
            conversationID: conversationID,
            body: body,
            replyToID: replyToID,
            messageID: UUID()
        )
        try await deviceLink.sendSync(kind: .sendMessage, body: JSONEncoder().encode(req))
    }

    // MARK: - Linked-device blob sync

    /// Primary: a linked device wants a blob. Serves it, rebuilds the
    /// offer when the device missed the manifest (offline past the paired
    /// mailbox TTL), or fails honestly when the message/blob is gone.
    private func handleLinkedBlobRequest(_ req: LinkedBlobRequest, fromDevice: UUID) async {
        switch await blobRelay.serve(req, to: fromDevice) {
        case .served, .failed:
            break
        case .unknownTransfer:
            let messages = (try? await store.fetchMessages(
                conversationID: req.conversationID, limit: 200, before: nil)) ?? []
            if let message = messages.first(where: { $0.id == req.messageID }) {
                await blobRelay.offerBlobs(for: message, to: fromDevice)
                _ = await blobRelay.serve(req, to: fromDevice)
            } else {
                let failure = LinkedBlobFailure(
                    transferID: req.transferID,
                    attachmentID: req.attachmentID,
                    reason: "This file is no longer available."
                )
                if let body = try? JSONEncoder().encode(failure) {
                    try? await deviceLink.sendSync(to: fromDevice, kind: .attachmentFailure, body: body)
                }
            }
        }
    }

    /// Linked device: the blob manifest for a known attachment, when its
    /// offer arrived over the paired channel (nil when the offer was
    /// missed — the download path asks the primary to re-offer).
    func linkedBlobManifest(for attachmentID: UUID) async -> LinkedBlobManifest? {
        await blobRelay.manifest(for: attachmentID)
    }

    /// Linked device: downloads a blob over the paired channel. The stream
    /// yields progress, then `.done` (decrypted file URL) or `.failed`
    /// (human-readable; the UI offers a retry, which resumes from the
    /// first missing chunk). The primary must be reachable — an
    /// unreachable primary surfaces as `.failed`, never a silent stall.
    func downloadLinkedBlob(manifest: LinkedBlobManifest) async -> AsyncStream<LinkedDownloadEvent> {
        await blobRelay.download(manifest)
    }

    /// Linked device: download when the manifest offer was missed (this
    /// device was offline, or the primary couldn't stage the blob at
    /// forward time). The primary re-offers from the stored message; the
    /// stream starts when the manifest arrives, or fails honestly.
    func downloadLinkedBlobBlind(
        attachmentID: UUID,
        messageID: UUID,
        conversationID: UUID
    ) async -> AsyncStream<LinkedDownloadEvent> {
        await blobRelay.downloadBlind(
            attachmentID: attachmentID, messageID: messageID, conversationID: conversationID)
    }

    /// Recipient identity keys for a conversation (DM peer or group members).
    private func recipientKeys(for conversation: Conversation, excluding senderID: UUID? = nil) async -> [Data] {
        let contacts = (try? await store.fetchContacts()) ?? []
        if conversation.kind == .direct {
            let peerID = conversation.memberIDs.first { $0 != senderID }
            let peerKey = peerID.flatMap { id in contacts.first(where: { $0.id == id })?.identityKey }
            return peerKey.map { [$0] } ?? []
        }
        return conversation.memberIDs.compactMap { id in
            contacts.first { $0.id == id }?.identityKey
        }
    }
}

private extension ConversationKind {
    init(linkedString: String) {
        switch linkedString {
        case "group": self = .group
        case "channel": self = .channel
        default: self = .direct
        }
    }
}

// MARK: - Linked-device model bridges

private extension Message {
    func asLinked(senderName: String? = nil) -> LinkedMessage {
        // Device-link v1 carries text only: polls degrade to a readable
        // placeholder on the linked device rather than a blank bubble.
        let linkedBody = body ?? poll.map { "📊 \($0.question)" }
        return LinkedMessage(
            id: id,
            conversationID: conversationID,
            body: linkedBody,
            replyToID: replyToID,
            isFromMe: isFromMe,
            senderName: senderName,
            status: status.rawValue,
            sentAt: sentAt,
            expiresAt: expiresAt,
            attachment: attachment.map {
                LinkedAttachmentMeta(
                    id: $0.id,
                    filename: $0.filename,
                    mimeType: $0.mimeType,
                    byteCount: $0.byteCount,
                    thumbnailData: $0.thumbnailData
                )
            },
            voiceNote: voiceNote.map {
                LinkedVoiceNoteMeta(
                    id: $0.id,
                    duration: $0.duration,
                    levels: $0.levels,
                    transcript: $0.transcript
                )
            }
        )
    }
}

private extension LinkedMessage {
    func asMessage() -> Message {
        Message(
            id: id,
            conversationID: conversationID,
            senderID: UUID(),
            isFromMe: isFromMe,
            body: body,
            replyToID: replyToID,
            status: MessageStatus(rawValue: status) ?? .delivered,
            expiresAt: expiresAt,
            // The linked device never gets wrappedKey/remoteLocator: it has
            // no conversation keys and no relay access. Blobs arrive via
            // the paired blob-transfer protocol instead.
            attachment: attachment.map {
                Attachment(
                    id: $0.id,
                    filename: $0.filename,
                    mimeType: $0.mimeType,
                    byteCount: $0.byteCount,
                    thumbnailData: $0.thumbnailData
                )
            },
            voiceNote: voiceNote.map {
                VoiceNote(
                    id: $0.id,
                    duration: $0.duration,
                    levels: $0.levels,
                    transcript: $0.transcript
                )
            },
            sentAt: sentAt
        )
    }
}
