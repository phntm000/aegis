import AegisCrypto
import Combine
import Foundation
import UIKit

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

    /// The conversation currently on screen (for screenshot notices, read receipts).
    var visibleConversationID: UUID?

    // MARK: - Services

    let crypto: any CryptoService
    let transport: any TransportService
    let store: any StoreService

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

    // MARK: - Init

    init(factory: any ServiceFactory) {
        self.crypto = factory.makeCrypto()
        self.transport = factory.makeTransport()
        self.store = factory.makeStore()
        self.appLock = AppLockManager()
        self.privacy = PrivacyController()
        self.notifications = NotificationManager()
        self.privacy.attach(appState: self)
        self.appLock.refreshBiometry()
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
        }
        await notifications.refreshStatus()

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
                self.connectionState = state
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
                await handleIncomingEdit(payload)
            case .delete:
                await handleIncomingDelete(payload)
            case .readReceipt:
                await handleIncomingReadReceipt(payload, from: envelope.senderKey)
            case .typing:
                await handleIncomingTyping(payload, envelope: envelope, senderIdentity: fullSenderIdentity)
            case .screenshotNotice:
                await handleIncomingScreenshotNotice(envelope: envelope, senderIdentity: fullSenderIdentity)
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
        // Already flagged for this exact new identity: not a new change —
        // the pending check below holds the message.
        if let pending = await transport.pendingIdentityChange(for: conversationID),
           pending.newFingerprint == senderFP
        {
            return false
        }
        // The contact this conversation belongs to: the hinted previous
        // identity when the sender rotated, else the expected route peer
        // (covers prekeys arriving on an established peer's route).
        let contactFP = supersedes ?? expectedFingerprint
        guard let contact = await contactForFingerprint(contactFP),
              let storedFP = Self.fingerprint(ofSerializedIdentity: contact.identityKey),
              storedFP != senderFP
        else { return false }
        // The authenticated sender differs from the contact's stored key:
        // flag the contact, banner the conversation, and hold the message.
        var updated = contact
        updated.verification = .identityChanged
        try? await store.saveContact(updated)
        await transport.noteIdentityChange(
            PendingIdentityChange(
                previousFingerprint: storedFP,
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

    /// Whether display is currently paused for this conversation: a pending
    /// identity change whose new identity matches the sender.
    private func isIdentityChangePending(for conversationID: UUID, senderIdentity: Data) async -> Bool {
        guard let senderFP = Self.fingerprint(ofSerializedIdentity: senderIdentity),
              let pending = await transport.pendingIdentityChange(for: conversationID)
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
    private static func fingerprint(ofSerializedIdentity data: Data) -> Data? {
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

    private func handleIncomingText(_ payload: WirePayload, envelope: IncomingEnvelope, senderIdentity: Data?) async {
        guard var conversation = try? await store.fetchConversation(id: envelope.conversationID) else { return }
        let contact = await resolveContact(for: envelope.senderKey, fullIdentity: senderIdentity)
        let expiresAt = payload.expiresIn.map { Date().addingTimeInterval($0) }

        let message = Message(
            conversationID: conversation.id,
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

    private func handleIncomingEdit(_ payload: WirePayload) async {
        guard let target = payload.targetMessageID, let editedBody = payload.editedBody else { return }
        await mutateMessage(id: target) { message in
            message.body = editedBody
            message.editedAt = Date()
        }
    }

    private func handleIncomingDelete(_ payload: WirePayload) async {
        guard let target = payload.targetMessageID else { return }
        await mutateMessage(id: target) { message in
            message.body = nil
            message.attachment = nil
            message.voiceNote = nil
            message.deletedAt = Date()
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
}
