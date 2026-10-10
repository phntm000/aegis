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
            let plaintext = try await crypto.decryptMessage(
                envelope.ciphertext,
                conversationID: envelope.conversationID,
                senderKey: envelope.senderKey
            )
            let payload = try WirePayload.decoded(from: plaintext)
            switch payload.kind {
            case .text:
                await handleIncomingText(payload, envelope: envelope)
            case .reaction:
                await handleIncomingReaction(payload, envelope: envelope)
            case .edit:
                await handleIncomingEdit(payload)
            case .delete:
                await handleIncomingDelete(payload)
            case .readReceipt:
                await handleIncomingReadReceipt(payload, from: envelope.senderKey)
            case .typing:
                await handleIncomingTyping(payload, envelope: envelope)
            case .screenshotNotice:
                await handleIncomingScreenshotNotice(envelope: envelope)
            }
        } catch {
            // Corrupt or undecryptable envelope: drop it loudly in debug, silently
            // in production. Never crash the listener loop.
            #if DEBUG
            print("[Aegis] Dropping undecryptable envelope: \(error)")
            #endif
        }
    }

    private func handleIncomingText(_ payload: WirePayload, envelope: IncomingEnvelope) async {
        guard var conversation = try? await store.fetchConversation(id: envelope.conversationID) else { return }
        let contact = await resolveContact(for: envelope.senderKey)
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

    private func handleIncomingReaction(_ payload: WirePayload, envelope: IncomingEnvelope) async {
        guard let target = payload.targetMessageID, let emoji = payload.emoji else { return }
        let reactor = await resolveContact(for: envelope.senderKey)
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

    private func handleIncomingTyping(_ payload: WirePayload, envelope: IncomingEnvelope) async {
        let contact = await resolveContact(for: envelope.senderKey)
        typingSubject.send(TypingEvent(
            conversationID: envelope.conversationID,
            contactID: contact.id,
            displayName: contact.displayName,
            isTyping: payload.isTyping ?? false
        ))
    }

    private func handleIncomingScreenshotNotice(envelope: IncomingEnvelope) async {
        let contact = await resolveContact(for: envelope.senderKey)
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

    /// Find the contact for an identity key, creating an unverified placeholder
    /// for unknown senders rather than dropping their messages.
    private func resolveContact(for identityKey: Data) async -> Contact {
        let contacts = (try? await store.fetchContacts()) ?? []
        if let existing = contacts.first(where: { $0.identityKey == identityKey }) {
            return existing
        }
        // Unknown sender: create a placeholder the user can rename / verify / block.
        let placeholder = Contact(
            displayName: "Unknown contact",
            identityKey: identityKey,
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
