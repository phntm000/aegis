import Combine
import Foundation
import UIKit

/// Drives a single conversation thread: loading, sending (text / attachments /
/// voice notes), reactions, edits, deletes, typing indicators, read receipts,
/// and disappearing-message timers. All network payloads go through
/// encrypt → envelope → transport; the store is updated optimistically.
@MainActor
final class ConversationViewModel: ObservableObject {
    // MARK: - Published UI state

    /// Oldest-first, for the thread view.
    @Published private(set) var messages: [Message] = []
    @Published var draft = ""
    @Published private(set) var isLoading = true
    @Published private(set) var isLoadingMore = false
    @Published var loadError: String?
    @Published var sendError: String?
    @Published var typingNames: [String] = []
    @Published var replyingTo: Message?
    @Published var editingMessage: Message?
    @Published var transfers: [UUID: TransferState] = [:]
    @Published var messageForInfo: Message?
    @Published private(set) var contactsByID: [UUID: Contact] = [:]
    /// Set while the peer's identity change is unverified: the banner shows
    /// and new peer messages are held (not rendered) until resolve.
    @Published private(set) var pendingIdentityChange: PendingIdentityChange?

    @Published private(set) var conversation: Conversation

    let contact: Contact?

    /// The contact as currently known (refreshes when flagged), for
    /// verification UI.
    var displayContact: Contact? {
        guard let contact else { return nil }
        return contactsByID[contact.id] ?? contact
    }

    /// Messages rendered in the thread: while an identity change is pending
    /// (and not dismissed), peer messages at/after detection are held back
    /// until the user re-verifies or explicitly dismisses.
    var visibleMessages: [Message] {
        guard let pending = pendingIdentityChange, !pending.dismissed else { return messages }
        return messages.filter { $0.isFromMe || $0.sentAt < pending.detectedAt }
    }

    // MARK: - Private

    private let appState: AppState
    private var cancellables = Set<AnyCancellable>()
    private var typingClearTasks: [UUID: Task<Void, Never>] = [:]
    private var hasMore = true
    private let pageSize = 60

    private var crypto: any CryptoService { appState.crypto }
    private var transport: any TransportService { appState.transport }
    private var store: any StoreService { appState.store }

    init(conversation: Conversation, contact: Contact?, appState: AppState) {
        self.conversation = conversation
        self.contact = contact
        self.appState = appState
    }

    // MARK: - Lifecycle

    func onAppear() {
        appState.visibleConversationID = conversation.id
        subscribeToTyping()
        subscribeToInbound()
        Task { @MainActor in
            await load()
            await markAsRead()
            await refreshIdentityChangeState()
        }
    }

    func onDisappear() {
        if appState.visibleConversationID == conversation.id {
            appState.visibleConversationID = nil
        }
        sendTyping(false)
        cancellables.removeAll()
    }

    func refreshConversation() async {
        if let updated = try? await store.fetchConversation(id: conversation.id) {
            conversation = updated
        }
    }

    // MARK: - Loading

    func load() async {
        isLoading = true
        loadError = nil
        defer { isLoading = false }
        do {
            let newestFirst = try await store.fetchMessages(
                conversationID: conversation.id,
                limit: pageSize,
                before: nil
            )
            messages = newestFirst.reversed()
            hasMore = newestFirst.count >= pageSize
            let contacts = try await store.fetchContacts()
            contactsByID = Dictionary(uniqueKeysWithValues: contacts.map { ($0.id, $0) })
            // Drop any that expired while we were away.
            _ = try? await store.purgeExpiredMessages()
        } catch {
            loadError = error.localizedDescription
        }
    }

    /// Display name for a message sender (groups show names on incoming bubbles).
    func senderName(for message: Message) -> String? {
        guard !message.isFromMe, conversation.kind != .direct else { return nil }
        if let contact = contactsByID[message.senderID] {
            return contact.displayName
        }
        return nil
    }

    func loadMore() async {
        guard !isLoadingMore, hasMore, let oldest = messages.first else { return }
        isLoadingMore = true
        defer { isLoadingMore = false }
        do {
            let newestFirst = try await store.fetchMessages(
                conversationID: conversation.id,
                limit: pageSize,
                before: oldest.sentAt
            )
            messages = newestFirst.reversed() + messages
            hasMore = newestFirst.count >= pageSize
        } catch {
            loadError = error.localizedDescription
        }
    }

    /// Insert or update a message pushed from outside (inbound listener, edits).
    func upsert(_ message: Message) {
        if let idx = messages.firstIndex(where: { $0.id == message.id }) {
            messages[idx] = message
        } else {
            messages.append(message)
        }
    }

    func message(withId id: UUID) -> Message? {
        messages.first { $0.id == id }
    }

    // MARK: - Sending

    var canSend: Bool {
        conversation.canSend && appState.connectionState.canSend
    }

    func send() async {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, canSend else { return }
        let replyToID = replyingTo?.id
        draft = ""
        replyingTo = nil
        await sendText(body: text, replyToID: replyToID, attachment: nil, voiceNote: nil)
    }

    private func sendText(
        body: String?,
        replyToID: UUID?,
        attachment: Attachment?,
        voiceNote: VoiceNote?
    ) async {
        guard let me = appState.identity else { return }
        // Linked secondary: relay the send through the primary device.
        if appState.isLinkedDevice, attachment == nil, voiceNote == nil {
            await sendTextViaPrimary(body: body, replyToID: replyToID, senderID: me.id)
            return
        }
        let messageID = UUID()
        let expiresAt = conversation.disappearingInterval.map { Date().addingTimeInterval($0) }

        var message = Message(
            conversationID: conversation.id,
            senderID: me.id,
            isFromMe: true,
            body: body,
            replyToID: replyToID,
            status: .sending,
            expiresAt: expiresAt,
            attachment: attachment,
            voiceNote: voiceNote,
            sentAt: Date()
        )
        try? await store.saveMessage(message)
        upsert(message)
        Haptics.impact(.light)

        do {
            var payload = WirePayload.text(
                id: messageID,
                body: body,
                replyToID: replyToID,
                attachment: attachment,
                voiceNote: voiceNote,
                expiresIn: conversation.disappearingInterval
            )
            // Identity-rotation hint (encrypted): lets the recipient link our
            // new identity to the previous one and show "safety number
            // changed" instead of an unknown sender.
            payload.previousFingerprint = await crypto.supersededIdentityFingerprint()
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: conversation.id,
                recipientKeys: await recipientKeys()
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: messageID,
                conversationID: conversation.id,
                ciphertext: ciphertext,
                kind: .message
            ))
            message.status = .sent
        } catch {
            message.status = .failed
            sendError = error.localizedDescription
            Haptics.notification(.error)
        }
        try? await store.updateMessage(message)
        upsert(message)
        await updateConversationPreview(for: message)
        // Primary: mirror the sent message to linked devices.
        if message.status == .sent {
            await appState.forwardToLinkedDevices(message, conversation: conversation, senderName: nil)
        }
    }

    /// Linked-device send path: the message is saved locally and handed to
    /// the primary over the paired channel; the primary's echo (via sync)
    /// flips it to `.sent`.
    private func sendTextViaPrimary(body: String?, replyToID: UUID?, senderID: UUID) async {
        let text = body ?? ""
        var message = Message(
            conversationID: conversation.id,
            senderID: senderID,
            isFromMe: true,
            body: text,
            replyToID: replyToID,
            status: .sending,
            expiresAt: conversation.disappearingInterval.map { Date().addingTimeInterval($0) },
            attachment: nil,
            voiceNote: nil,
            sentAt: Date()
        )
        try? await store.saveMessage(message)
        upsert(message)
        do {
            try await appState.sendAsLinkedDevice(
                conversationID: conversation.id,
                body: text,
                replyToID: replyToID
            )
            // The primary echoes the sent message back over sync; until
            // then it stays `.sending` (honest pending state).
        } catch {
            message.status = .failed
            sendError = error.localizedDescription
            try? await store.updateMessage(message)
            upsert(message)
        }
        await updateConversationPreview(for: message)
    }

    func retrySend(_ message: Message) async {
        guard message.isFromMe, message.status == .failed else { return }
        var retried = message
        retried.status = .sending
        try? await store.updateMessage(retried)
        upsert(retried)
        do {
            var payload = WirePayload.text(
                id: retried.id,
                body: retried.body,
                replyToID: retried.replyToID,
                attachment: retried.attachment,
                voiceNote: retried.voiceNote,
                expiresIn: conversation.disappearingInterval
            )
            payload.previousFingerprint = await crypto.supersededIdentityFingerprint()
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: conversation.id,
                recipientKeys: await recipientKeys()
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: retried.id,
                conversationID: conversation.id,
                ciphertext: ciphertext,
                kind: .message
            ))
            retried.status = .sent
            sendError = nil
        } catch {
            retried.status = .failed
            sendError = error.localizedDescription
        }
        try? await store.updateMessage(retried)
        upsert(retried)
    }

    // MARK: - Attachments

    /// An upload that failed before its message existed, kept with its
    /// staged source file so the user can retry without re-picking.
    struct PendingUpload: Identifiable, Sendable {
        enum Kind: Sendable {
            case attachment(filename: String, mimeType: String)
            case voiceNote(duration: TimeInterval, levels: [Float])
        }
        let id: UUID
        let kind: Kind
        /// Plaintext staged copy owned by the view model (deleted on
        /// success or explicit discard).
        let sourceURL: URL
        let errorMessage: String

        var displayName: String {
            switch kind {
            case .attachment(let filename, _): return filename
            case .voiceNote: return "Voice note"
            }
        }
    }

    /// Uploads that failed before a message existed. The composer renders
    /// these with Retry / Dismiss.
    @Published private(set) var failedUploads: [PendingUpload] = []

    /// Retry a failed upload from its staged source file.
    func retryUpload(_ upload: PendingUpload) async {
        failedUploads.removeAll { $0.id == upload.id }
        transfers[upload.id] = .preparing
        switch upload.kind {
        case .attachment(let filename, let mimeType):
            await sendAttachment(fileURL: upload.sourceURL, filename: filename, mimeType: mimeType, reusingStaged: true)
        case .voiceNote(let duration, let levels):
            await sendVoiceNote(fileURL: upload.sourceURL, duration: duration, levels: levels, reusingStaged: true)
        }
    }

    /// Discards a failed upload and deletes its staged source file.
    func discardUpload(_ upload: PendingUpload) {
        failedUploads.removeAll { $0.id == upload.id }
        transfers[upload.id] = nil
        try? FileManager.default.removeItem(at: upload.sourceURL)
    }

    /// Encrypt → upload with progress → send. The relay only ever sees ciphertext.
    /// `reusingStaged` is true when retrying: `fileURL` is already our
    /// staged copy, so it must not be copied (or deleted on failure) again.
    func sendAttachment(fileURL: URL, filename: String, mimeType: String, reusingStaged: Bool = false) async {
        let attachmentID = UUID()
        transfers[attachmentID] = .preparing
        // Stage a private copy: the caller's URL (photo picker / recorder)
        // may disappear or be reused while the upload is in flight.
        let staged: URL
        do {
            if reusingStaged {
                staged = fileURL
            } else {
                staged = AegisPaths.ensureStaging().appendingPathComponent("\(attachmentID)-\(filename)")
                if FileManager.default.fileExists(atPath: staged.path) {
                    try FileManager.default.removeItem(at: staged)
                }
                try FileManager.default.copyItem(at: fileURL, to: staged)
            }
        } catch {
            transfers[attachmentID] = .failed(error.localizedDescription)
            sendError = error.localizedDescription
            return
        }
        do {
            let encrypted = try await crypto.encryptAttachment(at: staged, conversationID: conversation.id)
            let thumbnail = makeThumbnail(for: staged, mimeType: mimeType)

            transfers[attachmentID] = .inProgress(0)
            for await progress in transport.uploadBlob(from: encrypted.fileURL, conversationID: conversation.id, id: attachmentID) {
                transfers[attachmentID] = .inProgress(progress)
            }

            let attachment = Attachment(
                id: attachmentID,
                filename: filename,
                mimeType: mimeType,
                byteCount: encrypted.byteCount,
                wrappedKey: encrypted.wrappedKey,
                remoteLocator: try? await transport.blobLocator(attachmentID: attachmentID, conversationID: conversation.id),
                thumbnailData: thumbnail
            )
            transfers[attachmentID] = .done
            // Keep the ciphertext staged until the message sends.
            try? FileManager.default.removeItem(at: staged)
            failedUploads.removeAll { $0.id == attachmentID }
            await sendText(body: nil, replyToID: nil, attachment: attachment, voiceNote: nil)
        } catch {
            transfers[attachmentID] = .failed(error.localizedDescription)
            // The staged source survives for retry; the composer offers it.
            let pending = PendingUpload(
                id: attachmentID,
                kind: .attachment(filename: filename, mimeType: mimeType),
                sourceURL: staged,
                errorMessage: error.localizedDescription
            )
            failedUploads.removeAll { $0.id == attachmentID }
            failedUploads.append(pending)
            sendError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    func sendVoiceNote(fileURL: URL, duration: TimeInterval, levels: [Float], reusingStaged: Bool = false) async {
        let noteID = UUID()
        transfers[noteID] = .preparing
        let staged: URL
        do {
            if reusingStaged {
                staged = fileURL
            } else {
                staged = AegisPaths.ensureStaging().appendingPathComponent("\(noteID).m4a")
                if FileManager.default.fileExists(atPath: staged.path) {
                    try FileManager.default.removeItem(at: staged)
                }
                try FileManager.default.copyItem(at: fileURL, to: staged)
            }
        } catch {
            transfers[noteID] = .failed(error.localizedDescription)
            sendError = error.localizedDescription
            return
        }
        do {
            let encrypted = try await crypto.encryptAttachment(at: staged, conversationID: conversation.id)
            transfers[noteID] = .inProgress(0)
            for await progress in transport.uploadBlob(from: encrypted.fileURL, conversationID: conversation.id, id: noteID) {
                transfers[noteID] = .inProgress(progress)
            }
            let voiceNote = VoiceNote(
                id: noteID,
                duration: duration,
                levels: levels,
                wrappedKey: encrypted.wrappedKey,
                remoteLocator: try? await transport.blobLocator(attachmentID: noteID, conversationID: conversation.id)
            )
            // Persist the decrypted audio locally for instant playback.
            let localURL = AegisPaths.attachmentsDirectory.appendingPathComponent("\(noteID).m4a")
            try? FileManager.default.copyItem(at: staged, to: localURL)
            try? FileManager.default.removeItem(at: staged)
            transfers[noteID] = .done
            failedUploads.removeAll { $0.id == noteID }
            await sendText(body: nil, replyToID: nil, attachment: nil, voiceNote: voiceNote)
        } catch {
            transfers[noteID] = .failed(error.localizedDescription)
            let pending = PendingUpload(
                id: noteID,
                kind: .voiceNote(duration: duration, levels: levels),
                sourceURL: staged,
                errorMessage: error.localizedDescription
            )
            failedUploads.removeAll { $0.id == noteID }
            failedUploads.append(pending)
            sendError = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    /// Download + decrypt an inbound attachment for viewing.
    func localURL(for attachment: Attachment) async -> URL? {
        let localURL = AegisPaths.attachmentsDirectory
            .appendingPathComponent("\(attachment.id)-\(attachment.filename)")
        if FileManager.default.fileExists(atPath: localURL.path) {
            return localURL
        }
        guard let locator = attachment.remoteLocator, let wrappedKey = attachment.wrappedKey else {
            return nil
        }
        transfers[attachment.id] = .inProgress(0)
        do {
            let stagedCipher = AegisPaths.ensureStaging().appendingPathComponent("\(attachment.id).bin")
            for await progress in transport.downloadBlob(locator: locator, id: attachment.id, to: stagedCipher) {
                transfers[attachment.id] = .inProgress(progress)
            }
            // The nonce is prepended by our encrypt path; the real AegisCrypto
            // defines the exact framing — see INTEGRATION_NOTES.md.
            try await crypto.decryptAttachment(
                ciphertextURL: stagedCipher,
                wrappedKey: wrappedKey,
                nonce: Data(),
                to: localURL
            )
            try? FileManager.default.removeItem(at: stagedCipher)
            transfers[attachment.id] = .done
            return localURL
        } catch {
            transfers[attachment.id] = .failed(error.localizedDescription)
            return nil
        }
    }

    /// Local playable URL for a voice note (downloads + decrypts if needed).
    func localAudioURL(for voiceNote: VoiceNote) async -> URL? {
        let localURL = AegisPaths.attachmentsDirectory.appendingPathComponent("\(voiceNote.id).m4a")
        if FileManager.default.fileExists(atPath: localURL.path) {
            return localURL
        }
        guard let locator = voiceNote.remoteLocator, let wrappedKey = voiceNote.wrappedKey else {
            return nil
        }
        transfers[voiceNote.id] = .inProgress(0)
        do {
            let stagedCipher = AegisPaths.ensureStaging().appendingPathComponent("\(voiceNote.id).bin")
            for await progress in transport.downloadBlob(locator: locator, id: voiceNote.id, to: stagedCipher) {
                transfers[voiceNote.id] = .inProgress(progress)
            }
            try await crypto.decryptAttachment(
                ciphertextURL: stagedCipher,
                wrappedKey: wrappedKey,
                nonce: Data(),
                to: localURL
            )
            try? FileManager.default.removeItem(at: stagedCipher)
            transfers[voiceNote.id] = .done
            return localURL
        } catch {
            transfers[voiceNote.id] = .failed(error.localizedDescription)
            return nil
        }
    }

    private func makeThumbnail(for url: URL, mimeType: String) -> Data? {
        guard mimeType.hasPrefix("image/"),
              let image = UIImage(contentsOfFile: url.path) else { return nil }
        let target = CGSize(width: 320, height: 320)
        let renderer = UIGraphicsImageRenderer(size: target)
        let thumb = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: target))
        }
        return thumb.jpegData(compressionQuality: 0.6)
    }

    // MARK: - Reactions / edits / deletes

    func toggleReaction(_ emoji: String, on message: Message) async {
        guard let me = appState.identity else { return }
        var updated = message
        var reactors = updated.reactions[emoji] ?? []
        let adding: Bool
        if let idx = reactors.firstIndex(of: me.id) {
            reactors.remove(at: idx)
            adding = false
            if reactors.isEmpty {
                updated.reactions.removeValue(forKey: emoji)
            } else {
                updated.reactions[emoji] = reactors
            }
        } else {
            reactors.append(me.id)
            updated.reactions[emoji] = reactors
            adding = true
        }
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.impact(.light)

        // Sync the delta to peers (toggle is idempotent on receipt).
        if adding {
            do {
                let payload = WirePayload.reaction(targetMessageID: message.id, emoji: emoji)
                let ciphertext = try await crypto.encryptMessage(
                    payload.encoded(),
                    conversationID: conversation.id,
                    recipientKeys: await recipientKeys()
                )
                try await transport.sendEnvelope(OutgoingEnvelope(
                    id: UUID(), conversationID: conversation.id,
                    ciphertext: ciphertext, kind: .reaction
                ))
            } catch {
                sendError = error.localizedDescription
            }
        }
    }

    func editMessage(_ message: Message, newBody: String) async {
        let trimmed = newBody.trimmingCharacters(in: .whitespacesAndNewlines)
        guard message.isFromMe, !message.isDeleted, !trimmed.isEmpty,
              trimmed != message.body else { return }
        var updated = message
        updated.body = trimmed
        updated.editedAt = Date()
        try? await store.updateMessage(updated)
        upsert(updated)
        do {
            let payload = WirePayload.edit(targetMessageID: message.id, editedBody: trimmed)
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: conversation.id,
                recipientKeys: await recipientKeys()
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: UUID(), conversationID: conversation.id,
                ciphertext: ciphertext, kind: .edit
            ))
        } catch {
            sendError = error.localizedDescription
        }
    }

    func deleteMessage(_ message: Message) async {
        var updated = message
        updated.body = nil
        updated.attachment = nil
        updated.voiceNote = nil
        updated.deletedAt = Date()
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.impact(.medium)
        do {
            let payload = WirePayload.delete(targetMessageID: message.id)
            let ciphertext = try await crypto.encryptMessage(
                payload.encoded(),
                conversationID: conversation.id,
                recipientKeys: await recipientKeys()
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: UUID(), conversationID: conversation.id,
                ciphertext: ciphertext, kind: .delete
            ))
        } catch {
            sendError = error.localizedDescription
        }
    }

    // MARK: - Read receipts & typing

    func markAsRead() async {
        guard conversation.readReceiptsEnabled,
              UserDefaults.standard.bool(forKey: SettingsKeys.readReceiptsDefault) else { return }
        let unread = messages.filter { !$0.isFromMe && $0.status == .delivered }
        guard !unread.isEmpty else { return }
        for var message in unread {
            message.status = .read
            try? await store.updateMessage(message)
            upsert(message)
        }
        if conversation.unreadCount > 0 {
            var updated = conversation
            updated.unreadCount = 0
            try? await store.saveConversation(updated)
            conversation = updated
        }
        try? await transport.sendReadReceipt(
            conversationID: conversation.id,
            messageIDs: unread.map { $0.id }
        )
    }

    func sendTyping(_ isTyping: Bool) {
        guard conversation.typingIndicatorsEnabled,
              UserDefaults.standard.bool(forKey: SettingsKeys.typingIndicatorsDefault),
              conversation.canSend else { return }
        // Capture Sendable values; the Task itself stays off the view model.
        let transport = self.transport
        let conversationID = conversation.id
        Task {
            try? await transport.sendTypingIndicator(conversationID: conversationID, isTyping: isTyping)
        }
    }

    private func subscribeToTyping() {
        appState.typingEvents
            .filter { [weak self] event in event.conversationID == self?.conversation.id }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] event in
                guard let self else { return }
                if event.isTyping {
                    if !self.typingNames.contains(event.displayName) {
                        self.typingNames.append(event.displayName)
                    }
                    // Auto-clear a stale indicator after 4s without a refresh.
                    self.typingClearTasks[event.contactID]?.cancel()
                    self.typingClearTasks[event.contactID] = Task { @MainActor [weak self] in
                        try? await Task.sleep(nanoseconds: 4_000_000_000)
                        self?.typingNames.removeAll { $0 == event.displayName }
                    }
                } else {
                    self.typingNames.removeAll { $0 == event.displayName }
                }
            }
            .store(in: &cancellables)
    }

    /// Live inbound messages for the open thread (new arrivals, edits,
    /// deletes, reactions) — upserted and marked read while visible.
    private func subscribeToInbound() {
        appState.inboundMessages
            .filter { [weak self] message in message.conversationID == self?.conversation.id }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] message in
                guard let self else { return }
                self.upsert(message)
                Task { @MainActor [weak self] in
                    await self?.markAsRead()
                    // The identity-change notice arrives here too: refresh
                    // the banner / held-message state.
                    await self?.refreshIdentityChangeState()
                }
            }
            .store(in: &cancellables)
    }

    /// Re-reads the pending identity-change state and the contact's
    /// verification, so the banner and held messages react to flagging,
    /// re-verification, and dismissal.
    func refreshIdentityChangeState() async {
        pendingIdentityChange = await transport.pendingIdentityChange(for: conversation.id)
        if let contact {
            let contacts = (try? await store.fetchContacts()) ?? []
            if let fresh = contacts.first(where: { $0.id == contact.id }) {
                contactsByID[fresh.id] = fresh
            }
        }
    }

    /// Explicit user dismissal of the identity-change banner: held messages
    /// are shown, the contact stays flagged until re-verified.
    func dismissIdentityChangeWarning() async {
        await transport.resolveIdentityChange(conversationID: conversation.id, adoptNewKey: false)
        Haptics.impact(.medium)
        await refreshIdentityChangeState()
    }

    // MARK: - Disappearing messages

    func setDisappearing(_ interval: TimeInterval?) async {
        var updated = conversation
        updated.disappearingInterval = interval
        try? await store.saveConversation(updated)
        conversation = updated
        Haptics.selection()
    }

    // MARK: - Conversation settings

    func setReadReceipts(_ enabled: Bool) async {
        var updated = conversation
        updated.readReceiptsEnabled = enabled
        try? await store.saveConversation(updated)
        conversation = updated
        Haptics.selection()
    }

    func setTypingIndicators(_ enabled: Bool) async {
        var updated = conversation
        updated.typingIndicatorsEnabled = enabled
        try? await store.saveConversation(updated)
        conversation = updated
        Haptics.selection()
    }

    func setMuted(_ muted: Bool) async {
        var updated = conversation
        updated.isMuted = muted
        try? await store.saveConversation(updated)
        conversation = updated
        Haptics.selection()
    }

    /// Delete the conversation and its local history. Returns true on success.
    func deleteConversation() async -> Bool {
        do {
            try await store.deleteConversation(id: conversation.id)
            return true
        } catch {
            loadError = error.localizedDescription
            return false
        }
    }

    /// Leave a group/channel on the network, then delete local history.
    /// Returns true when the caller should dismiss.
    func leaveAndDelete() async -> Bool {
        do {
            try await transport.leaveConversation(conversation.id)
            try await store.deleteConversation(id: conversation.id)
            Haptics.notification(.warning)
            return true
        } catch {
            loadError = error.localizedDescription
            return false
        }
    }

    // MARK: - Private

    private func recipientKeys() async -> [Data] {
        let contacts = (try? await store.fetchContacts()) ?? []
        if conversation.kind == .direct, let contact {
            return [contact.identityKey]
        }
        return conversation.memberIDs.compactMap { id in
            contacts.first { $0.id == id }?.identityKey
        }
    }

    private func updateConversationPreview(for message: Message) async {
        var updated = conversation
        if let attachment = message.attachment {
            updated.lastMessagePreview = "📎 \(attachment.filename)"
        } else if let voiceNote = message.voiceNote {
            updated.lastMessagePreview = "🎤 Voice note (\(Formatters.duration(voiceNote.duration)))"
        } else {
            updated.lastMessagePreview = message.body
        }
        updated.lastMessageAt = message.sentAt
        updated.lastMessageIsFromMe = true
        try? await store.saveConversation(updated)
        conversation = updated
    }
}
