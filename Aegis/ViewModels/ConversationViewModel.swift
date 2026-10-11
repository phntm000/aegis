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
            await refreshThreadSummaries()
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

    /// Pages history backwards until the message is loaded (or history is
    /// exhausted). Used by jump-to-message from quotes, pins, and stars.
    func ensureMessageLoaded(_ id: UUID) async -> Bool {
        for _ in 0..<25 {
            if message(withId: id) != nil { return true }
            let oldestBefore = messages.first?.id
            await loadMore()
            if messages.first?.id == oldestBefore { break }
        }
        return message(withId: id) != nil
    }

    // MARK: - Sending

    var canSend: Bool {
        conversation.canSend && appState.connectionState.canSend
    }

    /// Attachments and voice notes send from the primary device only in
    /// v1 (the linked-device relay carries text); the composer hides those
    /// affordances on linked devices instead of failing silently.
    var canSendAttachments: Bool {
        !appState.isLinkedDevice
    }

    func send() async {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, canSend else { return }
        let replying = replyingTo
        draft = ""
        replyingTo = nil
        await sendText(
            body: text,
            replyToID: replying?.id,
            quote: replying.map { quoteSnapshot(for: $0) },
            threadRootID: nil,
            attachment: nil,
            voiceNote: nil
        )
    }

    /// Builds a frozen quote snapshot of the message being replied to.
    func quoteSnapshot(for message: Message) -> QuoteSnapshot {
        let name: String
        if message.isFromMe {
            name = "You"
        } else {
            name = senderName(for: message) ?? contact?.displayName ?? "Unknown"
        }
        return message.makeQuoteSnapshot(senderName: name)
    }

    /// Sends a reply inside a thread anchored at `parentID`.
    func sendThreadReply(to parentID: UUID, body: String) async {
        let text = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, canSend else { return }
        await sendText(
            body: text,
            replyToID: nil,
            quote: nil,
            threadRootID: parentID,
            attachment: nil,
            voiceNote: nil
        )
    }

    private func sendText(
        body: String?,
        replyToID: UUID?,
        quote: QuoteSnapshot?,
        threadRootID: UUID?,
        attachment: Attachment?,
        voiceNote: VoiceNote?
    ) async {
        guard let me = appState.identity else { return }
        // Linked secondary: relay the send through the primary device.
        // (Device-link v1 carries text only: thread/quote metadata is
        // dropped on this path and the primary echoes a plain message.)
        if appState.isLinkedDevice, attachment == nil, voiceNote == nil {
            await sendTextViaPrimary(body: body, replyToID: replyToID, senderID: me.id)
            return
        }
        let messageID = UUID()
        let afterRead = conversation.disappearingAfterRead
        let expiresAt = conversation.disappearingInterval.flatMap {
            afterRead ? nil : Date().addingTimeInterval($0)
        }

        var message = Message(
            conversationID: conversation.id,
            senderID: me.id,
            isFromMe: true,
            body: body,
            replyToID: replyToID,
            quoteSnapshot: quote,
            status: .sending,
            expiresAt: expiresAt,
            disappearAfterReadInterval: afterRead ? conversation.disappearingInterval : nil,
            threadRootID: threadRootID,
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
                quote: quote,
                threadRootID: threadRootID,
                attachment: attachment,
                voiceNote: voiceNote,
                expiresIn: conversation.disappearingInterval,
                disappearAfterRead: afterRead ? true : nil
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

    /// Linked-device send path: the message is shown as sending and handed
    /// to the primary over the paired channel; the primary's echo (same ID)
    /// persists it and flips it to `.sent`.
    private func sendTextViaPrimary(body: String?, replyToID: UUID?, senderID: UUID) async {
        let text = body ?? ""
        let message = Message(
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
            var failed = message
            failed.status = .failed
            sendError = error.localizedDescription
            upsert(failed)
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
                quote: retried.quoteSnapshot,
                threadRootID: retried.threadRootID,
                attachment: retried.attachment,
                voiceNote: retried.voiceNote,
                expiresIn: conversation.disappearingInterval,
                disappearAfterRead: retried.disappearAfterReadInterval == nil ? nil : true
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
        guard canSendAttachments else {
            sendError = "Attachments send from your primary device. This device is linked."
            return
        }
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
        guard canSendAttachments else {
            sendError = "Voice notes send from your primary device. This device is linked."
            return
        }
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

    /// Sends a signed event payload (reaction, edit, tombstone, ballot,
    /// pin). The identity signature binds the event to our long-term key;
    /// the AEAD channel authenticates the session.
    private func sendSignedEvent(_ payload: WirePayload, kind: EnvelopeKind) async -> Bool {
        do {
            var signed = payload
            let signature = try await crypto.signWithIdentity(signed.signableBytes())
            signed.attachSignature(signature)
            let ciphertext = try await crypto.encryptMessage(
                signed.encoded(),
                conversationID: conversation.id,
                recipientKeys: await recipientKeys()
            )
            try await transport.sendEnvelope(OutgoingEnvelope(
                id: UUID(), conversationID: conversation.id,
                ciphertext: ciphertext, kind: kind
            ))
            return true
        } catch {
            sendError = error.localizedDescription
            return false
        }
    }

    func toggleReaction(_ emoji: String, on message: Message) async {
        guard let me = appState.identity, !message.isDeleted else { return }
        var updated = message
        var reactors = updated.reactions[emoji] ?? []
        if let idx = reactors.firstIndex(of: me.id) {
            reactors.remove(at: idx)
            if reactors.isEmpty {
                updated.reactions.removeValue(forKey: emoji)
            } else {
                updated.reactions[emoji] = reactors
            }
        } else {
            reactors.append(me.id)
            updated.reactions[emoji] = reactors
        }
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.impact(.light)

        // Sync the delta to peers as a signed event (toggle is idempotent
        // on receipt, so adds and removals both propagate).
        let payload = WirePayload.reaction(targetMessageID: message.id, emoji: emoji)
        await sendSignedEvent(payload, kind: .reaction)
    }

    /// The configured edit window (default 48h, 0 = disabled).
    var editWindowSeconds: TimeInterval {
        guard UserDefaults.standard.object(forKey: SettingsKeys.editWindowSeconds) != nil else {
            return defaultEditWindowSeconds
        }
        return UserDefaults.standard.double(forKey: SettingsKeys.editWindowSeconds)
    }

    func canEdit(_ message: Message) -> Bool {
        canEditMessage(message, windowSeconds: editWindowSeconds)
    }

    /// Time remaining in the edit window for `message`, nil when not editable.
    func editWindowRemaining(for message: Message) -> TimeInterval? {
        guard canEdit(message) else { return nil }
        let elapsed = Date().timeIntervalSince(message.sentAt)
        return max(0, editWindowSeconds - elapsed)
    }

    func editMessage(_ message: Message, newBody: String) async {
        let trimmed = newBody.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canEdit(message), !trimmed.isEmpty, trimmed != message.body else {
            if !canEdit(message) {
                sendError = "The edit window for this message has closed."
            }
            return
        }
        var updated = message
        // Local version history: keep the pre-edit body.
        if let previous = updated.body {
            updated.editHistory.append(MessageEdit(body: previous, editedAt: Date()))
        }
        updated.body = trimmed
        updated.editedAt = Date()
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.notification(.success)
        let payload = WirePayload.edit(targetMessageID: message.id, editedBody: trimmed)
        await sendSignedEvent(payload, kind: .edit)
    }

    func deleteMessage(_ message: Message) async {
        guard message.isFromMe, !message.isDeleted else { return }
        // Store tombstone path: drops attachment metadata and
        // cryptographically wipes the Keychain wrapped keys + cached files.
        try? await store.deleteMessage(id: message.id, conversationID: message.conversationID)
        if let tombstoned = try? await store.fetchMessage(id: message.id, conversationID: message.conversationID) {
            upsert(tombstoned)
        } else {
            var fallback = message
            fallback.body = nil
            fallback.attachment = nil
            fallback.voiceNote = nil
            fallback.poll = nil
            fallback.deletedAt = Date()
            upsert(fallback)
        }
        Haptics.impact(.medium)
        // Signed tombstone: propagates to participants and linked devices.
        let payload = WirePayload.delete(targetMessageID: message.id)
        await sendSignedEvent(payload, kind: .delete)
    }

    // MARK: - Stars (local-only)

    func toggleStar(_ message: Message) async {
        guard !message.isDeleted else { return }
        var updated = message
        updated.isStarred.toggle()
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.selection()
        await loadStarred()
    }

    @Published private(set) var starredMessages: [Message] = []
    @Published private(set) var isLoadingStarred = false

    func loadStarred() async {
        isLoadingStarred = true
        defer { isLoadingStarred = false }
        starredMessages = (try? await store.fetchStarredMessages(conversationID: conversation.id)) ?? []
    }

    // MARK: - Pins (shared, admin-controlled)

    /// Whether the local user may pin in this conversation: anyone in a
    /// 1:1 chat, moderators+ in groups/channels.
    var canPin: Bool {
        switch conversation.kind {
        case .direct: return true
        case .group, .channel, .vault: return conversation.myRole?.canModerate ?? false
        }
    }

    /// Messages with an active (non-expired) pin, newest pin first.
    var activePins: [Message] {
        messages.filter(\.isPinned)
            .sorted { ($0.pin?.pinnedAt ?? .distantPast) > ($1.pin?.pinnedAt ?? .distantPast) }
    }

    func pinMessage(_ message: Message, expiresAt: Date?) async {
        guard canPin, !message.isDeleted, !message.isPinned else { return }
        // Pinning a disappearing message is blocked: the pin would
        // outlive (and thereby resurrect) content the timer killed.
        guard !message.isEphemeral else {
            sendError = "Disappearing messages can't be pinned."
            return
        }
        guard let me = appState.identity else { return }
        let name = "You"
        var updated = message
        updated.pin = MessagePin(
            pinnedBy: me.id,
            pinnedByName: name,
            pinnedAt: Date(),
            expiresAt: expiresAt
        )
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.notification(.success)
        let payload = WirePayload.pin(targetMessageID: message.id, expiresAt: expiresAt)
        await sendSignedEvent(payload, kind: .pin)
    }

    func unpinMessage(_ message: Message) async {
        guard canPin, message.isPinned else { return }
        var updated = message
        updated.pin = nil
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.selection()
        let payload = WirePayload.unpin(targetMessageID: message.id)
        await sendSignedEvent(payload, kind: .pin)
    }

    // MARK: - Threads

    /// Thread root ID -> summary, refreshed on load and on new arrivals.
    @Published private(set) var threadSummaries: [UUID: ThreadSummary] = [:]

    /// Per-thread last-read timestamps (local-only), for unread badges.
    @Published private(set) var threadReadAt: [UUID: Date] = [:]

    private var threadReadDefaultsKey: String { "threads.lastRead.\(conversation.id.uuidString)" }

    func refreshThreadSummaries() async {
        threadSummaries = (try? await store.fetchThreadSummaries(conversationID: conversation.id)) ?? [:]
        if let data = UserDefaults.standard.data(forKey: threadReadDefaultsKey),
           let decoded = try? JSONDecoder().decode([String: Date].self, from: data) {
            threadReadAt = Dictionary(
                uniqueKeysWithValues: decoded.compactMap { key, value in
                    UUID(uuidString: key).map { ($0, value) }
                }
            )
        }
    }

    func markThreadRead(_ rootID: UUID) {
        threadReadAt[rootID] = Date()
        let encoded = Dictionary(
            uniqueKeysWithValues: threadReadAt.map { ($0.key.uuidString, $0.value) }
        )
        if let data = try? JSONEncoder().encode(encoded) {
            UserDefaults.standard.set(data, forKey: threadReadDefaultsKey)
        }
    }

    func threadHasUnread(_ rootID: UUID) -> Bool {
        guard let summary = threadSummaries[rootID] else { return false }
        guard let readAt = threadReadAt[rootID] else { return true }
        return summary.lastActivityAt > readAt
    }

    func threadReplies(for rootID: UUID) async -> [Message] {
        (try? await store.fetchThreadReplies(conversationID: conversation.id, threadRootID: rootID)) ?? []
    }

    // MARK: - Polls

    /// Creates and sends a poll. Returns false when validation fails
    /// (question/options are validated by the composer; this is the last
    /// line of defense).
    @discardableResult
    func createPoll(
        question: String,
        options: [String],
        allowsMultipleChoice: Bool,
        isAnonymous: Bool,
        closesAt: Date?,
        expiresIn: TimeInterval? = nil
    ) async -> Bool {
        guard let me = appState.identity, canSend else { return false }
        let q = question.trimmingCharacters(in: .whitespacesAndNewlines)
        let opts = options.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !q.isEmpty, opts.count >= 2, opts.count <= 10 else {
            sendError = "Polls need a question and 2–10 options."
            return false
        }
        let eligible: Int? = conversation.kind == .direct ? nil : max(2, conversation.memberIDs.count)
        let poll = PollMessage(
            question: String(q.prefix(280)),
            options: opts.map { String($0.prefix(100)) },
            allowsMultipleChoice: allowsMultipleChoice,
            isAnonymous: isAnonymous,
            closesAt: closesAt,
            tally: [:],
            voters: [],
            voterChoices: [:],
            myChoices: [],
            eligibleVoterCount: eligible
        )
        let messageID = UUID()
        let afterRead = conversation.disappearingAfterRead
        var message = Message(
            id: messageID,
            conversationID: conversation.id,
            senderID: me.id,
            isFromMe: true,
            body: nil,
            status: .sending,
            expiresAt: afterRead ? nil : expiresIn ?? conversation.disappearingInterval.map { Date().addingTimeInterval($0) },
            disappearAfterReadInterval: afterRead ? (expiresIn ?? conversation.disappearingInterval) : nil,
            poll: poll,
            sentAt: Date()
        )
        // The store's poll-message validation requires content: polls ride
        // as kind == .poll, which the store accepts.
        try? await store.saveMessage(message)
        upsert(message)
        Haptics.impact(.light)

        do {
            var payload = WirePayload.poll(
                id: messageID,
                question: poll.question,
                options: poll.options,
                allowsMultipleChoice: poll.allowsMultipleChoice,
                anonymous: poll.isAnonymous,
                closesAt: poll.closesAt,
                eligibleVoterCount: poll.eligibleVoterCount,
                expiresIn: expiresIn ?? conversation.disappearingInterval,
                disappearAfterRead: afterRead ? true : nil
            )
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
                kind: .poll
            ))
            message.status = .sent
        } catch {
            message.status = .failed
            sendError = error.localizedDescription
        }
        try? await store.updateMessage(message)
        upsert(message)
        return message.status != .failed
    }

    /// Casts (or changes) our vote on a poll. Enforces single/multi-choice,
    /// anonymity (no changes), and the close deadline.
    func castVote(on pollMessage: Message, choices: [Int]) async {
        guard let me = appState.identity,
              var poll = pollMessage.poll,
              !pollMessage.isDeleted else { return }
        guard poll.canVote(voter: me.id, choices: choices) else {
            if poll.isClosed {
                sendError = "This poll has closed."
            } else if poll.isAnonymous && poll.voters.contains(me.id) {
                sendError = "Anonymous votes can't be changed."
            } else {
                sendError = "That vote isn't valid for this poll."
            }
            return
        }
        // Retract our previous ballot locally (non-anonymous only; the
        // poll struct handles the tally math).
        if !poll.isAnonymous, let previous = poll.previousChoices(of: me.id) {
            for option in previous {
                poll.tally[option] = max(0, (poll.tally[option] ?? 1) - 1)
            }
        }
        for option in choices { poll.tally[option, default: 0] += 1 }
        if !poll.voters.contains(me.id) { poll.voters.append(me.id) }
        if !poll.isAnonymous { poll.voterChoices[me.id] = choices }
        poll.myChoices = choices
        var updated = pollMessage
        updated.poll = poll
        try? await store.updateMessage(updated)
        upsert(updated)
        Haptics.selection()

        // Signed ballot: the tally is recomputed from ballots on receipt.
        let payload = WirePayload.ballot(targetMessageID: pollMessage.id, choices: choices)
        await sendSignedEvent(payload, kind: .ballot)
    }

    // MARK: - Read receipts & typing

    func markAsRead() async {
        guard conversation.readReceiptsEnabled,
              UserDefaults.standard.bool(forKey: SettingsKeys.readReceiptsDefault) else { return }
        let unread = messages.filter { !$0.isFromMe && $0.status == .delivered }
        guard !unread.isEmpty else { return }
        let now = Date()
        for var message in unread {
            message.status = .read
            // "Disappear after read": the timer starts now.
            if let interval = message.disappearAfterReadInterval, message.expiresAt == nil {
                message.expiresAt = now.addingTimeInterval(interval)
            }
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
                    // Keep thread disclosures fresh as replies land.
                    await self?.refreshThreadSummaries()
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

    func setDisappearing(_ interval: TimeInterval?, afterRead: Bool = false) async {
        var updated = conversation
        updated.disappearingInterval = interval
        updated.disappearingAfterRead = afterRead && interval != nil
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
