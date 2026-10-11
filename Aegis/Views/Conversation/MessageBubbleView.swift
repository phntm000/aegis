import SwiftUI
import UIKit

/// A single message bubble: quote context, body, attachments, polls,
/// thread disclosure, reactions (incl. custom emoji packs), delivery
/// state, and the long-press action sheet (react / reply / thread /
/// copy / edit / star / pin / delete). Deleted messages render as
/// tombstones; the layout never shifts.
struct MessageBubbleView: View {
    let message: Message
    @ObservedObject var viewModel: ConversationViewModel
    @EnvironmentObject private var appState: AppState

    /// Jump to another message in the thread (quotes, pins, stars).
    var onJumpToMessage: ((UUID) -> Void)? = nil
    /// Open the thread anchored at the given parent message id.
    var onOpenThread: ((UUID) -> Void)? = nil

    @State private var showingActions = false

    var body: some View {
        if message.isDeleted {
            tombstone
        } else {
            bubble
        }
    }

    // MARK: - Deleted tombstone

    private var tombstone: some View {
        HStack {
            if message.isFromMe { Spacer() }
            HStack(spacing: AegisLayout.xs) {
                Image(systemName: "trash")
                    .font(.system(size: 12))
                    .accessibilityHidden(true)
                Text("This message was deleted")
                    .font(AegisType.footnote)
                    .italic()
            }
            .foregroundStyle(AegisColors.textTertiary)
            .padding(.vertical, AegisLayout.s)
            if !message.isFromMe { Spacer() }
        }
        .accessibilityLabel("Deleted message")
    }

    // MARK: - Bubble

    private var bubble: some View {
        HStack(alignment: .bottom, spacing: AegisLayout.xs) {
            if message.isFromMe { Spacer(minLength: AegisLayout.xxl) }

            VStack(alignment: message.isFromMe ? .trailing : .leading, spacing: AegisLayout.xs) {
                VStack(alignment: .leading, spacing: AegisLayout.xs) {
                    if let name = viewModel.senderName(for: message) {
                        Text(name)
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.accent)
                    }

                    quoteBlock

                    if let attachment = message.attachment {
                        AttachmentContentView(attachment: attachment, viewModel: viewModel)
                    }

                    if let voiceNote = message.voiceNote {
                        VoiceNoteBubbleView(voiceNote: voiceNote, viewModel: viewModel)
                    }

                    if let poll = message.poll {
                        PollMessageView(poll: poll, isFromMe: message.isFromMe) { choices in
                            Task { @MainActor in await viewModel.castVote(on: message, choices: choices) }
                        }
                    } else if let body = message.body {
                        Text(body)
                            .font(AegisType.body)
                            .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent : AegisColors.textPrimary)
                            .textSelection(.enabled)
                    }

                    metaRow
                }
                .padding(.horizontal, AegisLayout.m)
                .padding(.vertical, AegisLayout.s)
                .background(message.isFromMe ? AegisColors.bubbleOutgoing : AegisColors.bubbleIncoming)
                .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))
                .onLongPressGesture {
                    Haptics.impact(.medium)
                    showingActions = true
                }
                .accessibilityAction(named: "Message actions") {
                    showingActions = true
                }

                threadDisclosure

                if !message.reactions.isEmpty {
                    reactionChips
                }
            }

            if !message.isFromMe { Spacer(minLength: AegisLayout.xxl) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
        .sheet(isPresented: $showingActions) {
            MessageActionsSheet(
                message: message,
                viewModel: viewModel,
                onJumpToMessage: onJumpToMessage,
                onOpenThread: onOpenThread
            )
            .presentationDetents([.medium, .large])
        }
    }

    // MARK: - Quote

    /// Renders the frozen quote snapshot (survives the original being
    /// edited or deleted); tapping follows the live pointer. When the
    /// original was edited after the quote, an "edited" marker shows the
    /// quote is the pre-edit version.
    @ViewBuilder
    private var quoteBlock: some View {
        if let snapshot = message.quoteSnapshot, let replyID = message.replyToID {
            let originalEdited = viewModel.message(withId: replyID)?.isEdited ?? false
            Button {
                onJumpToMessage?(replyID)
            } label: {
                HStack(spacing: AegisLayout.xs) {
                    Capsule()
                        .fill(message.isFromMe ? AegisColors.textOnAccent.opacity(0.6) : AegisColors.accent)
                        .frame(width: 3)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Text(snapshot.senderName)
                                .font(AegisType.captionStrong)
                                .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.85) : AegisColors.accent)
                            if originalEdited {
                                Text("· edited since")
                                    .font(AegisType.caption)
                                    .italic()
                                    .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.7) : AegisColors.textTertiary)
                            }
                        }
                        Text(snapshot.fallbackText)
                            .font(AegisType.caption)
                            .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.8) : AegisColors.textSecondary)
                            .lineLimit(2)
                    }
                }
            }
            .accessibilityLabel("Quoted message from \(snapshot.senderName)\(originalEdited ? ", edited since quoting" : ""): \(snapshot.fallbackText)")
            .accessibilityHint("Jump to quoted message")
        } else if let replyID = message.replyToID,
                  let replied = viewModel.message(withId: replyID) {
            // Legacy path: no snapshot captured (older clients).
            Button {
                onJumpToMessage?(replyID)
            } label: {
                HStack(spacing: AegisLayout.xs) {
                    Capsule()
                        .fill(message.isFromMe ? AegisColors.textOnAccent.opacity(0.6) : AegisColors.accent)
                        .frame(width: 3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(replied.isFromMe ? "You" : (viewModel.senderName(for: replied) ?? ""))
                            .font(AegisType.captionStrong)
                            .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.85) : AegisColors.accent)
                        Text(replied.isDeleted ? "Message deleted" : (replied.body ?? (replied.attachment != nil ? "📎 Attachment" : "🎤 Voice note")))
                            .font(AegisType.caption)
                            .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.8) : AegisColors.textSecondary)
                            .lineLimit(2)
                    }
                }
            }
            .accessibilityLabel("Replying to \(replied.body ?? "a message")")
        }
    }

    // MARK: - Thread disclosure

    /// Collapsible thread entry: reply count, unread dot, last activity.
    /// Thread replies themselves don't nest further.
    @ViewBuilder
    private var threadDisclosure: some View {
        if !message.isThreadReply,
           let summary = viewModel.threadSummaries[message.id],
           summary.replyCount > 0 {
            Button {
                onOpenThread?(message.id)
            } label: {
                HStack(spacing: AegisLayout.xs) {
                    Image(systemName: "bubble.left.and.bubble.right.fill")
                        .font(.system(size: 12))
                        .accessibilityHidden(true)
                    Text("\(summary.replyCount) \(summary.replyCount == 1 ? "reply" : "replies")")
                        .font(AegisType.captionStrong)
                    if viewModel.threadHasUnread(message.id) {
                        Circle()
                            .fill(AegisColors.accent)
                            .frame(width: 8, height: 8)
                            .accessibilityLabel("Unread replies")
                    }
                    Text("· \(relativeTime(summary.lastActivityAt))")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(AegisColors.textTertiary)
                        .accessibilityHidden(true)
                }
                .foregroundStyle(AegisColors.accent)
                .padding(.horizontal, AegisLayout.s)
                .padding(.vertical, 6)
                .background(AegisColors.accentSoft.opacity(0.5))
                .clipShape(Capsule())
            }
            .accessibilityLabel("\(summary.replyCount) replies in thread\(viewModel.threadHasUnread(message.id) ? ", unread" : "")")
            .accessibilityHint("Open thread")
        }
    }

    private func relativeTime(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    // MARK: - Meta row

    private var metaRow: some View {
        HStack(spacing: AegisLayout.xs) {
            if message.isStarred {
                Image(systemName: "star.fill")
                    .font(.system(size: 10))
                    .accessibilityLabel("Starred")
            }
            if message.isPinned {
                Image(systemName: "pin.fill")
                    .font(.system(size: 10))
                    .accessibilityLabel("Pinned")
            }
            if message.isEphemeral {
                Image(systemName: "timer")
                    .font(AegisType.caption)
                    .accessibilityLabel("Disappearing message")
            }
            if message.isEdited {
                Text("edited")
                    .font(AegisType.caption)
                    .italic()
            }
            Text(Formatters.bubbleTime(message.sentAt))
                .font(AegisType.caption)
            if message.isFromMe {
                ReadReceiptView(status: message.status)
            }
        }
        .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.75) : AegisColors.textTertiary)
    }

    // MARK: - Reactions

    private var reactionChips: some View {
        HStack(spacing: AegisLayout.xs) {
            ForEach(message.sortedReactions, id: \.emoji) { reaction in
                let isMine = appState.identity.map { message.didReact(reaction.emoji, senderID: $0.id) } ?? false
                ReactionChipView(
                    emoji: reaction.emoji,
                    count: reaction.count,
                    isMine: isMine
                ) {
                    Task { @MainActor in await viewModel.toggleReaction(reaction.emoji, on: message) }
                }
            }
        }
    }

    private var accessibilityText: String {
        var parts: [String] = []
        if let name = viewModel.senderName(for: message) { parts.append(name) }
        if let snapshot = message.quoteSnapshot {
            parts.append("quoting \(snapshot.senderName)")
        }
        if let poll = message.poll { parts.append("poll: \(poll.question)") }
        else if let body = message.body { parts.append(body) }
        if message.attachment != nil { parts.append("attachment") }
        if message.voiceNote != nil { parts.append("voice note") }
        if message.isStarred { parts.append("starred") }
        if message.isPinned { parts.append("pinned") }
        parts.append(Formatters.bubbleTime(message.sentAt))
        return parts.joined(separator: ", ")
    }
}

/// One reaction chip. Custom-emoji reactions render as images (loaded
/// from the local pack); a missing pack renders a placeholder glyph —
/// never attacker-controlled text.
private struct ReactionChipView: View {
    let emoji: String
    let count: Int
    let isMine: Bool
    var onTap: () -> Void

    @State private var customImage: UIImage?

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 4) {
                if ReactionKey.isCustomEmoji(emoji) {
                    if let customImage {
                        Image(uiImage: customImage)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 16, height: 16)
                    } else {
                        Image(systemName: "face.smiling")
                            .font(.system(size: 14))
                    }
                } else {
                    Text(emoji)
                        .font(AegisType.caption)
                }
                Text("\(count)")
                    .font(AegisType.caption)
                    .monospacedDigit()
            }
            .foregroundStyle(isMine ? AegisColors.accent : AegisColors.textPrimary)
            .padding(.horizontal, AegisLayout.s)
            .padding(.vertical, 3)
            .background(isMine ? AegisColors.accentSoft : AegisColors.surfaceElevated)
            .clipShape(Capsule())
            .overlay {
                Capsule().stroke(isMine ? AegisColors.accent : AegisColors.separator, lineWidth: isMine ? 1 : 0.5)
            }
        }
        .accessibilityLabel("\(count) reactions of \(ReactionKey.isCustomEmoji(emoji) ? "custom emoji" : emoji)\(isMine ? ", including yours" : "")")
        .task {
            if ReactionKey.isCustomEmoji(emoji) {
                customImage = await EmojiPackStore.shared.image(forReactionKey: emoji)
            }
        }
    }
}

/// The long-press action sheet: reaction picker on top, message actions
/// below. Every control is wired to the view model.
private struct MessageActionsSheet: View {
    let message: Message
    @ObservedObject var viewModel: ConversationViewModel
    var onJumpToMessage: ((UUID) -> Void)?
    var onOpenThread: ((UUID) -> Void)?
    @Environment(\.dismiss) private var dismiss
    @State private var showingEditHistory = false
    @State private var showingPinExpiry = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ReactionPickerView { emoji in
                        dismiss()
                        Task { @MainActor in await viewModel.toggleReaction(emoji, on: message) }
                    }
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }

                Section {
                    Button {
                        viewModel.replyingTo = message
                        dismiss()
                    } label: {
                        Label("Reply", systemImage: "arrowshape.turn.up.left")
                    }
                    .accessibilityLabel("Reply to message")

                    Button {
                        dismiss()
                        onOpenThread?(message.threadRootID ?? message.id)
                    } label: {
                        Label(
                            message.isThreadReply ? "Open thread" : "Reply in thread…",
                            systemImage: "bubble.left.and.bubble.right"
                        )
                    }
                    .accessibilityLabel(message.isThreadReply ? "Open thread" : "Start or open thread")

                    if let body = message.body {
                        Button {
                            UIPasteboard.general.string = body
                            Haptics.selection()
                            dismiss()
                        } label: {
                            Label("Copy", systemImage: "doc.on.doc")
                        }
                    }

                    if viewModel.canEdit(message) {
                        Button {
                            viewModel.editingMessage = message
                            viewModel.draft = message.body ?? ""
                            dismiss()
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        .accessibilityHint(editHint)
                    }

                    Button {
                        Task { @MainActor in await viewModel.toggleStar(message) }
                        dismiss()
                    } label: {
                        Label(
                            message.isStarred ? "Unstar" : "Star",
                            systemImage: message.isStarred ? "star.slash" : "star"
                        )
                    }
                    .accessibilityHint("Stars stay on this device only")

                    if viewModel.canPin {
                        if message.isPinned {
                            Button {
                                Task { @MainActor in await viewModel.unpinMessage(message) }
                                dismiss()
                            } label: {
                                Label("Unpin", systemImage: "pin.slash")
                            }
                        } else {
                            Button {
                                showingPinExpiry = true
                            } label: {
                                Label("Pin", systemImage: "pin")
                            }
                            .accessibilityHint("Pin for everyone in this chat")
                        }
                    }

                    if message.isEdited {
                        Button {
                            showingEditHistory = true
                        } label: {
                            Label("Edit history", systemImage: "clock.arrow.circlepath")
                        }
                    }
                }

                if message.isFromMe, !message.isDeleted {
                    Section {
                        Button(role: .destructive) {
                            Task { @MainActor in await viewModel.deleteMessage(message) }
                            dismiss()
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                        .accessibilityHint("Deletes for everyone in this chat")
                    }
                }
            }
            .navigationTitle("Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $showingEditHistory) {
                EditHistoryView(message: message)
            }
            .sheet(isPresented: $showingPinExpiry) {
                PinExpirySheet { expiry in
                    Task { @MainActor in await viewModel.pinMessage(message, expiresAt: expiry) }
                    dismiss()
                }
            }
        }
    }

    private var editHint: String {
        if let remaining = viewModel.editWindowRemaining(for: message) {
            return "Editable for \(Formatters.duration(remaining)) more"
        }
        return "Edit this message"
    }
}

/// Pin duration picker: optional expiry for a shared pin.
private struct PinExpirySheet: View {
    var onPick: (Date?) -> Void
    @Environment(\.dismiss) private var dismiss

    private let options: [(label: String, date: Date?)] = [
        ("Until unpinned", nil),
        ("1 hour", Date().addingTimeInterval(3600)),
        ("24 hours", Date().addingTimeInterval(24 * 3600)),
        ("7 days", Date().addingTimeInterval(7 * 24 * 3600)),
    ]

    var body: some View {
        NavigationStack {
            List(options, id: \.label) { option in
                Button {
                    onPick(option.date)
                    dismiss()
                } label: {
                    Text(option.label)
                        .font(AegisType.body)
                        .foregroundStyle(AegisColors.textPrimary)
                        .frame(minHeight: AegisLayout.minTapTarget)
                }
                .accessibilityLabel("Pin \(option.label.lowercased())")
            }
            .navigationTitle("Pin duration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let conversation = SampleData.previewConversation(title: "Maya Chen")
    let vm = ConversationViewModel(conversation: conversation, contact: SampleData.previewContact(name: "Maya Chen"), appState: appState)
    return VStack(spacing: 12) {
        ForEach(SampleData.previewMessages(for: "Maya Chen").prefix(5)) { message in
            MessageBubbleView(message: message, viewModel: vm)
        }
    }
    .padding()
    .environmentObject(appState)
    .task { @MainActor in await vm.load() }
}
