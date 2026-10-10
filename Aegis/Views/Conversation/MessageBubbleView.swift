import SwiftUI
import UIKit

/// A single message bubble: reply context, body, attachments, reactions,
/// delivery state, and the full context menu (reply / react / copy / edit /
/// delete). Deleted messages render as tombstones; the layout never shifts.
struct MessageBubbleView: View {
    let message: Message
    @ObservedObject var viewModel: ConversationViewModel
    @EnvironmentObject private var appState: AppState

    @State private var showingReactions = false

    private let reactionEmojis = ["❤️", "👍", "😂", "😮", "😢", "🙏"]

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

                    if let replyID = message.replyToID,
                       let replied = viewModel.message(withId: replyID) {
                        replyPreview(for: replied)
                    }

                    if let attachment = message.attachment {
                        AttachmentContentView(attachment: attachment, viewModel: viewModel)
                    }

                    if let voiceNote = message.voiceNote {
                        VoiceNoteBubbleView(voiceNote: voiceNote, viewModel: viewModel)
                    }

                    if let body = message.body {
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
                .contextMenu { contextMenu }

                if !message.reactions.isEmpty {
                    reactionChips
                }
            }

            if !message.isFromMe { Spacer(minLength: AegisLayout.xxl) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
    }

    // MARK: - Subviews

    private func replyPreview(for replied: Message) -> some View {
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
        .accessibilityLabel("Replying to \(replied.body ?? "a message")")
    }

    private var metaRow: some View {
        HStack(spacing: AegisLayout.xs) {
            if message.isEphemeral {
                Image(systemName: "timer")
                    .font(.system(size: 10))
                    .accessibilityLabel("Disappearing message")
            }
            if message.isEdited {
                Text("edited")
                    .font(.system(size: 10))
                    .italic()
            }
            Text(Formatters.bubbleTime(message.sentAt))
                .font(.system(size: 10))
            if message.isFromMe {
                ReadReceiptView(status: message.status)
            }
        }
        .foregroundStyle(message.isFromMe ? AegisColors.textOnAccent.opacity(0.75) : AegisColors.textTertiary)
    }

    private var reactionChips: some View {
        HStack(spacing: AegisLayout.xs) {
            ForEach(message.sortedReactions, id: \.emoji) { reaction in
                let isMine = appState.identity.map { message.didReact(reaction.emoji, senderID: $0.id) } ?? false
                Button {
                    Task { @MainActor in await viewModel.toggleReaction(reaction.emoji, on: message) }
                } label: {
                    Text("\(reaction.emoji) \(reaction.count)")
                        .font(AegisType.caption)
                        .foregroundStyle(isMine ? AegisColors.accent : AegisColors.textPrimary)
                        .padding(.horizontal, AegisLayout.s)
                        .padding(.vertical, 3)
                        .background(isMine ? AegisColors.accentSoft : AegisColors.surfaceElevated)
                        .clipShape(Capsule())
                        .overlay {
                            Capsule().stroke(isMine ? AegisColors.accent : AegisColors.separator, lineWidth: isMine ? 1 : 0.5)
                        }
                }
                .accessibilityLabel("\(reaction.count) reactions of \(reaction.emoji)\(isMine ? ", including yours" : "")")
            }
        }
    }

    // MARK: - Context menu

    @ViewBuilder
    private var contextMenu: some View {
        ForEach(reactionEmojis, id: \.self) { emoji in
            Button {
                Task { @MainActor in await viewModel.toggleReaction(emoji, on: message) }
            } label: {
                Text("React \(emoji)")
            }
        }

        Button {
            viewModel.replyingTo = message
        } label: {
            Label("Reply", systemImage: "arrowshape.turn.up.left")
        }

        if let body = message.body {
            Button {
                UIPasteboard.general.string = body
                Haptics.selection()
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
        }

        if message.isFromMe, message.body != nil {
            Button {
                viewModel.editingMessage = message
                viewModel.draft = message.body ?? ""
            } label: {
                Label("Edit", systemImage: "pencil")
            }
        }

        Button(role: .destructive) {
            Task { @MainActor in await viewModel.deleteMessage(message) }
        } label: {
            Label("Delete", systemImage: "trash")
        }
    }

    private var accessibilityText: String {
        var parts: [String] = []
        if let name = viewModel.senderName(for: message) { parts.append(name) }
        if let body = message.body { parts.append(body) }
        if message.attachment != nil { parts.append("attachment") }
        if message.voiceNote != nil { parts.append("voice note") }
        parts.append(Formatters.bubbleTime(message.sentAt))
        return parts.joined(separator: ", ")
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
