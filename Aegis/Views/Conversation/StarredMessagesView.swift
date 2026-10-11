import SwiftUI

/// Local-only starred messages for a conversation. Stars never sync —
/// this list is exactly what's on this device. Tapping a star jumps to
/// the message in the thread.
struct StarredMessagesView: View {
    @ObservedObject var viewModel: ConversationViewModel
    var onJump: (UUID) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isLoadingStarred {
                    LoadingOverlayView(label: "Loading starred…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if viewModel.starredMessages.isEmpty {
                    EmptyStateView(
                        icon: "star",
                        title: "No starred messages",
                        message: "Long-press any message and tap Star to keep it here. Stars stay on this device only."
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(viewModel.starredMessages) { message in
                        Button {
                            dismiss()
                            onJump(message.id)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(starredPreview(for: message))
                                    .font(AegisType.body)
                                    .foregroundStyle(AegisColors.textPrimary)
                                    .lineLimit(3)
                                Text(Formatters.bubbleTime(message.sentAt))
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                            .padding(.vertical, AegisLayout.xs)
                        }
                        .accessibilityLabel("Starred message: \(starredPreview(for: message))")
                        .accessibilityHint("Jump to message in conversation")
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                Task { @MainActor in await viewModel.toggleStar(message) }
                            } label: {
                                Label("Unstar", systemImage: "star.slash")
                            }
                            .accessibilityLabel("Remove star")
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Starred")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { await viewModel.loadStarred() }
            .refreshable { await viewModel.loadStarred() }
        }
    }

    private func starredPreview(for message: Message) -> String {
        if let body = message.body, !body.isEmpty { return body }
        if message.poll != nil { return "📊 \(message.poll?.question ?? "Poll")" }
        if message.voiceNote != nil { return "🎤 Voice note" }
        if message.attachment != nil { return "📎 Attachment" }
        return "Message"
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = ConversationViewModel(
        conversation: SampleData.previewConversation(title: "Maya Chen"),
        contact: nil,
        appState: appState
    )
    return StarredMessagesView(viewModel: vm, onJump: { _ in })
        .environmentObject(appState)
}
