import SwiftUI

/// The pinned-message bar pinned to the top of the conversation thread,
/// plus the full pinned list sheet. Pins are shared (signed pin events)
/// and admin-controlled in groups/channels; an expired pin drops off
/// automatically.
struct PinnedMessageBar: View {
    @ObservedObject var viewModel: ConversationViewModel
    var onJump: (UUID) -> Void

    @State private var showingAll = false

    private var pins: [Message] { viewModel.activePins }

    var body: some View {
        if let latest = pins.first {
            HStack(spacing: AegisLayout.s) {
                Button {
                    onJump(latest.id)
                } label: {
                    HStack(spacing: AegisLayout.s) {
                        Image(systemName: "pin.fill")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.accent)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Pinned by \(latest.pin?.pinnedByName ?? "someone")")
                                .font(AegisType.captionStrong)
                                .foregroundStyle(AegisColors.accent)
                            Text(pinPreview(for: latest))
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                                .lineLimit(1)
                        }
                        if let expiresAt = latest.pin?.expiresAt {
                            Text("expires \(Formatters.duration(max(0, expiresAt.timeIntervalSinceNow)))")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textTertiary)
                        }
                    }
                }
                .accessibilityLabel("Pinned message: \(pinPreview(for: latest))")
                .accessibilityHint("Jump to pinned message")

                Spacer()

                if pins.count > 1 {
                    Button("\(pins.count)") {
                        showingAll = true
                    }
                    .font(AegisType.captionStrong)
                    .foregroundStyle(AegisColors.accent)
                    .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                    .accessibilityLabel("\(pins.count) pinned messages. View all.")
                }
            }
            .padding(.horizontal, AegisLayout.l)
            .padding(.vertical, AegisLayout.s)
            .background(AegisColors.accentSoft.opacity(0.6))
            .sheet(isPresented: $showingAll) {
                PinnedMessagesSheet(viewModel: viewModel, onJump: onJump)
            }
        }
    }

    private func pinPreview(for message: Message) -> String {
        if let body = message.body, !body.isEmpty { return body }
        if message.poll != nil { return "📊 \(message.poll?.question ?? "Poll")" }
        if message.voiceNote != nil { return "🎤 Voice note" }
        if message.attachment != nil { return "📎 Attachment" }
        return "Message"
    }
}

/// Full list of active pins with unpin controls (permission-gated).
struct PinnedMessagesSheet: View {
    @ObservedObject var viewModel: ConversationViewModel
    var onJump: (UUID) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.activePins.isEmpty {
                    EmptyStateView(
                        icon: "pin",
                        title: "No pinned messages",
                        message: viewModel.canPin
                            ? "Long-press a message and tap Pin to keep it at the top for everyone."
                            : "Only admins can pin messages here."
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(viewModel.activePins) { message in
                        HStack {
                            Button {
                                dismiss()
                                onJump(message.id)
                            } label: {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(pinPreview(for: message))
                                        .font(AegisType.body)
                                        .foregroundStyle(AegisColors.textPrimary)
                                        .lineLimit(3)
                                    HStack(spacing: AegisLayout.xs) {
                                        Text("Pinned by \(message.pin?.pinnedByName ?? "someone")")
                                        if let expiresAt = message.pin?.expiresAt {
                                            Text("· expires in \(Formatters.duration(max(0, expiresAt.timeIntervalSinceNow)))")
                                        }
                                    }
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                                }
                            }
                            .accessibilityLabel("Pinned message: \(pinPreview(for: message))")
                            Spacer()
                            if viewModel.canPin {
                                Button {
                                    Task { @MainActor in await viewModel.unpinMessage(message) }
                                } label: {
                                    Image(systemName: "pin.slash")
                                        .foregroundStyle(AegisColors.textSecondary)
                                }
                                .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                                .accessibilityLabel("Unpin message")
                            }
                        }
                        .padding(.vertical, AegisLayout.xs)
                    }
                    .listStyle(.plain)
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Pinned")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func pinPreview(for message: Message) -> String {
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
    return PinnedMessagesSheet(viewModel: vm, onJump: { _ in })
        .environmentObject(appState)
}
