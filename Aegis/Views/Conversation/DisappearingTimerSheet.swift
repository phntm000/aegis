import SwiftUI

/// Disappearing-message timer picker. Applies to new messages from the moment
/// it's set; both sides purge expired messages locally.
struct DisappearingTimerSheet: View {
    @ObservedObject var viewModel: ConversationViewModel
    @Environment(\.dismiss) private var dismiss

    private struct Option: Hashable {
        let label: String
        let detail: String
        let interval: TimeInterval?
    }

    private let options: [Option] = [
        Option(label: "Off", detail: "Messages are kept", interval: nil),
        Option(label: "10 seconds", detail: "For the truly sensitive", interval: 10),
        Option(label: "30 seconds", detail: "", interval: 30),
        Option(label: "1 minute", detail: "", interval: 60),
        Option(label: "1 hour", detail: "", interval: 3600),
        Option(label: "24 hours", detail: "A sensible default", interval: 24 * 3600),
        Option(label: "7 days", detail: "", interval: 7 * 24 * 3600),
    ]

    @State private var afterRead: Bool = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(options, id: \.self) { option in
                        Button {
                            Task { @MainActor in
                                await viewModel.setDisappearing(option.interval, afterRead: afterRead)
                                dismiss()
                            }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(option.label)
                                        .font(AegisType.body)
                                        .foregroundStyle(AegisColors.textPrimary)
                                    if !option.detail.isEmpty {
                                        Text(option.detail)
                                            .font(AegisType.caption)
                                            .foregroundStyle(AegisColors.textSecondary)
                                    }
                                }
                                Spacer()
                                if isSelected(option) {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(AegisColors.accent)
                                        .accessibilityLabel("Selected")
                                }
                            }
                        }
                        .accessibilityLabel("Disappearing messages: \(option.label)")
                    }
                } header: {
                    EmptyView()
                } footer: {
                    Text("When enabled, new messages disappear from both devices after the timer elapses. It doesn't prevent screenshots — use screenshot alerts for that.")
                }

                Section("Timer starts") {
                    Toggle("After the message is read", isOn: $afterRead)
                        .accessibilityHint("When off, the timer starts when the message is sent")
                    Text("After-read mode starts the countdown when the recipient opens the chat. Your own messages expire when they're read by the other side.")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
            }
            .onAppear {
                afterRead = viewModel.conversation.disappearingAfterRead
            }
            .navigationTitle("Disappearing messages")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func isSelected(_ option: Option) -> Bool {
        viewModel.conversation.disappearingInterval == option.interval
            && viewModel.conversation.disappearingAfterRead == (afterRead && option.interval != nil)
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = ConversationViewModel(
        conversation: SampleData.previewConversation(title: "Maya Chen"),
        contact: nil,
        appState: appState
    )
    return DisappearingTimerSheet(viewModel: vm)
}
