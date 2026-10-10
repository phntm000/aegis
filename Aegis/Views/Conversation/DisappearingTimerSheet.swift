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
        Option(label: "30 seconds", detail: "For the truly sensitive", interval: 30),
        Option(label: "1 minute", detail: "", interval: 60),
        Option(label: "1 hour", detail: "", interval: 3600),
        Option(label: "24 hours", detail: "A sensible default", interval: 24 * 3600),
        Option(label: "7 days", detail: "", interval: 7 * 24 * 3600),
    ]

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(options, id: \.self) { option in
                        Button {
                            Task { @MainActor in
                                await viewModel.setDisappearing(option.interval)
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
                                if viewModel.conversation.disappearingInterval == option.interval {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(AegisColors.accent)
                                        .accessibilityLabel("Selected")
                                }
                            }
                        }
                        .accessibilityLabel("Disappearing messages: \(option.label)")
                    }
                } footer: {
                    Text("When enabled, new messages disappear from both devices after the timer elapses. It doesn't prevent screenshots — use screenshot alerts for that.")
                }
            }
            .navigationTitle("Disappearing messages")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium])
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
