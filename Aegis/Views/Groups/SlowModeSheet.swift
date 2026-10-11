import AegisModeration
import SwiftUI

/// Slow-mode picker: per-channel rate limit from 5 seconds to 6 hours.
/// Admin-settable, with role exemptions. Enforced client-side from the
/// signed channel policy; bypass attempts are visible as invalid events.
struct SlowModeSheet: View {
    @ObservedObject var viewModel: ChannelPermissionsViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var selection: TimeInterval?

    init(viewModel: ChannelPermissionsViewModel) {
        self.viewModel = viewModel
        _selection = State(initialValue: viewModel.slowModeInterval)
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        selection = nil
                    } label: {
                        checkRow(title: "Off", selected: selection == nil)
                    }
                    .accessibilityLabel("Slow mode off")
                    ForEach(SlowModeEnforcer.presets, id: \.self) { interval in
                        Button {
                            selection = interval
                        } label: {
                            checkRow(
                                title: SlowModeEnforcer.label(for: interval),
                                selected: selection == interval
                            )
                        }
                        .accessibilityLabel("Slow mode \(SlowModeEnforcer.label(for: interval))")
                    }
                } header: {
                    Text("Minimum time between messages")
                } footer: {
                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("Each member may post once per interval. Owners, admins, and moderators are exempt.")
                        Text("Slow mode is enforced by every honest client from the signed channel state — a modified client that posts faster has its messages rejected as invalid events.")
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            .navigationTitle("Slow mode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        Task { @MainActor in
                            await viewModel.setSlowMode(selection)
                            dismiss()
                        }
                    }
                    .disabled(viewModel.isWorking)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func checkRow(title: String, selected: Bool) -> some View {
        HStack {
            Text(title)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textPrimary)
            Spacer()
            if selected {
                Image(systemName: "checkmark")
                    .foregroundStyle(AegisColors.accent)
                    .accessibilityHidden(true)
            }
        }
        .contentShape(Rectangle())
        .frame(minHeight: AegisLayout.minTapTarget)
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let vm = ChannelPermissionsViewModel(
        conversation: SampleData.previewConversation(title: "Design sync"),
        appState: appState
    )
    return SlowModeSheet(viewModel: vm)
        .environmentObject(appState)
}
