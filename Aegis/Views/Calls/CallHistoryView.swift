import SwiftUI

/// Call history: direction, kind, duration, and outcome. Tap to call back;
/// long-press for video. Clearing is explicit and confirmed.
struct CallHistoryView: View {
    @StateObject private var viewModel: CallsViewModel
    @EnvironmentObject private var appState: AppState

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: CallsViewModel(appState: appState))
    }

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isLoading {
                    LoadingOverlayView(label: "Loading calls…")
                } else if viewModel.isEmpty {
                    EmptyStateView(
                        icon: "phone",
                        title: "No calls yet",
                        message: "Voice and video calls here are end-to-end encrypted. Start one from any conversation."
                    )
                } else {
                    callList
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Calls")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                if !viewModel.isEmpty {
                    ToolbarItem(placement: .primaryAction) {
                        Button("Clear") {
                            viewModel.showingClearConfirmation = true
                        }
                        .accessibilityLabel("Clear call history")
                    }
                }
            }
            .confirmationDialog("Clear call history?", isPresented: $viewModel.showingClearConfirmation, titleVisibility: .visible) {
                Button("Clear history", role: .destructive) {
                    Task { @MainActor in await viewModel.clearHistory() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes the call log from this device.")
            }
            .onAppear {
                Task { @MainActor in
                    await viewModel.load()
                }
            }
            .refreshable { @MainActor in
                await viewModel.load()
            }
        }
    }

    private var callList: some View {
        List {
            ForEach(viewModel.records) { record in
                CallRecordRow(record: record) {
                    Task { @MainActor in await viewModel.callBack(record, kind: .audio) }
                } onVideoCall: {
                    Task { @MainActor in await viewModel.callBack(record, kind: .video) }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
    }
}

private struct CallRecordRow: View {
    let record: CallRecord
    var onCall: () -> Void
    var onVideoCall: () -> Void

    var body: some View {
        Button(action: onCall) {
            HStack(spacing: AegisLayout.m) {
                AvatarView(displayName: record.contactName, size: AegisLayout.avatarM)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    Text(record.contactName)
                        .font(AegisType.body)
                        .foregroundStyle(record.endReason == .missed ? AegisColors.danger : AegisColors.textPrimary)
                    HStack(spacing: AegisLayout.xs) {
                        Image(systemName: directionIcon)
                            .font(.system(size: 11))
                            .foregroundStyle(record.endReason == .missed ? AegisColors.danger : AegisColors.textTertiary)
                            .accessibilityHidden(true)
                        Text(detailText)
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }

                Spacer()

                Image(systemName: record.kind == .video ? "video.fill" : "phone.fill")
                    .font(.system(size: 16))
                    .foregroundStyle(AegisColors.accent)
                    .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            }
            .padding(.vertical, AegisLayout.xs)
        }
        .contextMenu {
            Button {
                onCall()
            } label: {
                Label("Voice call", systemImage: "phone.fill")
            }
            Button {
                onVideoCall()
            } label: {
                Label("Video call", systemImage: "video.fill")
            }
        }
        .accessibilityLabel("\(record.kind == .video ? "Video" : "Voice") call with \(record.contactName), \(record.endReason.displayName)")
        .accessibilityHint("Double tap to call back")
    }

    private var directionIcon: String {
        switch record.direction {
        case .incoming: return "arrow.down.left"
        case .outgoing: return "arrow.up.right"
        }
    }

    private var detailText: String {
        var parts: [String] = [Formatters.chatListTimestamp(record.startedAt)]
        if let duration = record.duration, duration > 0 {
            parts.append(Formatters.duration(duration))
        } else {
            parts.append(record.endReason.displayName)
        }
        return parts.joined(separator: " · ")
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return CallHistoryView(appState: appState)
        .environmentObject(appState)
}
