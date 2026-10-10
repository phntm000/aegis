import SwiftUI

/// The active call screen: remote presence, call state / elapsed timer, and
/// controls. Video rendering is owned by the transport's media pipeline —
/// the app shows the contact's presence until frames arrive (see
/// INTEGRATION_NOTES.md for the video-sink API the transport must provide).
struct ActiveCallView: View {
    @EnvironmentObject private var appState: AppState
    @StateObject private var viewModel: ActiveCallViewModel

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: ActiveCallViewModel(appState: appState))
    }

    var body: some View {
        ZStack {
            AegisColors.background.ignoresSafeArea()

            VStack(spacing: AegisLayout.xl) {
                Spacer()

                if let call = appState.activeCall {
                    AvatarView(displayName: call.contactName, size: 110)
                        .accessibilityHidden(true)

                    VStack(spacing: AegisLayout.xs) {
                        Text(call.contactName)
                            .font(AegisType.title)
                            .foregroundStyle(AegisColors.textPrimary)
                        Text(statusText(for: call))
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textSecondary)
                            .monospacedDigit()
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(call.kind == .video ? "Video" : "Voice") call with \(call.contactName), \(statusText(for: call))")

                    if call.kind == .video && !call.isVideoEnabled {
                        Text("Camera is off")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textTertiary)
                            .padding(.horizontal, AegisLayout.m)
                            .padding(.vertical, AegisLayout.xs)
                            .background(AegisColors.surfaceElevated)
                            .clipShape(Capsule())
                    }
                } else {
                    ProgressView()
                        .tint(AegisColors.accent)
                }

                Spacer()

                CallControlsView(viewModel: viewModel)
                    .padding(.bottom, AegisLayout.xxl)
            }
            .padding()
        }
        .alert("Screen sharing", isPresented: Binding(
            get: { viewModel.screenShareError != nil },
            set: { if !$0 { viewModel.screenShareError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(viewModel.screenShareError ?? "")
        }
        .onAppear {
            viewModel.startTicker()
        }
        .onDisappear {
            viewModel.stopTicker()
        }
    }

    private func statusText(for call: ActiveCall) -> String {
        switch call.state {
        case .dialing: return "Dialing…"
        case .ringing: return "Ringing…"
        case .connecting: return "Connecting…"
        case .connected: return Formatters.callElapsed(viewModel.elapsed)
        case .ended: return "Ended"
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    appState.activeCall = ActiveCall(
        id: UUID(),
        contactID: UUID(),
        contactName: "Maya Chen",
        kind: .video,
        direction: .outgoing,
        state: .connected,
        isMuted: false,
        isSpeakerOn: true,
        isVideoEnabled: true,
        isScreenSharing: false,
        connectedAt: Date().addingTimeInterval(-125)
    )
    return ActiveCallView(appState: appState)
        .environmentObject(appState)
}
