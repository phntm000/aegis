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
                    if call.kind == .video && call.state == .connected {
                        // Live remote video. The WebRTC layer feeds decoded
                        // frames through the transport's media router into
                        // this sink; the avatar returns when video is off.
                        RemoteVideoView { sink in
                            appState.transport.setVideoSink(sink, for: call.id)
                        }
                        .frame(maxWidth: .infinity, maxHeight: 320)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                        .padding(.horizontal, AegisLayout.m)
                        .onDisappear {
                            appState.transport.setVideoSink(nil, for: call.id)
                        }
                    } else {
                        AvatarView(displayName: call.contactName, size: 110)
                            .accessibilityHidden(true)
                    }

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

                if let call = appState.activeCall, let sas = call.callSAS {
                    sasVerificationSection(for: call, sas: sas)
                }

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

    /// The SAS verification ceremony: both parties read the 4 characters
    /// aloud and confirm they match, binding the media keys to the verified
    /// conversation (see docs/CRYPTO.md §11). Shown only once both DTLS
    /// fingerprints are known — no ceremony for a SAS that binds nothing.
    @ViewBuilder
    private func sasVerificationSection(for call: ActiveCall, sas: String) -> some View {
        switch call.sasVerification {
        case .verified:
            Label("Call verified", systemImage: "checkmark.shield.fill")
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.success)
                .padding(.horizontal, AegisLayout.m)
                .padding(.vertical, AegisLayout.xs)
                .background(AegisColors.surfaceElevated)
                .clipShape(Capsule())
                .accessibilityLabel("Call verified. The security codes matched.")
        case .mismatch:
            VStack(spacing: AegisLayout.xs) {
                Label("Security codes don't match", systemImage: "exclamationmark.shield.fill")
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.danger)
                Text("Someone may be intercepting this call. Hang up if you're unsure.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, AegisLayout.m)
            .padding(.vertical, AegisLayout.s)
            .background(AegisColors.danger.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Warning. Security codes don't match. Someone may be intercepting this call.")
        case .unverified:
            VStack(spacing: AegisLayout.s) {
                Text("Verify this call")
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textPrimary)
                Text(sas.map(String.init).joined(separator: " "))
                    .font(.system(.title, design: .monospaced).weight(.bold))
                    .foregroundStyle(AegisColors.textPrimary)
                    .accessibilityLabel("Security code: \(sas.map(String.init).joined(separator: ", "))")
                Text("Read these characters aloud with \(call.contactName). If they match, no one can listen in.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                HStack(spacing: AegisLayout.m) {
                    Button("They match") { viewModel.confirmSAS(match: true) }
                        .buttonStyle(.borderedProminent)
                    Button("Don't match") { viewModel.confirmSAS(match: false) }
                        .buttonStyle(.bordered)
                }
            }
            .padding(AegisLayout.m)
            .background(AegisColors.surfaceElevated)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .padding(.horizontal, AegisLayout.m)
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
