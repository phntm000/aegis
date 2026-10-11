import SwiftUI

/// The in-call control cluster: mute, speaker, camera, screen share.
/// Each control reflects live state and is wired to the transport.
///
/// Screen sharing has three states: in-app app-content sharing (with
/// pause + on-device redaction), full-device sharing via the ReplayKit
/// Broadcast Upload Extension, and off.
struct CallControlsView: View {
    @ObservedObject var viewModel: ActiveCallViewModel

    private var isSharing: Bool {
        viewModel.call?.isScreenSharing == true || viewModel.call?.isBroadcastSharing == true
    }

    var body: some View {
        VStack(spacing: AegisLayout.l) {
            HStack(spacing: AegisLayout.xl) {
                control(
                    icon: viewModel.call?.isMuted == true ? "mic.slash.fill" : "mic.fill",
                    label: viewModel.call?.isMuted == true ? "Unmute" : "Mute",
                    isActive: viewModel.call?.isMuted == true
                ) {
                    Task { @MainActor in await viewModel.toggleMute() }
                }

                control(
                    icon: "speaker.wave.2.fill",
                    label: "Speaker",
                    isActive: viewModel.call?.isSpeakerOn == true
                ) {
                    Task { @MainActor in await viewModel.toggleSpeaker() }
                }

                if viewModel.call?.kind == .video {
                    control(
                        icon: viewModel.call?.isVideoEnabled == true ? "video.fill" : "video.slash.fill",
                        label: "Camera",
                        isActive: viewModel.call?.isVideoEnabled == true
                    ) {
                        Task { @MainActor in await viewModel.toggleVideo() }
                    }
                }

                shareControl
            }

            // While in-app screen sharing: pause + redact.
            if viewModel.call?.isScreenSharing == true {
                HStack(spacing: AegisLayout.xl) {
                    control(
                        icon: viewModel.call?.isScreenSharePaused == true ? "play.fill" : "pause.fill",
                        label: viewModel.call?.isScreenSharePaused == true ? "Resume" : "Pause",
                        isActive: viewModel.call?.isScreenSharePaused == true
                    ) {
                        Task { @MainActor in await viewModel.toggleScreenSharePaused() }
                    }

                    control(
                        icon: "eye.slash.fill",
                        label: "Redact",
                        isActive: !(viewModel.call?.screenShareRedactions.isEmpty ?? true)
                    ) {
                        viewModel.showingRedactSheet = true
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Screen share options")
            }

            // End call
            Button {
                Task { @MainActor in await viewModel.endCall() }
            } label: {
                Image(systemName: "phone.down.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(.white)
                    .frame(width: 72, height: 72)
                    .background(AegisColors.danger)
                    .clipShape(Circle())
            }
            .accessibilityLabel("End call")
        }
    }

    /// The share control: a plain toggle for in-app sharing when the
    /// broadcast extension isn't available, otherwise a menu offering both
    /// app-content and full-device sharing. Never a dead button.
    @ViewBuilder
    private var shareControl: some View {
        let sharing = isSharing
        let icon = sharing ? "rectangle.on.rectangle.slash" : "rectangle.on.rectangle"
        if viewModel.broadcastShareSupported, !sharing {
            Menu {
                Button("Share app screen") {
                    Task { @MainActor in await viewModel.toggleScreenShare() }
                }
                Button("Share full screen") {
                    viewModel.showingBroadcastPicker = true
                }
            } label: {
                controlContent(icon: icon, label: "Share", isActive: false)
            }
            .accessibilityLabel("Share screen. Choose app screen or full screen.")
        } else {
            control(icon: icon, label: "Share", isActive: sharing) {
                Task { @MainActor in await viewModel.toggleScreenShare() }
            }
        }
    }

    private func control(icon: String, label: String, isActive: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            controlContent(icon: icon, label: label, isActive: isActive)
        }
        .accessibilityLabel(label)
        .accessibilityValue(isActive ? "on" : "off")
    }

    private func controlContent(icon: String, label: String, isActive: Bool) -> some View {
        VStack(spacing: AegisLayout.xs) {
            Image(systemName: icon)
                .font(.system(size: 22))
                .foregroundStyle(isActive ? AegisColors.textOnAccent : AegisColors.textPrimary)
                .frame(width: 60, height: 60)
                .background(isActive ? AegisColors.accent : AegisColors.surfaceElevated)
                .clipShape(Circle())
            Text(label)
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textSecondary)
        }
    }
}
