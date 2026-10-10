import SwiftUI

/// The in-call control cluster: mute, speaker, camera, screen share.
/// Each control reflects live state and is wired to the transport.
struct CallControlsView: View {
    @ObservedObject var viewModel: ActiveCallViewModel

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

                control(
                    icon: viewModel.call?.isScreenSharing == true ? "rectangle.on.rectangle.slash" : "rectangle.on.rectangle",
                    label: "Share",
                    isActive: viewModel.call?.isScreenSharing == true
                ) {
                    Task { @MainActor in await viewModel.toggleScreenShare() }
                }
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

    private func control(icon: String, label: String, isActive: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
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
        .accessibilityLabel(label)
        .accessibilityValue(isActive ? "on" : "off")
    }
}
