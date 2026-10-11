import SwiftUI
import WebRTCBridge

// MARK: - Participant tile (video or avatar)

/// One participant in the room grid. Renders their camera when published
/// (via a per-peer video sink on this side's session UUID), otherwise an
/// avatar. The speaking ring is driven by locally computed audio levels.
struct ParticipantVideoTile: View {
    let participant: VoiceRoomParticipant
    let room: VoiceRoom
    let onSelect: () -> Void

    @EnvironmentObject private var appState: AppState

    private var callID: UUID? { room.videoCallIDs[participant.fingerprintHex] }

    var body: some View {
        Button(action: onSelect) {
            ZStack(alignment: .bottomLeading) {
                RoundedRectangle(cornerRadius: AegisLayout.radiusM)
                    .fill(AegisColors.surface)
                    .overlay {
                        if participant.isLocal, participant.isCameraOn {
                            localPreview
                        } else if participant.isCameraOn, let callID {
                            remoteVideo(callID: callID)
                        } else {
                            avatarContent
                        }
                    }
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
                    .overlay {
                        RoundedRectangle(cornerRadius: AegisLayout.radiusM)
                            .stroke(
                                participant.isSpeaking ? AegisColors.success : Color.clear,
                                lineWidth: 3
                            )
                    }

                // Name + state badges.
                VStack(alignment: .leading, spacing: 2) {
                    if mediaBadge != nil {
                        Text(mediaBadge!)
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(AegisColors.warning)
                            .clipShape(Capsule())
                    }
                    HStack(spacing: 4) {
                        if participant.isMuted {
                            Image(systemName: "mic.slash.fill")
                                .font(.caption2)
                                .foregroundStyle(.white)
                                .padding(4)
                                .background(Color.red.opacity(0.85))
                                .clipShape(Circle())
                        }
                        if participant.hasHandRaised {
                            Image(systemName: "hand.raised.fill")
                                .font(.caption2)
                                .foregroundStyle(.white)
                                .padding(4)
                                .background(AegisColors.accent.opacity(0.9))
                                .clipShape(Circle())
                        }
                        if room.mode == .stage, participant.isSpeaker, !participant.isLocal {
                            Image(systemName: "star.fill")
                                .font(.caption2)
                                .foregroundStyle(.white)
                                .padding(4)
                                .background(AegisColors.success.opacity(0.9))
                                .clipShape(Circle())
                        }
                        Spacer()
                        Text(participant.isLocal ? "You" : participant.displayName)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.black.opacity(0.45))
                            .clipShape(Capsule())
                    }
                }
                .padding(AegisLayout.s)
            }
            .frame(minHeight: 150)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityDescription)
        .accessibilityHint("Shows volume and speaker controls")
    }

    private var avatarContent: some View {
        VStack(spacing: AegisLayout.xs) {
            Circle()
                .fill(AegisColors.accent.opacity(0.15))
                .frame(width: 56, height: 56)
                .overlay {
                    Text(initials)
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(AegisColors.accent)
                }
            if participant.isSpeaking {
                Text("Speaking")
                    .font(.caption2)
                    .foregroundStyle(AegisColors.success)
            }
        }
    }

    private func remoteVideo(callID: UUID) -> some View {
        RemoteVideoView { sink in
            appState.transport.setVideoSink(sink, for: callID)
        }
        .onDisappear {
            appState.transport.setVideoSink(nil, for: callID)
        }
        .accessibilityHidden(true)
    }

    private var localPreview: some View {
        LocalPreviewView(
            onAttach: { renderer in
                Task { @MainActor in await appState.attachVoiceRoomLocalPreview(renderer) }
            },
            onDetach: { renderer in
                Task { @MainActor in await appState.detachVoiceRoomLocalPreview(renderer) }
            }
        )
        .accessibilityHidden(true)
    }

    private var mediaBadge: String? {
        switch participant.mediaState {
        case .connected: return nil
        case .connecting: return "Connecting…"
        case .reconnecting: return "Reconnecting…"
        case .failed: return "Connection failed"
        }
    }

    private var accessibilityDescription: String {
        var parts = [participant.isLocal ? "You" : participant.displayName]
        if participant.isSpeaking { parts.append("speaking") }
        if participant.isMuted { parts.append("muted") }
        if participant.isDeafened { parts.append("deafened") }
        if participant.isCameraOn { parts.append("camera on") }
        if participant.hasHandRaised { parts.append("hand raised") }
        if room.mode == .stage, participant.isSpeaker { parts.append("speaker") }
        return parts.joined(separator: ", ")
    }

    private var initials: String {
        let parts = participant.displayName.split(separator: " ")
        let first = parts.first?.prefix(1) ?? ""
        let second = parts.dropFirst().first?.prefix(1) ?? ""
        let result = String(first + second)
        return result.isEmpty ? "?" : result.uppercased()
    }
}

// MARK: - Local camera preview

/// Wraps an RTCMTLVideoView so the room UI can show the local camera. The
/// engine attaches it to the first camera-active peer connection's video
/// track (see WebRTCMediaEngine.refreshLocalPreviewLocked). Attach/detach
/// are deferred past the view-update pass and teardown, so no SwiftUI
/// state is mutated mid-render.
struct LocalPreviewView: UIViewRepresentable {
    var onAttach: (any RTCVideoRenderer) -> Void
    var onDetach: (any RTCVideoRenderer) -> Void

    final class Coordinator {
        var renderer: (any RTCVideoRenderer)?
        var onDetach: ((any RTCVideoRenderer) -> Void)?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> RTCMTLVideoView {
        let view = RTCMTLVideoView(frame: .zero)
        view.videoContentMode = .scaleAspectFill
        context.coordinator.renderer = view
        context.coordinator.onDetach = onDetach
        DispatchQueue.main.async { onAttach(view) }
        return view
    }

    func updateUIView(_ uiView: RTCMTLVideoView, context: Context) {}

    static func dismantleUIView(_ uiView: RTCMTLVideoView, coordinator: Coordinator) {
        if let renderer = coordinator.renderer {
            coordinator.onDetach?(renderer)
        }
        coordinator.renderer = nil
    }
}

// MARK: - Participant detail sheet

/// Per-participant controls: local-only volume, and (for the host) speaker
/// approval. Volume never leaves the device.
struct ParticipantDetailSheet: View {
    let fingerprintHex: String
    let room: VoiceRoom

    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var volume: Float = 1.0

    private var participant: VoiceRoomParticipant? {
        room.participants.first(where: { $0.fingerprintHex == fingerprintHex })
    }

    var body: some View {
        NavigationStack {
            if let participant {
                Form {
                    Section {
                        LabeledContent("Status", value: statusText(for: participant))
                        if room.mode == .stage {
                            LabeledContent("Floor", value: participant.isSpeaker ? "Speaker" : "Audience")
                        }
                    }
                    if !participant.isLocal {
                        Section {
                            VStack(alignment: .leading, spacing: AegisLayout.s) {
                                HStack {
                                    Text("Volume")
                                    Spacer()
                                    Text("\(Int(volume * 100))%")
                                        .monospacedDigit()
                                        .foregroundStyle(AegisColors.textSecondary)
                                }
                                Slider(value: Binding(
                                    get: { Double(volume) },
                                    set: { volume = Float($0) }
                                ), in: 0...1, step: 0.01) {
                                    Text("Volume")
                                } minimumValueLabel: {
                                    Image(systemName: "speaker.fill")
                                } maximumValueLabel: {
                                    Image(systemName: "speaker.wave.3.fill")
                                }
                                .onChange(of: volume) { _, newValue in
                                    Task { @MainActor in
                                        await appState.setVoiceRoomParticipantVolume(
                                            fingerprintHex: fingerprintHex, volume: newValue)
                                    }
                                }
                                Text("Applies only on this device — nobody else is affected.")
                                    .font(.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                            .padding(.vertical, AegisLayout.xs)
                        } header: {
                            Text("Hear them")
                        }
                    }
                    if room.isLocalHost, !participant.isLocal {
                        Section {
                            if participant.hasHandRaised {
                                Button("Approve as speaker") {
                                    Task { @MainActor in
                                        await appState.setVoiceRoomSpeakerApproval(
                                            fingerprintHex: fingerprintHex, approved: true)
                                        dismiss()
                                    }
                                }
                                Button("Deny hand raise", role: .destructive) {
                                    Task { @MainActor in
                                        await appState.setVoiceRoomSpeakerApproval(
                                            fingerprintHex: fingerprintHex, approved: false)
                                        dismiss()
                                    }
                                }
                            } else if room.mode == .stage, participant.isSpeaker {
                                Button("Remove from speakers", role: .destructive) {
                                    Task { @MainActor in
                                        await appState.setVoiceRoomSpeakerApproval(
                                            fingerprintHex: fingerprintHex, approved: false)
                                        dismiss()
                                    }
                                }
                            } else if room.mode == .stage {
                                Button("Make speaker") {
                                    Task { @MainActor in
                                        await appState.setVoiceRoomSpeakerApproval(
                                            fingerprintHex: fingerprintHex, approved: true)
                                        dismiss()
                                    }
                                }
                            }
                        } header: {
                            Text("Host controls")
                        }
                    }
                }
                .navigationTitle(participant.isLocal ? "You" : participant.displayName)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { dismiss() }
                    }
                }
                .onAppear { volume = participant.volume }
            }
        }
        .accessibilityLabel("Participant controls")
    }

    private func statusText(for participant: VoiceRoomParticipant) -> String {
        var parts: [String] = []
        parts.append(participant.isMuted ? "Muted" : "Unmuted")
        if participant.isCameraOn { parts.append("Camera on") }
        if participant.isSpeaking { parts.append("Speaking") }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Camera rationale

/// Shown before the system camera prompt: why Aegis wants the camera.
struct CameraRationaleSheet: View {
    var onEnable: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                Image(systemName: "video.fill")
                    .font(.largeTitle)
                    .foregroundStyle(AegisColors.accent)
                    .padding(.top, AegisLayout.xl)
                Text("Share your camera?")
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)
                Text("Your video goes only to the people in this room, encrypted end-to-end like everything else in Aegis. You can turn the camera off at any time.")
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)
                Spacer()
                Button("Enable camera") {
                    onEnable()
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityLabel("Enable camera")
                Button("Not now") { dismiss() }
                    .foregroundStyle(AegisColors.textSecondary)
                    .padding(.bottom, AegisLayout.xl)
            }
            .navigationTitle("Camera access")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }
}

// MARK: - Room control buttons

struct RoomControlButton: View {
    let icon: String
    let label: String
    let isActive: Bool
    var isEnabled: Bool = true
    var destructive: Bool = false
    var disabledHint: String? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            RoomControlButtonContent(icon: icon, label: label, isActive: isActive, destructive: destructive)
        }
        .disabled(!isEnabled)
        .opacity(isEnabled ? 1 : 0.45)
        .accessibilityLabel(label)
        .accessibilityValue(isActive ? "on" : "off")
        .accessibilityHint(disabledHint ?? "")
    }
}

struct RoomControlButtonContent: View {
    let icon: String
    let label: String
    let isActive: Bool
    var destructive: Bool = false

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(destructive ? .white : (isActive ? AegisColors.accent : AegisColors.textSecondary))
                .frame(width: 60, height: 60)
                .background(destructive ? Color.red : AegisColors.surface)
                .clipShape(Circle())
            Text(label)
                .font(.caption)
                .foregroundStyle(AegisColors.textSecondary)
        }
    }
}
