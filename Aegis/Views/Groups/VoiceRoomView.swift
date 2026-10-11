import AVFoundation
import SwiftUI
import UIKit

// MARK: - Voice Room UI
//
// Banner + full room view for group voice rooms. The room now carries video:
// each participant tile renders their camera when published, the local user
// gets a picture-in-picture preview, and per-participant volume, speaking
// indicators, and stage/open-floor modes are all wired to VoiceRoomManager.
//
// States: joining (spinner) → joined (grid) → failed (error + retry).
// Permission-denied states (mic/camera) show a rationale with a Settings
// link instead of a dead toggle.

/// Compact banner shown in group conversations: join button when a room is
/// live, or a "start room" affordance when none is active.
struct VoiceRoomBannerView: View {
    let conversation: Conversation
    @EnvironmentObject private var appState: AppState
    @State private var showingRoom = false

    private var room: VoiceRoom? { appState.voiceRoomState }
    private var isThisRoom: Bool { room?.conversationID == conversation.id }

    var body: some View {
        Button {
            if isThisRoom {
                showingRoom = true
            } else {
                Task { @MainActor in await appState.joinVoiceRoom(conversation) }
                showingRoom = true
            }
        } label: {
            HStack(spacing: AegisLayout.s) {
                Image(systemName: isThisRoom ? "waveform.circle.fill" : "phone.circle.fill")
                    .foregroundStyle(isThisRoom ? AegisColors.accent : AegisColors.textSecondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isThisRoom ? "Voice room" : "Start voice room")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(AegisColors.textPrimary)
                    if let room, isThisRoom {
                        Text("\(room.activeCount) in room")
                            .font(.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    } else {
                        Text("Talk with group members")
                            .font(.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }
                Spacer()
                if isThisRoom {
                    Text("Tap to open")
                        .font(.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                } else {
                    Text("Join")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(AegisColors.accent)
                }
            }
            .padding(.horizontal, AegisLayout.m)
            .padding(.vertical, AegisLayout.s)
            .background(AegisColors.surface)
            .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, AegisLayout.m)
        .padding(.top, AegisLayout.s)
        .accessibilityLabel(isThisRoom ? "Open voice room" : "Join voice room")
        .sheet(isPresented: $showingRoom) {
            if appState.voiceRoomState != nil {
                VoiceRoomView()
                    .environmentObject(appState)
            }
        }
    }
}

/// The active voice room: join states, participant video grid, stage
/// controls, and mute/camera/deafen/leave.
struct VoiceRoomView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var confirmLeave = false
    @State private var showingCameraRationale = false
    @State private var selectedParticipantID: String?

    private var room: VoiceRoom? { appState.voiceRoomState }

    var body: some View {
        NavigationStack {
            Group {
                switch room?.joinState ?? .idle {
                case .idle, .joining:
                    joiningView
                case .failed(let message):
                    failedView(message: message)
                case .joined:
                    if let room {
                        roomView(room)
                    } else {
                        roomEndedView
                    }
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Voice room")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .confirmationDialog("Leave the voice room?", isPresented: $confirmLeave, titleVisibility: .visible) {
                Button("Leave", role: .destructive) {
                    Task { @MainActor in
                        await appState.leaveVoiceRoom()
                        dismiss()
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
            .sheet(isPresented: $showingCameraRationale) {
                CameraRationaleSheet {
                    showingCameraRationale = false
                    Task { @MainActor in
                        await appState.setVoiceRoomCameraEnabled(true)
                    }
                }
            }
            .sheet(isPresented: Binding(
                get: { selectedParticipantID != nil },
                set: { if !$0 { selectedParticipantID = nil } }
            )) {
                if let fingerprint = selectedParticipantID, let room {
                    ParticipantDetailSheet(fingerprintHex: fingerprint, room: room)
                        .environmentObject(appState)
                }
            }
            .alert("Camera access denied", isPresented: $appState.voiceRoomCameraDeniedAlert) {
                Button("Open Settings") { openAppSettings() }
                Button("Not now", role: .cancel) {}
            } message: {
                Text("Aegis needs camera access to publish your video. You can keep participating with audio only.")
            }
        }
    }

    // MARK: - Join states

    private var joiningView: some View {
        VStack(spacing: AegisLayout.m) {
            ProgressView()
                .tint(AegisColors.accent)
                .scaleEffect(1.2)
            Text("Joining room…")
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityLabel("Joining voice room")
    }

    private func failedView(message: String) -> some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(AegisColors.danger)
            Text("Couldn't join the room")
                .font(AegisType.headline)
                .foregroundStyle(AegisColors.textPrimary)
            Text(message)
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, AegisLayout.xl)
            Button("Try again") {
                Task { @MainActor in await appState.retryVoiceRoomJoin() }
            }
            .buttonStyle(.borderedProminent)
            .accessibilityLabel("Retry joining the voice room")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var roomEndedView: some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: "phone.down.circle")
                .font(.largeTitle)
                .foregroundStyle(AegisColors.textSecondary)
            Text("The voice room has ended.")
                .foregroundStyle(AegisColors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Room

    private func roomView(_ room: VoiceRoom) -> some View {
        VStack(spacing: 0) {
            header(room)

            if room.micPermissionDenied {
                permissionBanner(
                    icon: "mic.slash.fill",
                    text: "Microphone is off — others can't hear you.",
                    actionLabel: "Open Settings"
                )
            }
            if room.cameraPermissionDenied {
                permissionBanner(
                    icon: "video.slash.fill",
                    text: "Camera access is off — video stays disabled.",
                    actionLabel: "Open Settings"
                )
            }

            if room.mode == .stage {
                stageBanner(room)
            }

            ScrollView {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 150), spacing: AegisLayout.s)],
                    spacing: AegisLayout.s
                ) {
                    ForEach(room.sortedParticipants) { participant in
                        ParticipantVideoTile(
                            participant: participant,
                            room: room,
                            onSelect: { selectedParticipantID = participant.fingerprintHex }
                        )
                    }
                }
                .padding(.horizontal, AegisLayout.m)
                .padding(.top, AegisLayout.s)
            }

            if room.isLocalHost, room.mode == .stage, !room.raisedHands.isEmpty {
                raisedHandsPanel(room)
            }

            Spacer(minLength: 0)

            controlRow(room)
                .padding(.vertical, AegisLayout.m)
        }
    }

    private func header(_ room: VoiceRoom) -> some View {
        VStack(spacing: 4) {
            HStack(spacing: AegisLayout.s) {
                Text(room.groupName)
                    .font(AegisType.headline)
                    .foregroundStyle(AegisColors.textPrimary)
                modeBadge(room.mode)
            }
            .padding(.top, AegisLayout.m)
            Text("\(room.activeCount) participant\(room.activeCount == 1 ? "" : "s") · end-to-end encrypted")
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textSecondary)
                .padding(.bottom, AegisLayout.s)
                .accessibilityLabel("\(room.activeCount) participants. End-to-end encrypted. \(room.mode == .stage ? "Stage mode." : "Open floor.")")
        }
    }

    private func modeBadge(_ mode: VoiceRoomMode) -> some View {
        Text(mode == .stage ? "Stage" : "Open floor")
            .font(.caption2)
            .foregroundStyle(AegisColors.textOnAccent)
            .padding(.horizontal, AegisLayout.s)
            .padding(.vertical, 2)
            .background(mode == .stage ? AegisColors.accent : AegisColors.textTertiary)
            .clipShape(Capsule())
    }

    private func stageBanner(_ room: VoiceRoom) -> some View {
        let local = room.participants.first(where: \.isLocal)
        let canTalk = local.map { canTransmit(mode: .stage, participant: $0) } ?? false
        return HStack(spacing: AegisLayout.s) {
            Image(systemName: "person.3.fill")
                .foregroundStyle(AegisColors.accent)
            Text(canTalk
                 ? "Stage mode — you have the floor."
                 : "Stage mode — only speakers can talk. Raise your hand to request the floor.")
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textSecondary)
        }
        .padding(.horizontal, AegisLayout.m)
        .padding(.vertical, AegisLayout.s)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AegisColors.accent.opacity(0.08))
        .accessibilityElement(children: .combine)
    }

    private func permissionBanner(icon: String, text: String, actionLabel: String) -> some View {
        HStack(spacing: AegisLayout.s) {
            Image(systemName: icon)
                .foregroundStyle(AegisColors.warning)
            Text(text)
                .font(AegisType.caption)
                .foregroundStyle(AegisColors.textPrimary)
            Spacer()
            Button(actionLabel) { openAppSettings() }
                .font(AegisType.caption.weight(.semibold))
                .foregroundStyle(AegisColors.accent)
        }
        .padding(.horizontal, AegisLayout.m)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.warning.opacity(0.12))
    }

    private func raisedHandsPanel(_ room: VoiceRoom) -> some View {
        VStack(alignment: .leading, spacing: AegisLayout.s) {
            Text("Raised hands (\(room.raisedHands.count))")
                .font(AegisType.caption.weight(.semibold))
                .foregroundStyle(AegisColors.textSecondary)
                .padding(.horizontal, AegisLayout.m)
            ForEach(room.raisedHands) { participant in
                HStack {
                    Text(participant.displayName)
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Button("Approve") {
                        Task { @MainActor in
                            await appState.setVoiceRoomSpeakerApproval(
                                fingerprintHex: participant.fingerprintHex, approved: true)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .accessibilityLabel("Approve \(participant.displayName) as speaker")
                    Button("Deny") {
                        Task { @MainActor in
                            await appState.setVoiceRoomSpeakerApproval(
                                fingerprintHex: participant.fingerprintHex, approved: false)
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityLabel("Deny \(participant.displayName)'s hand raise")
                }
                .padding(.horizontal, AegisLayout.m)
            }
        }
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.surface)
    }

    // MARK: - Controls

    private func controlRow(_ room: VoiceRoom) -> some View {
        let local = room.participants.first(where: \.isLocal)
        let stageBlocked = room.mode == .stage && !(local.map { canTransmit(mode: .stage, participant: $0) } ?? true)
        return HStack(spacing: AegisLayout.l) {
            RoomControlButton(
                icon: room.localMuted ? "mic.slash.fill" : "mic.fill",
                label: room.localMuted ? "Unmute" : "Mute",
                isActive: !room.localMuted,
                isEnabled: !stageBlocked,
                disabledHint: stageBlocked ? "Only speakers can unmute on stage" : nil
            ) {
                Task { @MainActor in
                    await appState.setVoiceRoomMuted(!room.localMuted)
                }
            }
            RoomControlButton(
                icon: room.localCameraOn ? "video.fill" : "video.slash.fill",
                label: "Camera",
                isActive: room.localCameraOn
            ) {
                handleCameraToggle(room: room)
            }
            RoomControlButton(
                icon: "speaker.slash.fill",
                label: room.localDeafened ? "Undeafen" : "Deafen",
                isActive: !room.localDeafened
            ) {
                Task { @MainActor in
                    await appState.setVoiceRoomDeafened(!room.localDeafened)
                }
            }
            if room.mode == .stage, let local, !canTransmit(mode: .stage, participant: local) {
                RoomControlButton(
                    icon: local.hasHandRaised ? "hand.raised.fill" : "hand.raised",
                    label: local.hasHandRaised ? "Lower hand" : "Raise hand",
                    isActive: local.hasHandRaised
                ) {
                    Task { @MainActor in
                        await appState.raiseVoiceRoomHand(!local.hasHandRaised)
                    }
                }
            }
            if room.isLocalHost {
                Menu {
                    Button("Open floor") {
                        Task { @MainActor in await appState.setVoiceRoomMode(.openFloor) }
                    }
                    Button("Stage") {
                        Task { @MainActor in await appState.setVoiceRoomMode(.stage) }
                    }
                } label: {
                    RoomControlButtonContent(
                        icon: room.mode == .stage ? "person.3.fill" : "person.2.fill",
                        label: "Mode",
                        isActive: false
                    )
                }
                .accessibilityLabel("Room mode: \(room.mode == .stage ? "stage" : "open floor"). Change room mode.")
            }
            RoomControlButton(
                icon: "phone.down.fill",
                label: "Leave",
                isActive: false,
                destructive: true
            ) {
                confirmLeave = true
            }
        }
    }

    private func handleCameraToggle(room: VoiceRoom) {
        if room.localCameraOn {
            Task { @MainActor in await appState.setVoiceRoomCameraEnabled(false) }
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .notDetermined:
            // Show our rationale before the system prompt.
            showingCameraRationale = true
        case .denied, .restricted:
            appState.voiceRoomCameraDeniedAlert = true
        case .authorized:
            Task { @MainActor in await appState.setVoiceRoomCameraEnabled(true) }
        @unknown default:
            break
        }
    }

    private func openAppSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
}
