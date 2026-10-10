import SwiftUI

// MARK: - Voice Room UI
//
// Banner + full room view for group voice rooms. The banner lives at the top
// of group conversations; tapping it (or Join) opens the room sheet.

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

/// The active voice room: participant grid + mute/deafen/leave.
struct VoiceRoomView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var confirmLeave = false

    private var room: VoiceRoom? { appState.voiceRoomState }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if let room {
                    Text(room.groupName)
                        .font(.headline)
                        .padding(.top, AegisLayout.m)
                    Text("\(room.activeCount) participant\(room.activeCount == 1 ? "" : "s") · end-to-end encrypted")
                        .font(.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .padding(.bottom, AegisLayout.m)

                    ScrollView {
                        LazyVGrid(
                            columns: [GridItem(.adaptive(minimum: 104), spacing: AegisLayout.s)],
                            spacing: AegisLayout.s
                        ) {
                            ForEach(room.sortedParticipants) { participant in
                                ParticipantTile(participant: participant)
                            }
                        }
                        .padding(.horizontal, AegisLayout.m)
                    }

                    Spacer()

                    HStack(spacing: AegisLayout.l) {
                        RoomControlButton(
                            icon: room.localMuted ? "mic.slash.fill" : "mic.fill",
                            label: room.localMuted ? "Unmute" : "Mute",
                            isActive: !room.localMuted
                        ) {
                            Task { @MainActor in
                                await appState.setVoiceRoomMuted(!room.localMuted)
                            }
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
                        RoomControlButton(
                            icon: "phone.down.fill",
                            label: "Leave",
                            isActive: false,
                            destructive: true
                        ) {
                            confirmLeave = true
                        }
                    }
                    .padding(.vertical, AegisLayout.m)
                } else {
                    // The room closed while the sheet was open.
                    VStack(spacing: AegisLayout.m) {
                        Image(systemName: "phone.down.circle")
                            .font(.largeTitle)
                            .foregroundStyle(AegisColors.textSecondary)
                        Text("The voice room has ended.")
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        }
    }
}

private struct ParticipantTile: View {
    let participant: VoiceRoomParticipant

    var body: some View {
        VStack(spacing: AegisLayout.xs) {
            ZStack(alignment: .bottomTrailing) {
                Circle()
                    .fill(AegisColors.accent.opacity(0.15))
                    .frame(width: 64, height: 64)
                    .overlay {
                        Text(initials)
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(AegisColors.accent)
                    }
                if participant.isMuted || participant.isDeafened {
                    Image(systemName: participant.isDeafened ? "speaker.slash.fill" : "mic.slash.fill")
                        .font(.caption2)
                        .foregroundStyle(.white)
                        .padding(5)
                        .background(Color.red)
                        .clipShape(Circle())
                        .offset(x: 4, y: 4)
                }
            }
            Text(participant.displayName)
                .font(.caption)
                .lineLimit(1)
                .foregroundStyle(AegisColors.textPrimary)
            if participant.isLocal {
                Text("You")
                    .font(.caption2)
                    .foregroundStyle(AegisColors.textSecondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.surface)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
        .accessibilityLabel("\(participant.displayName)\(participant.isMuted ? ", muted" : "")")
    }

    private var initials: String {
        let parts = participant.displayName.split(separator: " ")
        let first = parts.first?.prefix(1) ?? ""
        let second = parts.dropFirst().first?.prefix(1) ?? ""
        let result = String(first + second)
        return result.isEmpty ? "?" : result.uppercased()
    }
}

private struct RoomControlButton: View {
    let icon: String
    let label: String
    let isActive: Bool
    var destructive: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
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
        .accessibilityLabel(label)
    }
}
