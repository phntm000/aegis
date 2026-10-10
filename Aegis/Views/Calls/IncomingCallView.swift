import SwiftUI

/// Full-screen incoming call: contact, call kind, accept / decline.
/// Presented by RootView above everything; dismissal is driven by AppState.
struct IncomingCallView: View {
    let call: IncomingCall
    @EnvironmentObject private var appState: AppState
    @State private var isWorking = false

    var body: some View {
        ZStack {
            AegisColors.background.ignoresSafeArea()

            VStack(spacing: AegisLayout.l) {
                Spacer()

                AvatarView(displayName: call.contactName, size: 110)
                    .accessibilityHidden(true)

                VStack(spacing: AegisLayout.xs) {
                    Text(call.contactName)
                        .font(AegisType.title)
                        .foregroundStyle(AegisColors.textPrimary)
                    Label(
                        call.kind == .video ? "Incoming secure video call" : "Incoming secure voice call",
                        systemImage: call.kind == .video ? "video.fill" : "phone.fill"
                    )
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textSecondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Incoming \(call.kind == .video ? "video" : "voice") call from \(call.contactName)")

                Text("End-to-end encrypted")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
                    .padding(.horizontal, AegisLayout.m)
                    .padding(.vertical, AegisLayout.xs)
                    .background(AegisColors.surfaceElevated)
                    .clipShape(Capsule())

                Spacer()

                HStack(spacing: AegisLayout.xxl) {
                    // Decline
                    Button {
                        Task { @MainActor in await decline() }
                    } label: {
                        Image(systemName: "phone.down.fill")
                            .font(.system(size: 28))
                            .foregroundStyle(.white)
                            .frame(width: 72, height: 72)
                            .background(AegisColors.danger)
                            .clipShape(Circle())
                    }
                    .disabled(isWorking)
                    .accessibilityLabel("Decline call")

                    // Accept
                    Button {
                        Task { @MainActor in await accept() }
                    } label: {
                        Image(systemName: "phone.fill")
                            .font(.system(size: 28))
                            .foregroundStyle(.white)
                            .frame(width: 72, height: 72)
                            .background(AegisColors.success)
                            .clipShape(Circle())
                    }
                    .disabled(isWorking)
                    .accessibilityLabel("Accept call")
                }
                .padding(.bottom, AegisLayout.xxl)
            }
            .padding()
        }
    }

    private func accept() async {
        isWorking = true
        defer { isWorking = false }
        Haptics.impact(.medium)
        await appState.answerIncomingCall()
    }

    private func decline() async {
        isWorking = true
        defer { isWorking = false }
        await appState.declineIncomingCall()
    }
}

#Preview {
    IncomingCallView(call: IncomingCall(
        id: UUID(),
        contactID: UUID(),
        contactName: "Maya Chen",
        kind: .video,
        receivedAt: Date()
    ))
    .environmentObject(AppState(factory: PreviewServiceFactory()))
}
