import SwiftUI

/// Redeem an `aegis-group:` invite code: establishes an encrypted 1:1
/// session with the inviter from the embedded prekey bundle and sends a
/// join request. A moderator of the group/channel approves the request;
/// this device becomes a member only after approval (the real invite +
/// sender-key distributions arrive then).
struct JoinGroupView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var code = ""
    @State private var isWorking = false
    @State private var error: String?
    @State private var requestSent = false

    var onRequested: (() -> Void)?

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.l) {
                Text("Join a group or channel")
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)

                Text("Paste an invite code shared by a group admin. A join request is sent to them — you'll become a member once they approve it.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)

                TextField("aegis-group:…", text: $code, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .font(AegisType.fingerprint)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .padding(.horizontal, AegisLayout.l)
                    .accessibilityLabel("Invite code")

                if let error {
                    Text(error)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.danger)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, AegisLayout.l)
                        .accessibilityLabel("Error: \(error)")
                }

                if requestSent {
                    Label("Request sent — waiting for approval", systemImage: "checkmark.circle.fill")
                        .font(AegisType.body)
                        .foregroundStyle(AegisColors.success)
                        .padding(.top, AegisLayout.s)
                }

                Button {
                    Task { @MainActor in await sendRequest() }
                } label: {
                    if isWorking {
                        ProgressView()
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    } else {
                        Text("Send join request")
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .disabled(isWorking || requestSent || code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .padding(.horizontal, AegisLayout.l)
                .accessibilityLabel("Send join request")

                Spacer()
            }
            .padding(.top, AegisLayout.xl)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func sendRequest() async {
        error = nil
        requestSent = false
        isWorking = true
        defer { isWorking = false }
        do {
            try await appState.transport.requestGroupJoin(code: code)
            requestSent = true
            Haptics.notification(.success)
            onRequested?()
        } catch {
            self.error = error.localizedDescription
            Haptics.notification(.error)
        }
    }
}

#Preview {
    JoinGroupView()
        .environmentObject(AppState(factory: PreviewServiceFactory()))
}
