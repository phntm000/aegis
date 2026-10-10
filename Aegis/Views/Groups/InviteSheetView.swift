import SwiftUI
import UIKit

/// Share a group/channel invite: QR for in-person, link + copy for remote.
/// The invite encodes the group id and inviter identity; the crypto layer
/// validates it on receipt.
struct InviteSheetView: View {
    let inviteCode: String
    let groupName: String

    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.l) {
                Text("Invite to \(groupName)")
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)

                QRCodeView(payload: inviteCode, size: 220)

                Text("Anyone with this code can request to join. Review new members in the member list.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)

                HStack(spacing: AegisLayout.m) {
                    Button {
                        UIPasteboard.general.string = inviteCode
                        copied = true
                        Haptics.notification(.success)
                        Task { @MainActor in
                            try? await Task.sleep(nanoseconds: 1_500_000_000)
                            await MainActor.run { copied = false }
                        }
                    } label: {
                        Label(copied ? "Copied" : "Copy code", systemImage: copied ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    }
                    .buttonStyle(.bordered)
                    .tint(AegisColors.accent)
                    .accessibilityLabel("Copy invite code")

                    ShareLink(item: inviteCode, subject: Text("Join \(groupName) on Aegis")) {
                        Label("Share", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .accessibilityLabel("Share invite link")
                }
                .padding(.horizontal, AegisLayout.l)

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
}

#Preview {
    InviteSheetView(inviteCode: "aegis-group:sample-invite-code", groupName: "Design sync")
}
