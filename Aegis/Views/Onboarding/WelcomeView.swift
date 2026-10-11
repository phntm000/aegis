import SwiftUI

/// Step 1 — the "no account" explainer. Sets the mental model before anything
/// is generated: identity is a keypair, there is nothing to sign up for.
struct WelcomeView: View {
    var onContinue: () -> Void
    @State private var showingLink = false
    @EnvironmentObject private var appState: AppState

    var body: some View {
        VStack(spacing: AegisLayout.xl) {
            Spacer()
            Image(systemName: "shield.fill")
                .font(.system(size: 72))
                .foregroundStyle(AegisColors.accent)
                .accessibilityHidden(true)
            Text("Private by architecture,\nnot by promise.")
                .font(AegisType.title)
                .multilineTextAlignment(.center)
                .foregroundStyle(AegisColors.textPrimary)

            VStack(alignment: .leading, spacing: AegisLayout.l) {
                explainerRow(
                    icon: "key.fill",
                    title: "No account, no phone number, no email",
                    body: "Your identity is a cryptographic keypair generated on this device. There is nothing to sign up for — and nothing to leak."
                )
                explainerRow(
                    icon: "lock.fill",
                    title: "End-to-end encrypted, always",
                    body: "Messages, calls, groups, and files are encrypted before they leave your phone. No one in the middle can read them — including us."
                )
                explainerRow(
                    icon: "server.rack",
                    title: "Free forever, yours to host",
                    body: "The relay code is open source. Go LAN-only, or self-host a relay in minutes."
                )
            }
            .padding(.horizontal, AegisLayout.l)

            Spacer()
            Button("Get started", action: onContinue)
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                .padding(.horizontal, AegisLayout.l)
                .accessibilityLabel("Get started with Aegis")
            Button("Link to an existing device") {
                showingLink = true
            }
            .font(AegisType.callout)
            .foregroundStyle(AegisColors.accent)
            .frame(minHeight: AegisLayout.minTapTarget)
            .padding(.top, AegisLayout.s)
            .accessibilityLabel("Link this device to an existing Aegis device")
        }
        .sheet(isPresented: $showingLink) {
            LinkDeviceOnboardingView()
        }
    }

    private func explainerRow(icon: String, title: String, body: String) -> some View {
        HStack(alignment: .top, spacing: AegisLayout.m) {
            Image(systemName: icon)
                .font(.system(size: 20))
                .foregroundStyle(AegisColors.accent)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: AegisLayout.xs) {
                Text(title)
                    .font(AegisType.bodyStrong)
                    .foregroundStyle(AegisColors.textPrimary)
                Text(body)
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textSecondary)
            }
        }
    }
}

#Preview {
    WelcomeView(onContinue: {})
}
