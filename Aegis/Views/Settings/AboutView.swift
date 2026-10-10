import SwiftUI

/// About Aegis: version, the threat-model summary in plain language, and the
/// honest limits. No marketing copy — just what it does and doesn't promise.
struct AboutView: View {
    var body: some View {
        List {
            Section {
                VStack(spacing: AegisLayout.m) {
                    Image(systemName: "shield.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(AegisColors.accent)
                        .accessibilityHidden(true)
                    Text("Aegis")
                        .font(AegisType.title)
                        .foregroundStyle(AegisColors.textPrimary)
                    Text("Version \(appVersion)")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, AegisLayout.m)
            }

            Section("What Aegis protects") {
                aboutRow(
                    icon: "lock.fill",
                    text: "Every message, call, and file is end-to-end encrypted. Your identity is a keypair generated on this device — there is no account, no phone number, no email."
                )
                aboutRow(
                    icon: "eye.slash.fill",
                    text: "Relays store and forward ciphertext they cannot read. With sealed sender on, they can't even see who is messaging whom."
                )
                aboutRow(
                    icon: "house.fill",
                    text: "LAN-only mode keeps all traffic inside your local network. Nothing reaches the internet at all."
                )
            }

            Section("Honest limits") {
                aboutRow(
                    icon: "exclamationmark.triangle.fill",
                    text: "Encryption can't stop someone you talk to from screenshotting or re-typing what you said. Screenshot alerts make it visible, not impossible."
                )
                aboutRow(
                    icon: "exclamationmark.triangle.fill",
                    text: "If your device itself is compromised — malware with full access — no messenger can protect you. Keep iOS updated."
                )
                aboutRow(
                    icon: "exclamationmark.triangle.fill",
                    text: "Losing your backup passphrase means losing your identity permanently. There is no recovery desk."
                )
            }

            Section("Free & open") {
                aboutRow(
                    icon: "gift.fill",
                    text: "Aegis is free forever. The app and the relay are open source — audit them, or host the relay yourself."
                )
            }
        }
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(version) (\(build))"
    }

    private func aboutRow(icon: String, text: String) -> some View {
        HStack(alignment: .top, spacing: AegisLayout.m) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundStyle(AegisColors.accent)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text(text)
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textPrimary)
        }
        .padding(.vertical, AegisLayout.xs)
    }
}

#Preview {
    NavigationStack {
        AboutView()
    }
}
