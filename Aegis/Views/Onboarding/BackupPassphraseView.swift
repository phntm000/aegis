import SwiftUI

/// Step 3 — encrypted backup passphrase. The passphrase encrypts the identity
/// backup; strength is enforced, and the copy is explicit that losing it means
/// losing recovery.
struct BackupPassphraseView: View {
    @ObservedObject var viewModel: OnboardingViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: AegisLayout.l) {
                if viewModel.backupComplete {
                    successCard
                } else {
                    formCard
                }
            }
            .padding(.horizontal, AegisLayout.l)
            .padding(.vertical, AegisLayout.m)
        }
    }

    private var formCard: some View {
        VStack(alignment: .leading, spacing: AegisLayout.m) {
            Text("This passphrase encrypts your identity backup. Write it down and keep it somewhere safe — if you lose it, the backup cannot be recovered. By anyone. That's the point.")
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)

            SecureField("Backup passphrase", text: $viewModel.passphrase)
                .textFieldStyle(.roundedBorder)
                .textContentType(.newPassword)
                .accessibilityLabel("Backup passphrase")
            SecureField("Confirm passphrase", text: $viewModel.confirmPassphrase)
                .textFieldStyle(.roundedBorder)
                .textContentType(.newPassword)
                .accessibilityLabel("Confirm backup passphrase")

            strengthMeter

            if !viewModel.confirmPassphrase.isEmpty,
               viewModel.passphrase != viewModel.confirmPassphrase {
                Text("Passphrases don't match.")
                    .font(AegisType.footnote)
                    .foregroundStyle(AegisColors.danger)
                    .accessibilityLabel("Passphrases don't match")
            }

            if let error = viewModel.backupError {
                ErrorBannerView(message: error, onDismiss: { viewModel.backupError = nil })
                    .padding(.horizontal, -AegisLayout.l)
            }

            Button {
                Task { @MainActor in await viewModel.createBackup() }
            } label: {
                HStack {
                    if viewModel.isBackingUp {
                        ProgressView().tint(AegisColors.textOnAccent)
                    }
                    Text(viewModel.isBackingUp ? "Encrypting backup…" : "Create encrypted backup")
                }
                .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
            }
            .buttonStyle(.borderedProminent)
            .tint(AegisColors.accent)
            .disabled(!viewModel.backupReady || viewModel.isBackingUp)
            .accessibilityLabel("Create encrypted backup")
        }
    }

    private var strengthMeter: some View {
        VStack(alignment: .leading, spacing: AegisLayout.xs) {
            HStack(spacing: AegisLayout.xs) {
                ForEach(0..<3) { i in
                    Capsule()
                        .fill(meterColor(for: i))
                        .frame(height: 6)
                        .accessibilityHidden(true)
                }
                Text(viewModel.passphrase.isEmpty ? "Enter a passphrase" : viewModel.passphraseStrength.displayName)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .padding(.leading, AegisLayout.s)
            }
            .accessibilityLabel("Passphrase strength: \(viewModel.passphraseStrength.displayName)")
            if viewModel.passphraseStrength == .weak, !viewModel.passphrase.isEmpty {
                Text("Use at least 8 characters — a few random words work well.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
            }
        }
    }

    private func meterColor(for index: Int) -> Color {
        guard !viewModel.passphrase.isEmpty else { return AegisColors.surfacePressed }
        let level: Int
        switch viewModel.passphraseStrength {
        case .weak: level = 1
        case .fair: level = 2
        case .strong: level = 3
        }
        guard index < level else { return AegisColors.surfacePressed }
        switch viewModel.passphraseStrength {
        case .weak: return AegisColors.danger
        case .fair: return AegisColors.warning
        case .strong: return AegisColors.success
        }
    }

    private var successCard: some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 48))
                .foregroundStyle(AegisColors.success)
                .accessibilityHidden(true)
            Text("Backup encrypted")
                .font(AegisType.titleSmall)
                .foregroundStyle(AegisColors.textPrimary)
            Text("Your identity is backed up with your passphrase. You can export it again anytime from Settings → Identity.")
                .font(AegisType.callout)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(AegisLayout.l)
        .background(AegisColors.surface)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))
        .accessibilityLabel("Backup encrypted successfully")
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return BackupPassphraseView(viewModel: OnboardingViewModel(appState: appState))
        .environmentObject(appState)
}
