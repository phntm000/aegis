import SwiftUI

/// Blocking launch screen shown when the encrypted store cannot be opened.
///
/// Fail closed, explained: nothing is decrypted and no conversation is
/// reachable from this screen. The usual cause is the device Keychain being
/// unavailable (e.g. launched before first unlock after a reboot, or a
/// device-management restriction). Retry is offered because the condition
/// can be transient.
struct LaunchErrorView: View {
    let error: Error
    var onRetry: () -> Void

    var body: some View {
        ZStack {
            AegisColors.background.ignoresSafeArea()
            ScrollView {
                VStack(spacing: AegisLayout.l) {
                    Spacer(minLength: AegisLayout.xxl)
                    Image(systemName: "exclamationmark.shield.fill")
                        .font(.system(size: 52))
                        .foregroundStyle(AegisColors.warning)
                        .accessibilityHidden(true)
                    Text("Aegis couldn't start")
                        .font(AegisType.title)
                        .foregroundStyle(AegisColors.textPrimary)
                    Text("Your encrypted database couldn't be opened, so nothing was decrypted. Your messages are still safely encrypted on this device.")
                        .font(AegisType.body)
                        .foregroundStyle(AegisColors.textSecondary)
                        .multilineTextAlignment(.center)
                    VStack(alignment: .leading, spacing: AegisLayout.s) {
                        Text("What you can try:")
                            .font(AegisType.headline)
                            .foregroundStyle(AegisColors.textPrimary)
                        tipRow("Tap Try Again — this is sometimes temporary.")
                        tipRow("Unlock your device, then reopen Aegis.")
                        tipRow("Restart your device if the problem persists.")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(AegisColors.surface)
                    .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
                    Button(action: onRetry) {
                        Text("Try Again")
                            .font(AegisType.headline)
                            .frame(maxWidth: .infinity)
                            .frame(minHeight: 44)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .accessibilityHint("Attempts to open the encrypted database again")
                    Text("Technical detail: \(error.localizedDescription)")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                        .multilineTextAlignment(.center)
                    Spacer(minLength: AegisLayout.xxl)
                }
                .padding(.horizontal, AegisLayout.l)
            }
        }
        .accessibilityLabel("Aegis couldn't start. Your encrypted database couldn't be opened.")
    }

    private func tipRow(_ text: String) -> some View {
        HStack(alignment: .top, spacing: AegisLayout.s) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(AegisColors.accent)
                .accessibilityHidden(true)
            Text(text)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textSecondary)
        }
    }
}

#Preview {
    LaunchErrorView(error: NSError(domain: "Aegis", code: -34018,
                                   userInfo: [NSLocalizedDescriptionKey: "database key unavailable: loadFailed(-34018)"])) {}
}
