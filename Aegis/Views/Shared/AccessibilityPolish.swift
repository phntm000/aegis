import SwiftUI

/// Shared HIG / accessibility building blocks used across screens.
///
/// - `aegisMinimumTapTarget()`: guarantees the 44×44pt minimum touch target
///   (Apple HIG) for small inline controls like text buttons. It only grows
///   content that is smaller than 44pt — it never shrinks anything.
/// - `ErrorStateView`: the standard full-screen error state with a wired
///   Retry action. Screens must never present a bare spinner forever or
///   mislabel a load failure as "empty" — if `viewModel.error` is set and
///   there is nothing to show, use this.
extension View {
    func aegisMinimumTapTarget() -> some View {
        frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
    }
}

/// Full-screen error state: icon, title, the failure message, and a
/// prominent retry button that is always wired. Never a dead end.
struct ErrorStateView: View {
    let message: String
    var title: String = "Something went wrong"
    var retryTitle: String = "Try again"
    var onRetry: () -> Void

    var body: some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(AegisColors.warning)
                .accessibilityHidden(true)
            Text(title)
                .font(AegisType.titleSmall)
                .foregroundStyle(AegisColors.textPrimary)
            Text(message)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, AegisLayout.xl)
                .accessibilityLabel("Error: \(message)")
            Button(retryTitle, action: onRetry)
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .frame(minWidth: 160, minHeight: AegisLayout.minTapTarget)
                .padding(.top, AegisLayout.s)
                .accessibilityLabel(retryTitle)
                .accessibilityHint("Retries the last operation")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

#Preview {
    ErrorStateView(message: "Couldn't reach the local store. Your data is safe — try again.") {}
}
