import SwiftUI

/// The per-contact verification shield shown in conversation headers and
/// contact rows. Tapping opens the safety-number verification flow.
///
/// - unverified: outlined shield, neutral — "not yet verified"
/// - verified: filled shield, accent — "safety number confirmed"
/// - identityChanged: warning triangle — key changed, re-verify before trusting
struct VerificationShieldView: View {
    let state: VerificationState
    var size: CGFloat = 18

    var body: some View {
        Group {
            switch state {
            case .unverified:
                Image(systemName: "shield")
                    .foregroundStyle(AegisColors.textTertiary)
            case .verified:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundStyle(AegisColors.accent)
            case .identityChanged:
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundStyle(AegisColors.warning)
            }
        }
        .font(.system(size: size))
        .accessibilityLabel(accessibilityLabel)
    }

    private var accessibilityLabel: String {
        switch state {
        case .unverified: return "Contact not yet verified"
        case .verified: return "Contact verified"
        case .identityChanged: return "Warning: contact's identity key changed"
        }
    }
}

/// Full-width warning shown at the top of a conversation when the peer's
/// identity key changed since verification. Tapping opens SafetyNumberView.
struct IdentityChangedBanner: View {
    var onVerify: () -> Void
    var onDismiss: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            Button(action: onVerify) {
                HStack(spacing: AegisLayout.s) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(AegisColors.warning)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Safety number changed — tap to re-verify")
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.textPrimary)
                        Text("This contact's identity key changed. Verify before sharing anything sensitive.")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                        .accessibilityHidden(true)
                }
                .padding(AegisLayout.m)
            }
            .accessibilityLabel("Safety number changed. Tap to re-verify.")
            if let onDismiss {
                Divider()
                Button("Dismiss — show messages anyway", action: onDismiss)
                    .font(AegisType.captionStrong)
                    .foregroundStyle(AegisColors.textSecondary)
                    .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    .accessibilityLabel("Dismiss identity change warning")
                    .accessibilityHint("Shows new messages without verifying the new key. The contact stays flagged.")
            }
        }
        .background(AegisColors.warning.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
        .padding(.horizontal, AegisLayout.l)
    }
}

#Preview {
    VStack(spacing: 12) {
        HStack(spacing: 16) {
            VerificationShieldView(state: .unverified)
            VerificationShieldView(state: .verified)
            VerificationShieldView(state: .identityChanged)
        }
        IdentityChangedBanner(onVerify: {})
    }
    .padding()
}
