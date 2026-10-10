import SwiftUI

/// Standard empty state: icon, title, explanation, optional action.
/// Used by chat list, contacts, calls, and search — never a bare blank screen.
struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: icon)
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(AegisColors.textTertiary)
                .accessibilityHidden(true)
            Text(title)
                .font(AegisType.titleSmall)
                .foregroundStyle(AegisColors.textPrimary)
            Text(message)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, AegisLayout.xl)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .tint(AegisColors.accent)
                    .padding(.top, AegisLayout.s)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

#Preview {
    EmptyStateView(
        icon: "bubble.left.and.bubble.right",
        title: "No conversations yet",
        message: "Add a contact to start your first end-to-end encrypted conversation.",
        actionTitle: "Add contact",
        action: {}
    )
}
