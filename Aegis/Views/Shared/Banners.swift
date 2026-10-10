import SwiftUI

/// Slim inline banner for errors with a dismiss action.
struct ErrorBannerView: View {
    let message: String
    var onDismiss: (() -> Void)?

    var body: some View {
        HStack(spacing: AegisLayout.s) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(AegisColors.danger)
                .accessibilityHidden(true)
            Text(message)
                .font(AegisType.footnote)
                .foregroundStyle(AegisColors.textPrimary)
                .lineLimit(3)
            Spacer()
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .foregroundStyle(AegisColors.textSecondary)
                        .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                }
                .accessibilityLabel("Dismiss error")
            }
        }
        .padding(AegisLayout.m)
        .background(AegisColors.surfaceElevated)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
        .overlay {
            RoundedRectangle(cornerRadius: AegisLayout.radiusM)
                .stroke(AegisColors.danger.opacity(0.4), lineWidth: 1)
        }
        .padding(.horizontal, AegisLayout.l)
        .accessibilityLabel("Error: \(message)")
    }
}

/// Connection status banner. Informational for LAN-only, actionable for
/// offline / relay-unreachable (with a Retry control wired to the transport).
struct ConnectionBannerView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        switch appState.connectionState {
        case .offline:
            banner(
                icon: "wifi.slash",
                text: "You're offline. Messages will send when you reconnect.",
                tint: AegisColors.danger,
                showRetry: true
            )
        case .relayUnreachable:
            banner(
                icon: "exclamationmark.icloud.fill",
                text: "Relay unreachable — retrying. LAN peers still work.",
                tint: AegisColors.warning,
                showRetry: true
            )
        case .lanOnly:
            banner(
                icon: "house.fill",
                text: "LAN-only mode. No internet traffic leaves this network.",
                tint: AegisColors.success,
                showRetry: false
            )
        case .localNetworkOnly:
            banner(
                icon: "house.fill",
                text: "No relay configured — running on local network only. Add your own relay in Settings to reach beyond it.",
                tint: AegisColors.textSecondary,
                showRetry: false
            )
        case .relayConnecting:
            banner(
                icon: "arrow.triangle.2.circlepath",
                text: "Connecting…",
                tint: AegisColors.textSecondary,
                showRetry: false
            )
        case .relayConnected:
            EmptyView()
        }
    }

    private func banner(icon: String, text: String, tint: Color, showRetry: Bool) -> some View {
        HStack(spacing: AegisLayout.s) {
            Image(systemName: icon)
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(text)
                .font(AegisType.footnote)
                .foregroundStyle(AegisColors.textPrimary)
            Spacer()
            if showRetry {
                Button("Retry") {
                    Task { @MainActor in await appState.transport.retryConnection() }
                }
                .font(AegisType.captionStrong)
                .foregroundStyle(AegisColors.accent)
                .frame(minHeight: AegisLayout.minTapTarget)
                .accessibilityLabel("Retry connection")
            }
        }
        .padding(.horizontal, AegisLayout.l)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.surfaceElevated)
    }
}

/// Full-screen loading state with an optional label.
struct LoadingOverlayView: View {
    var label: String = "Loading…"

    var body: some View {
        VStack(spacing: AegisLayout.m) {
            ProgressView()
                .tint(AegisColors.accent)
                .scaleEffect(1.2)
            Text(label)
                .font(AegisType.footnote)
                .foregroundStyle(AegisColors.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityLabel(label)
    }
}

#Preview {
    VStack(spacing: 16) {
        ErrorBannerView(message: "Couldn't send. Check your connection and try again.", onDismiss: {})
        LoadingOverlayView(label: "Decrypting…")
    }
}
