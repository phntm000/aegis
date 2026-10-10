import SwiftUI

/// Shown when app lock is enabled and the app was backgrounded. Biometric
/// prompt fires on appear; the button is the fallback path.
struct LockScreenView: View {
    @EnvironmentObject private var appState: AppState
    @State private var isAuthenticating = false

    var body: some View {
        ZStack {
            AegisColors.background.ignoresSafeArea()
            VStack(spacing: AegisLayout.l) {
                Spacer()
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(AegisColors.accent)
                    .accessibilityHidden(true)
                Text("Aegis is locked")
                    .font(AegisType.title)
                    .foregroundStyle(AegisColors.textPrimary)
                Text("Your conversations are protected. Authenticate to continue.")
                    .font(AegisType.body)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)

                Button {
                    Task { @MainActor in await unlock() }
                } label: {
                    HStack {
                        if isAuthenticating {
                            ProgressView().tint(AegisColors.textOnAccent)
                        } else {
                            Image(systemName: biometricIcon)
                        }
                        Text("Unlock with \(appState.appLock.biometryLabel)")
                    }
                    .frame(minWidth: 220, minHeight: AegisLayout.minTapTarget)
                }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .disabled(isAuthenticating)
                .accessibilityLabel("Unlock Aegis with \(appState.appLock.biometryLabel)")

                if let error = appState.appLock.lastError {
                    Text(error)
                        .font(AegisType.footnote)
                        .foregroundStyle(AegisColors.danger)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, AegisLayout.xl)
                }
                Spacer()
                Text("Aegis never sends your biometrics anywhere — authentication happens on-device.")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)
                    .padding(.bottom, AegisLayout.xl)
            }
        }
        .task { @MainActor in
            await unlock()
        }
    }

    private var biometricIcon: String {
        switch appState.appLock.biometryType {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        default: return "lock.fill"
        }
    }

    private func unlock() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        defer { isAuthenticating = false }
        if await appState.appLock.unlock() {
            appState.privacy.unshield()
        }
    }
}

#Preview {
    LockScreenView()
        .environmentObject(AppState(factory: PreviewServiceFactory()))
}
