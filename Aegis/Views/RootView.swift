import SwiftUI

/// Phase router: onboarding → (locked) → main. Also hosts the privacy shield
/// overlay and the incoming-call screen above everything else.
struct RootView: View {
    @EnvironmentObject private var appState: AppState
    @AppStorage(SettingsKeys.appearance) private var appearanceRaw: String = AppearanceMode.system.rawValue

    var body: some View {
        ZStack {
            switch appState.phase {
            case .loading:
                LaunchView()
            case .onboarding:
                OnboardingFlowView(appState: appState)
            case .locked:
                LockScreenView()
            case .main:
                MainTabView(appState: appState)
            }

            // Privacy shield: opaque cover so the app switcher snapshot
            // never contains message content.
            if appState.privacy.isShielded {
                AegisColors.privacyShield
                    .ignoresSafeArea()
                    .transition(.opacity)
                    .accessibilityHidden(true)
            }
        }
        .preferredColorScheme(AppearanceMode(rawValue: appearanceRaw)?.colorScheme)
        .animation(.easeInOut(duration: 0.18), value: appState.privacy.isShielded)
        .fullScreenCover(item: $appState.incomingCall) { call in
            IncomingCallView(call: call)
                .environmentObject(appState)
        }
        .fullScreenCover(item: $appState.activeCall) { _ in
            ActiveCallView(appState: appState)
        }
    }
}

extension IncomingCall: Identifiable {}
extension ActiveCall: Identifiable {}

/// Minimal branded launch screen while identity bootstrap runs.
struct LaunchView: View {
    var body: some View {
        ZStack {
            AegisColors.background.ignoresSafeArea()
            VStack(spacing: AegisLayout.m) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(AegisColors.accent)
                    .accessibilityHidden(true)
                Text("Aegis")
                    .font(AegisType.largeTitle)
                    .foregroundStyle(AegisColors.textPrimary)
                ProgressView()
                    .tint(AegisColors.accent)
            }
        }
        .accessibilityLabel("Loading Aegis")
    }
}

#Preview {
    RootView()
        .environmentObject(AppState(factory: PreviewServiceFactory()))
}
