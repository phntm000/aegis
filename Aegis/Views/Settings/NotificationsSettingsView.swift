import SwiftUI
import UIKit

/// Notification preferences. Aegis has no push server — notifications are
/// scheduled on-device when messages arrive while the app is backgrounded.
struct NotificationsSettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @EnvironmentObject private var appState: AppState

    @AppStorage(SettingsKeys.notificationsEnabled) private var enabled = true
    @AppStorage(SettingsKeys.notificationPreviews) private var previews = true
    @AppStorage(SettingsKeys.notificationSound) private var sound = true

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(appState: appState))
    }

    var body: some View {
        List {
            Section {
                Toggle(isOn: $enabled) {
                    Text("Message notifications")
                }
                .accessibilityLabel("Message notifications")
                .onChange(of: enabled) { _, newValue in
                    if newValue {
                        Task { @MainActor in await appState.notifications.requestAuthorization() }
                    }
                }

                HStack {
                    Text("System permission")
                    Spacer()
                    Text(statusLabel)
                        .font(AegisType.callout)
                        .foregroundStyle(statusColor)
                }
                .accessibilityLabel("Notification permission: \(statusLabel)")

                if appState.notifications.status == .denied {
                    Button("Open Settings to enable") {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.accent)
                }
            } footer: {
                Text("Notifications are generated on this device when messages arrive. There is no push server and no third party ever sees them.")
            }

            Section("Content") {
                Toggle(isOn: $previews) {
                    VStack(alignment: .leading) {
                        Text("Show message previews")
                        Text("Off shows only the sender's name")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }
                .disabled(!enabled)
                Toggle(isOn: $sound) {
                    Text("Sounds")
                }
                .disabled(!enabled)
            }
        }
        .navigationTitle("Notifications")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in
            await appState.notifications.refreshStatus()
        }
    }

    private var statusLabel: String {
        switch appState.notifications.status {
        case .authorized: return "Granted"
        case .denied: return "Denied"
        case .notDetermined: return "Not asked"
        case .provisional: return "Provisional"
        case .ephemeral: return "Ephemeral"
        @unknown default: return "Unknown"
        }
    }

    private var statusColor: Color {
        switch appState.notifications.status {
        case .authorized: return AegisColors.success
        case .denied: return AegisColors.danger
        default: return AegisColors.textSecondary
        }
    }
}

/// Face ID / Touch ID / passcode app lock.
struct AppLockSettingsView: View {
    @EnvironmentObject private var appState: AppState
    @AppStorage(SettingsKeys.appLock) private var appLockEnabled = false
    @State private var isAuthenticating = false
    @State private var error: String?

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(
                    get: { appLockEnabled },
                    set: { newValue in
                        Task { @MainActor in await setEnabled(newValue) }
                    }
                )) {
                    VStack(alignment: .leading) {
                        Text("Require \(appState.appLock.biometryLabel)")
                        Text("Lock Aegis when it goes to the background")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                }
                .disabled(isAuthenticating)
                .accessibilityLabel("Require \(appState.appLock.biometryLabel) to unlock")

                if appLockEnabled {
                    Button {
                        appState.appLock.lockNow()
                    } label: {
                        Label("Lock now", systemImage: "lock.fill")
                    }
                    .accessibilityLabel("Lock Aegis now")
                }

                if let error {
                    Text(error)
                        .font(AegisType.footnote)
                        .foregroundStyle(AegisColors.danger)
                }
            } footer: {
                Text("Biometric data never leaves your device — authentication is handled by iOS, and Aegis never sees it.")
            }
        }
        .navigationTitle("App lock")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func setEnabled(_ enabled: Bool) async {
        isAuthenticating = true
        error = nil
        defer { isAuthenticating = false }
        // Confirming with biometrics before enabling proves the device can
        // actually unlock — no setting that bricks the app.
        if await appState.appLock.unlock() {
            appLockEnabled = enabled
            if enabled { appState.appLock.lockNow() }
            Haptics.notification(.success)
        } else {
            error = "Authentication failed — app lock was not changed."
            Haptics.notification(.error)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        NotificationsSettingsView(appState: appState)
            .environmentObject(appState)
    }
}
