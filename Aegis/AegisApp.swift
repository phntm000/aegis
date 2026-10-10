import SwiftUI

@main
struct AegisApp: App {
    @StateObject private var launcher = LaunchCoordinator()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Sane defaults for first launch; Settings can change all of these.
        UserDefaults.standard.register(defaults: [
            SettingsKeys.sealedSender: true,
            SettingsKeys.readReceiptsDefault: true,
            SettingsKeys.typingIndicatorsDefault: true,
            SettingsKeys.screenshotAlerts: false,
            SettingsKeys.disappearingDefault: 0,
            SettingsKeys.appLock: false,
            SettingsKeys.appearance: AppearanceMode.system.rawValue,
            SettingsKeys.notificationsEnabled: true,
            SettingsKeys.notificationPreviews: true,
            SettingsKeys.notificationSound: true,
            SettingsKeys.relayMode: RelayConfig.Mode.automatic.rawValue,
        ])
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if let appState = launcher.appState {
                    RootView()
                        .environmentObject(appState)
                        .task {
                            await appState.bootstrap()
                        }
                        .onChange(of: scenePhase) { _, phase in
                            switch phase {
                            case .inactive:
                                // Cover content before iOS snapshots it for the switcher.
                                appState.privacy.shield()
                            case .background:
                                appState.appLock.lockIfEnabled()
                                // Persist ratchet + group session snapshots before
                                // the OS suspends us, so conversations resume
                                // without re-establishment on the next launch.
                                Task { await appState.crypto.flushSessions() }
                            case .active:
                                appState.privacy.unshield()
                                appState.notifications.clearDelivered()
                            @unknown default:
                                break
                            }
                        }
                } else if let error = launcher.launchError {
                    // Fail closed, explained: the encrypted store could not
                    // be opened, so nothing is decrypted or shown.
                    LaunchErrorView(error: error) {
                        launcher.retry()
                    }
                } else {
                    LaunchView()
                }
            }
        }
    }
}
