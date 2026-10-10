import Foundation
import UIKit

/// Privacy defenses: app-switcher snapshot shielding and screenshot detection.
///
/// - Snapshot shield: iOS snapshots the UI when the app resigns active. We
///   cover the window with an opaque shield so message content never lands in
///   the switcher preview.
/// - Screenshot detection: when the user opts into screenshot alerts, a local
///   screenshot posts a notice into the visible conversation and notifies
///   peers via the transport.
@MainActor
final class PrivacyController: ObservableObject {
    weak var appState: AppState?

    @Published private(set) var isShielded = false

    private var monitorTask: Task<Void, Never>?

    func attach(appState: AppState) {
        self.appState = appState
        startScreenshotMonitoring()
    }

    /// Cover the UI (called on `scenePhase == .inactive`).
    func shield() {
        isShielded = true
    }

    /// Reveal the UI (called on `scenePhase == .active`).
    func unshield() {
        isShielded = false
    }

    private func startScreenshotMonitoring() {
        monitorTask?.cancel()
        monitorTask = Task { @MainActor [weak self] in
            let sequence = NotificationCenter.default.notifications(
                named: UIApplication.userDidTakeScreenshotNotification
            )
            for await _ in sequence {
                guard let self else { return }
                await self.handleScreenshotTaken()
            }
        }
    }

    private func handleScreenshotTaken() async {
        guard UserDefaults.standard.bool(forKey: SettingsKeys.screenshotAlerts) else { return }
        await appState?.reportLocalScreenshot()
    }
}
