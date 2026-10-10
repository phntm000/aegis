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

    private var screenshotObserver: NSObjectProtocol?

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
        stopScreenshotMonitoring()
        // Closure observer (not the async sequence): `Notification` is not
        // Sendable, which Swift 6 rejects in `for await`.
        screenshotObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.handleScreenshotTaken()
            }
        }
    }

    private func stopScreenshotMonitoring() {
        if let observer = screenshotObserver {
            NotificationCenter.default.removeObserver(observer)
            screenshotObserver = nil
        }
    }

    private func handleScreenshotTaken() async {
        guard UserDefaults.standard.bool(forKey: SettingsKeys.screenshotAlerts) else { return }
        await appState?.reportLocalScreenshot()
    }
}
