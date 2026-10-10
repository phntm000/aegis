import Foundation
import UserNotifications

/// `UNNotificationSettings` is effectively immutable (all properties are
/// readonly); the SDK just doesn't annotate it.
extension UNNotificationSettings: @unchecked Sendable {}

/// Local notifications for messages and calls arriving while the app is
/// backgrounded. Aegis has no push server — these are scheduled on-device
/// when an envelope arrives and the app isn't in the foreground.
@MainActor
final class NotificationManager: ObservableObject {
    @Published private(set) var status: UNAuthorizationStatus = .notDetermined

    private var previewsEnabled: Bool {
        UserDefaults.standard.bool(forKey: SettingsKeys.notificationPreviews)
    }

    private var notificationsEnabled: Bool {
        UserDefaults.standard.bool(forKey: SettingsKeys.notificationsEnabled)
    }

    private var soundEnabled: Bool {
        UserDefaults.standard.bool(forKey: SettingsKeys.notificationSound)
    }

    func refreshStatus() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        status = settings.authorizationStatus
    }

    @discardableResult
    func requestAuthorization() async -> Bool {
        do {
            let granted = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            await refreshStatus()
            return granted
        } catch {
            return false
        }
    }

    func notifyMessage(from senderName: String, preview: String?, conversationID: UUID) {
        guard notificationsEnabled, status == .authorized else { return }
        let content = UNMutableNotificationContent()
        content.title = senderName
        // Respect the "show previews" setting: hide content, keep the ping.
        content.body = previewsEnabled ? (preview ?? "New message") : "New message"
        content.sound = soundEnabled ? .default : nil
        content.userInfo = ["conversationID": conversationID.uuidString]
        let request = UNNotificationRequest(
            identifier: "msg-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    func notifyIncomingCall(from senderName: String) {
        guard notificationsEnabled, status == .authorized else { return }
        let content = UNMutableNotificationContent()
        content.title = "Incoming secure call"
        content.body = senderName
        content.sound = soundEnabled ? .default : nil
        let request = UNNotificationRequest(
            identifier: "call-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    func clearDelivered() {
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
    }
}
