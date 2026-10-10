import SwiftUI

/// UserDefaults keys for app settings. Grouped here so Settings views and
/// core controllers agree on storage without string duplication.
enum SettingsKeys {
    // Privacy
    static let sealedSender = "privacy.sealedSender"
    static let readReceiptsDefault = "privacy.readReceiptsDefault"
    static let typingIndicatorsDefault = "privacy.typingIndicatorsDefault"
    static let screenshotAlerts = "privacy.screenshotAlerts"
    static let disappearingDefault = "privacy.disappearingDefault" // seconds, 0 = off

    // Security
    static let appLock = "security.appLock"

    // Appearance
    static let appearance = "appearance.mode"

    // Notifications
    static let notificationsEnabled = "notifications.enabled"
    static let notificationPreviews = "notifications.previews"
    static let notificationSound = "notifications.sound"

    // Relay
    static let relayMode = "relay.mode"
    static let relayCustomURL = "relay.customURL"
}

/// Appearance mode persisted in Settings.
enum AppearanceMode: String, Sendable, CaseIterable {
    case system
    case light
    case dark

    var displayName: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }
}
