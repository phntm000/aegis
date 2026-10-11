import SwiftUI
import UIKit

/// Semantic color tokens for Aegis.
///
/// Design language: Linear meets Signal — quiet, confident, precise. No neon,
/// no gamer gradients. One restrained accent, generous neutral surfaces, and
/// full light/dark support via dynamic providers (no asset catalog needed).
///
/// Rule: views reference only these tokens, never raw hex or system colors
/// directly, so the palette can be tuned in exactly one place.
enum AegisColors {
    // MARK: - Surfaces

    /// Default app background.
    static let background = dynamic(light: 0xF6F7F9, dark: 0x0D0E11)
    /// Grouped / secondary background (lists, sheets).
    static let backgroundSecondary = dynamic(light: 0xEDEFF2, dark: 0x14161B)
    /// Cards, bubbles, cells.
    static let surface = dynamic(light: 0xFFFFFF, dark: 0x1A1D23)
    /// Elevated cards, popovers, composer.
    static let surfaceElevated = dynamic(light: 0xFFFFFF, dark: 0x23262E)
    /// Pressed / selected fill.
    static let surfacePressed = dynamic(light: 0xE7EAEE, dark: 0x2B2F38)

    // MARK: - Text

    static let textPrimary = dynamic(light: 0x14161B, dark: 0xF2F4F7)
    static let textSecondary = dynamic(light: 0x5B6370, dark: 0xA4ADBB)
    static let textTertiary = dynamic(light: 0x8B93A1, dark: 0x6B7482)
    /// Text on top of the accent fill. Always near-white.
    static let textOnAccent = Color(white: 1.0)

    // MARK: - Accent & status

    /// The single brand accent. Calm, desaturated blue.
    static let accent = dynamic(light: 0x2F62D6, dark: 0x6B93F5)
    /// Soft accent wash for highlights and selected states.
    static let accentSoft = dynamic(light: 0xE4EBFD, dark: 0x1D2947)
    static let success = dynamic(light: 0x1E9E57, dark: 0x3ED598)
    static let warning = dynamic(light: 0xB7791F, dark: 0xE5A83B)
    static let danger = dynamic(light: 0xD64545, dark: 0xF26D6D)
    /// Secondary categorical hue (storage charts, settings iconography).
    static let purple = dynamic(light: 0x7C4DFF, dark: 0xA78BFA)

    // MARK: - Chat

    /// Outgoing message bubble fill.
    static let bubbleOutgoing = dynamic(light: 0x2F62D6, dark: 0x3B6FE0)
    /// Incoming message bubble fill.
    static let bubbleIncoming = dynamic(light: 0xE9EBEF, dark: 0x23262E)

    // MARK: - Chrome

    static let separator = dynamic(light: 0xE1E4E9, dark: 0x262A32)
    static let overlay = Color.black.opacity(0.45)
    /// Scrim behind the privacy shield shown in the app switcher.
    static let privacyShield = dynamic(light: 0xF6F7F9, dark: 0x0D0E11)
}

// MARK: - Private helper

private func dynamic(light: UInt32, dark: UInt32) -> Color {
    Color(uiColor: UIColor { traits in
        let hex = traits.userInterfaceStyle == .dark ? dark : light
        return UIColor(
            red: CGFloat((hex >> 16) & 0xFF) / 255.0,
            green: CGFloat((hex >> 8) & 0xFF) / 255.0,
            blue: CGFloat(hex & 0xFF) / 255.0,
            alpha: 1.0
        )
    })
}
