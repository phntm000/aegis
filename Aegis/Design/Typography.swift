import SwiftUI

/// Typography tokens for Aegis.
///
/// Every style maps to a Dynamic Type text style, so the whole app scales
/// with the user's preferred reading size. Views must use these tokens rather
/// than fixed point sizes — fixed sizes break Dynamic Type and VoiceOver users.
enum AegisType {
    // MARK: - Scale

    static let largeTitle = Font.largeTitle.weight(.bold)
    static let title = Font.title2.weight(.semibold)
    static let titleSmall = Font.title3.weight(.semibold)
    static let headline = Font.headline
    static let body = Font.body
    static let bodyStrong = Font.body.weight(.semibold)
    static let callout = Font.callout
    static let subheadline = Font.subheadline
    static let footnote = Font.footnote
    static let caption = Font.caption
    static let captionStrong = Font.caption.weight(.semibold)

    // MARK: - Special

    /// Monospaced style for identity fingerprints and safety numbers.
    static let fingerprint = Font.system(.footnote, design: .monospaced)
    static let fingerprintLarge = Font.system(.body, design: .monospaced)

    /// Tabular figures for timers, durations, and progress readouts.
    static let numeric = Font.system(.body, design: .monospaced)
}
