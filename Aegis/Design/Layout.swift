import SwiftUI

/// Spacing, corner radius, and sizing tokens. One scale, used everywhere,
/// so layout rhythm stays consistent across the app.
enum AegisLayout {
    // MARK: - Spacing scale (4pt base)

    static let xxs: CGFloat = 2
    static let xs: CGFloat = 4
    static let s: CGFloat = 8
    static let m: CGFloat = 12
    static let l: CGFloat = 16
    static let xl: CGFloat = 24
    static let xxl: CGFloat = 32

    // MARK: - Corner radii

    static let radiusS: CGFloat = 8
    static let radiusM: CGFloat = 12
    static let radiusL: CGFloat = 16
    static let radiusXL: CGFloat = 20
    static let radiusFull: CGFloat = 999

    // MARK: - Component sizes

    static let avatarXS: CGFloat = 28
    static let avatarS: CGFloat = 36
    static let avatarM: CGFloat = 48
    static let avatarL: CGFloat = 64
    static let avatarXL: CGFloat = 96

    /// Minimum tappable dimension (Apple HIG 44pt).
    static let minTapTarget: CGFloat = 44

    /// Standard horizontal screen margin.
    static let screenMargin: CGFloat = 16

    // MARK: - Shadows (used sparingly; the design is intentionally flat)

    static let cardShadow = Shadow(
        color: Color.black.opacity(0.06), radius: 12, x: 0, y: 4
    )
}

/// Lightweight shadow descriptor so views don't hand-roll shadow values.
struct Shadow {
    let color: Color
    let radius: CGFloat
    let x: CGFloat
    let y: CGFloat
}
