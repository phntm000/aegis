import SwiftUI

/// Contact avatar: deterministic color from the identity key, initials
/// fallback, optional verification ring.
struct AvatarView: View {
    let displayName: String
    var hue: Double = 0.6
    var size: CGFloat = AegisLayout.avatarM
    var verification: VerificationState?

    var body: some View {
        ZStack {
            Circle()
                .fill(Color(hue: hue, saturation: 0.32, brightness: 0.92))
                .overlay {
                    Circle()
                        .fill(Color(hue: hue, saturation: 0.45, brightness: 0.55).opacity(0.85))
                }
            Text(initials)
                .font(.system(size: size * 0.38, weight: .semibold))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .overlay(alignment: .bottomTrailing) {
            if verification == .verified {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: size * 0.32))
                    .foregroundStyle(AegisColors.accent)
                    .background(Circle().fill(AegisColors.background))
                    .accessibilityLabel("Verified contact")
            }
        }
        .accessibilityLabel("Avatar for \(displayName)")
    }

    private var initials: String {
        let parts = displayName.split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }
        let result = String(letters).uppercased()
        return result.isEmpty ? "?" : result
    }
}

/// Group/channel avatar: rounded square with a kind glyph.
struct GroupAvatarView: View {
    var kind: ConversationKind
    var size: CGFloat = AegisLayout.avatarM

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.28)
            .fill(AegisColors.accentSoft)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: kind == .channel ? "megaphone.fill" : "person.2.fill")
                    .font(.system(size: size * 0.4))
                    .foregroundStyle(AegisColors.accent)
                    .accessibilityHidden(true)
            }
            .accessibilityLabel(kind == .channel ? "Channel" : "Group")
    }
}

#Preview {
    HStack(spacing: 16) {
        AvatarView(displayName: "Maya Chen", hue: 0.58, verification: .verified)
        AvatarView(displayName: "Jonas Weber", hue: 0.1, size: AegisLayout.avatarL)
        GroupAvatarView(kind: .group)
        GroupAvatarView(kind: .channel)
    }
    .padding()
}
