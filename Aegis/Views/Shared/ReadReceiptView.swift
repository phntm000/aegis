import SwiftUI

/// Read/delivery checkmarks for outbound messages: single check (sent),
/// double check (delivered), accent double check (read).
struct ReadReceiptView: View {
    let status: MessageStatus

    var body: some View {
        Group {
            switch status {
            case .sending:
                Image(systemName: "clock")
            case .sent:
                Image(systemName: "check")
            case .delivered:
                Image(systemName: "checkmark")
            case .read:
                Image(systemName: "checkmark")
                    .foregroundStyle(AegisColors.accent)
            case .failed:
                Image(systemName: "exclamationmark.circle.fill")
                    .foregroundStyle(AegisColors.danger)
            }
        }
        .font(.system(size: 13, weight: .medium))
        .foregroundStyle(AegisColors.textTertiary)
        .accessibilityLabel(status.accessibilityLabel)
    }
}

#Preview {
    HStack(spacing: 12) {
        ForEach(MessageStatus.allCases, id: \.self) { status in
            ReadReceiptView(status: status)
        }
    }
    .padding()
}
