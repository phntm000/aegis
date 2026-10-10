import SwiftUI
import UIKit

/// The familiar three-dot typing indicator with a gentle bounce.
struct TypingIndicatorView: View {
    @State private var phase = 0
    private let timer = Timer.publish(every: 0.4, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3) { i in
                Circle()
                    .fill(AegisColors.textSecondary)
                    .frame(width: 7, height: 7)
                    .offset(y: phase == i ? -3 : 0)
                    .animation(.easeInOut(duration: 0.3), value: phase)
                    .accessibilityHidden(i > 0)
            }
        }
        .padding(.horizontal, AegisLayout.m)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.bubbleIncoming)
        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusL))
        .onReceive(timer) { _ in
            phase = (phase + 1) % 3
        }
        .accessibilityLabel("Typing")
    }
}

/// Guidance screen when a system permission (camera, microphone, notifications)
/// was denied, with a one-tap route to Settings.
struct PermissionDeniedView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: AegisLayout.m) {
            Image(systemName: icon)
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(AegisColors.textTertiary)
                .accessibilityHidden(true)
            Text(title)
                .font(AegisType.titleSmall)
                .foregroundStyle(AegisColors.textPrimary)
            Text(message)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, AegisLayout.xl)
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(AegisColors.accent)
            .padding(.top, AegisLayout.s)
            .accessibilityLabel("Open Settings to grant permission")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

#Preview {
    VStack {
        TypingIndicatorView()
        PermissionDeniedView(
            icon: "camera.fill",
            title: "Camera access needed",
            message: "Aegis needs camera access to scan QR codes. Your scans never leave the device."
        )
    }
}
