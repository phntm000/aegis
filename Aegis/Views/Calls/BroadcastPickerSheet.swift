import ReplayKit
import SwiftUI

// MARK: - Full-device screen sharing (ReplayKit)
//
// The system broadcast picker. Tapping it shows the OS broadcast UI where
// the user picks Aegis and starts the broadcast; the Broadcast Upload
// Extension then captures the whole device and its frames take over the
// call's video track (see BroadcastShareController). View-only by design:
// there is no remote-control channel.

/// The system broadcast picker view, preferring the Aegis extension.
struct BroadcastPickerView: UIViewRepresentable {
    func makeUIView(context: Context) -> RPSystemBroadcastPickerView {
        let picker = RPSystemBroadcastPickerView(frame: CGRect(x: 0, y: 0, width: 64, height: 64))
        picker.preferredExtension = "app.aegis.ios.BroadcastUpload"
        // The stock mic icon clashes with the app's iconography; keep the
        // system default look so users recognize the OS control.
        return picker
    }

    func updateUIView(_ uiView: RPSystemBroadcastPickerView, context: Context) {}
}

/// Sheet shown when the user picks full-device sharing: arms the reader,
/// then hands them to the system picker to actually start the broadcast.
struct BroadcastPickerSheet: View {
    @ObservedObject var viewModel: ActiveCallViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                Image(systemName: "rectangle.on.rectangle")
                    .font(.largeTitle)
                    .foregroundStyle(AegisColors.accent)
                    .padding(.top, AegisLayout.xl)
                Text("Share your full screen")
                    .font(AegisType.titleSmall)
                    .foregroundStyle(AegisColors.textPrimary)
                Text("Tap the broadcast button below, choose Aegis, then Start Broadcast. Everything on your screen is shared — close anything private first. View-only: the other side can't control your device.")
                    .font(AegisType.callout)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, AegisLayout.xl)
                BroadcastPickerView()
                    .frame(width: 64, height: 64)
                    .accessibilityLabel("Start broadcast. Opens the system screen-sharing picker.")
                Spacer()
                Button("Stop sharing") {
                    Task { @MainActor in
                        await viewModel.stopBroadcastShare()
                        dismiss()
                    }
                }
                .buttonStyle(.bordered)
                .tint(AegisColors.danger)
                .padding(.bottom, AegisLayout.xl)
            }
            .navigationTitle("Full-screen sharing")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .onAppear {
                // Arm the frame reader; it waits for the extension's frames.
                Task { @MainActor in await viewModel.startBroadcastShare() }
            }
        }
    }
}
