import SwiftUI

// MARK: - Link Device (onboarding)
//
// Fresh-device pairing flow: scan the primary's QR → verify SAS words →
// wait for the primary's confirmation → provisioning applies automatically
// and the app enters the main UI as a linked device.

struct LinkDeviceOnboardingView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var showingScanner = true
    @State private var sasWords: [String]?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                if let sasWords {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.largeTitle)
                        .foregroundStyle(AegisColors.accent)
                    Text("Verify safety words")
                        .font(AegisType.title)
                    Text("Compare these words with the ones on your primary device. If they don't match exactly, cancel — someone may be intercepting the pairing.")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                        .multilineTextAlignment(.center)
                    SASWordsGrid(words: sasWords)
                    if appState.phase == .main {
                        // Provisioning applied; the listener transitioned us.
                        Text("This device is now linked.")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.accent)
                        Button("Start messaging") { dismiss() }
                            .buttonStyle(.borderedProminent)
                    } else {
                        ProgressView()
                        Text("Waiting for confirmation on your primary device…")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                    }
                } else {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 64))
                        .foregroundStyle(AegisColors.accent)
                    Text("Scan the pairing code")
                        .font(AegisType.title)
                    Text("On your primary device, open Settings → Linked devices → \"Link a new device\" and scan the QR code shown there.")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                        .multilineTextAlignment(.center)
                    Button("Scan QR code") { showingScanner = true }
                        .buttonStyle(.borderedProminent)
                }
                if let error {
                    Text(error)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.danger)
                }
                Spacer()
            }
            .padding(AegisLayout.l)
            .navigationTitle("Link this device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        Task { @MainActor in await appState.cancelPairing() }
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $showingScanner) {
                ScannerView { payload in
                    Task { @MainActor in await handleScanned(payload) }
                }
            }
        }
    }

    private func handleScanned(_ payload: String) async {
        guard payload.hasPrefix("aegis-pair:") else {
            error = "This QR code is not an Aegis pairing code."
            return
        }
        do {
            sasWords = try await appState.beginSecondaryPairing(qrPayload: payload)
        } catch {
            self.error = error.localizedDescription
        }
    }
}

private struct SASWordsGrid: View {
    let words: [String]

    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: AegisLayout.s) {
            ForEach(Array(words.enumerated()), id: \.offset) { i, word in
                HStack {
                    Text("\(i + 1).")
                        .foregroundStyle(AegisColors.textSecondary)
                    Text(word)
                        .font(.body.weight(.semibold))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(AegisLayout.s)
                .background(AegisColors.surface)
                .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
            }
        }
        .accessibilityLabel("Safety words: \(words.joined(separator: ", "))")
    }
}
