import SwiftUI

// MARK: - Linked Devices Settings
//
// Pairing UI for the paired-device relay model. Primary: show a QR code, wait
// for the new device to scan, compare SAS words, confirm. Secondary (this
// device): scan the primary's QR, compare SAS words, done.

struct DeviceLinkView: View {
    @EnvironmentObject private var appState: AppState
    @State private var showingPrimaryPairing = false
    @State private var showingScanner = false
    @State private var scannedSAS: [String]?
    @State private var pairingError: String?
    @State private var confirmingUnpair: DeviceInfo?

    var body: some View {
        List {
            if appState.isLinkedDevice {
                Section {
                    Label(
                        "This device is linked. Messages are relayed through your primary device over an end-to-end encrypted channel.",
                        systemImage: "link.circle.fill"
                    )
                    .foregroundStyle(AegisColors.textSecondary)
                    .font(.caption)
                }
            }

            Section {
                if appState.linkedDevices.isEmpty {
                    Text("No linked devices")
                        .foregroundStyle(AegisColors.textSecondary)
                } else {
                    ForEach(appState.linkedDevices) { device in
                        HStack {
                            Image(systemName: appState.isLinkedDevice ? "iphone" : "ipad.and.iphone")
                                .foregroundStyle(AegisColors.accent)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(device.deviceName)
                                    .font(.subheadline.weight(.medium))
                                Text("Paired \(device.pairedAt, style: .date)")
                                    .font(.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                            Spacer()
                            Button("Unpair", role: .destructive) {
                                confirmingUnpair = device
                            }
                            .font(.caption)
                        }
                        .accessibilityLabel("Unpair \(device.deviceName)")
                    }
                }
            } header: {
                Text(appState.isLinkedDevice ? "Primary device" : "Linked devices")
            } footer: {
                Text("A linked device relays through \(appState.isLinkedDevice ? "the primary" : "this device") over an end-to-end encrypted paired channel. Unpairing wipes the channel keys on both sides.")
            }

            if !appState.isLinkedDevice {
                Section {
                    Button {
                        showingPrimaryPairing = true
                    } label: {
                        Label("Link a new device", systemImage: "qrcode")
                    }
                    .accessibilityLabel("Link a new device")
                } footer: {
                    Text("Shows a QR code for your other device to scan. You'll confirm matching safety words before anything is shared.")
                }
            }

            Section {
                Button {
                    showingScanner = true
                } label: {
                    Label("Scan to link this device", systemImage: "qrcode.viewfinder")
                }
                .accessibilityLabel("Scan a pairing QR code")
            } footer: {
                Text("Use this on a fresh device to link it to the device showing the QR code.")
            }
        }
        .navigationTitle("Linked devices")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in
            await appState.refreshLinkedDevices()
        }
        .sheet(isPresented: $showingPrimaryPairing) {
            PrimaryPairingView()
                .environmentObject(appState)
        }
        .sheet(isPresented: $showingScanner) {
            ScannerView { payload in
                Task { @MainActor in
                    await handleScanned(payload)
                }
            }
        }
        .sheet(item: $confirmingUnpair) { device in
            // item-based sheet needs Identifiable — DeviceInfo conforms.
            UnpairConfirmView(device: device) {
                Task { @MainActor in await appState.unpairDevice(device) }
            }
        }
        .alert("Pairing failed", isPresented: Binding(
            get: { pairingError != nil },
            set: { if !$0 { pairingError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(pairingError ?? "")
        }
        .sheet(isPresented: showingSecondaryPairing) {
            if let words = scannedSAS {
                SecondaryPairingView(words: words)
                    .environmentObject(appState)
            }
        }
    }

    private var showingSecondaryPairing: Binding<Bool> {
        Binding(
            get: { scannedSAS != nil },
            set: { if !$0 { scannedSAS = nil } }
        )
    }

    private func handleScanned(_ payload: String) async {
        guard payload.hasPrefix("aegis-pair:") else {
            pairingError = "This QR code is not an Aegis pairing code."
            return
        }
        do {
            let words = try await appState.beginSecondaryPairing(qrPayload: payload)
            scannedSAS = words
        } catch {
            pairingError = error.localizedDescription
        }
    }
}

/// Primary side: QR code → waiting → SAS confirmation.
private struct PrimaryPairingView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var qrPayload: String?
    @State private var error: String?
    @State private var confirming = false

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                if let qrPayload, let image = QRCode.image(from: qrPayload, size: 240) {
                    Image(uiImage: image)
                        .resizable()
                        .frame(width: 240, height: 240)
                        .padding()
                        .background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: AegisLayout.radiusM))
                        .accessibilityLabel("Pairing QR code")
                } else {
                    ProgressView()
                        .frame(width: 240, height: 240)
                }

                if let words = appState.pairingSASWords {
                    // The new device scanned: compare safety words, then confirm.
                    VStack(spacing: AegisLayout.s) {
                        Text("Compare these words with the ones on your other device. Only continue if they match exactly.")
                            .font(.caption)
                            .foregroundStyle(AegisColors.textSecondary)
                            .multilineTextAlignment(.center)
                        SASWordsView(words: words)
                        Button {
                            confirming = true
                        } label: {
                            Text("Words match — link device")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .confirmationDialog(
                            "Share contacts, conversations, and recent messages with this device?",
                            isPresented: $confirming,
                            titleVisibility: .visible
                        ) {
                            Button("Link device") {
                                Task { @MainActor in
                                    do {
                                        try await appState.confirmPairing()
                                        dismiss()
                                    } catch {
                                        self.error = error.localizedDescription
                                    }
                                }
                            }
                            Button("Cancel", role: .cancel) {}
                        } message: {
                            Text("The provisioning bundle is encrypted end-to-end and sent only after you confirm.")
                        }
                    }
                } else {
                    Text("On your other device, open Settings → Linked devices → \"Scan to link this device\" and scan this code.")
                        .font(.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                        .multilineTextAlignment(.center)
                }

                if let error {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Spacer()
            }
            .padding(AegisLayout.m)
            .navigationTitle("Link a new device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        Task { @MainActor in await appState.cancelPairing() }
                        dismiss()
                    }
                }
            }
            .task { @MainActor in
                do {
                    qrPayload = try await appState.beginPrimaryPairing()
                } catch {
                    self.error = error.localizedDescription
                }
            }
        }
    }
}

/// Secondary side: shows the SAS words after scanning; provisioning applies
/// automatically when the primary confirms.
private struct SecondaryPairingView: View {
    let words: [String]
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.largeTitle)
                    .foregroundStyle(AegisColors.accent)
                Text("Verify safety words")
                    .font(.headline)
                Text("Compare these words with the ones on your primary device. If they don't match exactly, cancel — someone may be intercepting the pairing.")
                    .font(.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                SASWordsView(words: words)
                if appState.isLinkedDevice {
                    Label("This device is now linked.", systemImage: "link.circle.fill")
                        .foregroundStyle(AegisColors.accent)
                    Button("Done") { dismiss() }
                        .buttonStyle(.borderedProminent)
                } else {
                    Text("Waiting for confirmation on your primary device…")
                        .font(.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                    ProgressView()
                }
                Spacer()
            }
            .padding(AegisLayout.m)
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
        }
    }
}

private struct SASWordsView: View {
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
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .accessibilityLabel("Safety words: \(words.joined(separator: ", "))")
    }
}

private struct UnpairConfirmView: View {
    let device: DeviceInfo
    let onConfirm: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: AegisLayout.m) {
                Text("Unpair \"\(device.deviceName)\"?")
                    .font(.headline)
                Text("The encrypted channel is wiped on both sides. The other device keeps its local copy of synced data.")
                    .font(.caption)
                    .foregroundStyle(AegisColors.textSecondary)
                    .multilineTextAlignment(.center)
                Button("Unpair", role: .destructive) {
                    onConfirm()
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                Button("Cancel", role: .cancel) { dismiss() }
                Spacer()
            }
            .padding(AegisLayout.m)
            .navigationTitle("Unpair device")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
