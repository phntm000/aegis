import SwiftUI

/// Relay configuration: automatic, LAN-only, or a self-hosted relay.
/// The relay is a dumb pipe — it stores and forwards ciphertext it cannot
/// read. LAN-only mode keeps everything off the internet entirely.
struct RelaySettingsView: View {
    @StateObject private var viewModel: SettingsViewModel
    @EnvironmentObject private var appState: AppState

    @State private var mode: RelayConfig.Mode = .automatic
    @State private var customURL = ""
    @State private var isApplying = false

    init(appState: AppState) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(appState: appState))
    }

    var body: some View {
        List {
            Section {
                HStack {
                    Label("Status", systemImage: "circle.fill")
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Text(appState.connectionState.displayName)
                        .font(AegisType.callout)
                        .foregroundStyle(statusColor)
                }
                .accessibilityLabel("Connection status: \(appState.connectionState.displayName)")

                Button {
                    Task { @MainActor in await viewModel.retryConnection() }
                } label: {
                    Label("Retry connection", systemImage: "arrow.triangle.2.circlepath")
                }
                .accessibilityLabel("Retry connection")
            }

            Section("Mode") {
                ForEach([RelayConfig.Mode.automatic, .lanOnly, .customRelay], id: \.self) { option in
                    Button {
                        mode = option
                        Haptics.selection()
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(modeTitle(option))
                                    .font(AegisType.body)
                                    .foregroundStyle(AegisColors.textPrimary)
                                Text(modeDetail(option))
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                            Spacer()
                            if mode == option {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(AegisColors.accent)
                                    .accessibilityLabel("Selected")
                            }
                        }
                    }
                    .accessibilityLabel("\(modeTitle(option)) relay mode")
                }
            }

            if mode == .customRelay {
                Section {
                    TextField("https://relay.example.com", text: $customURL)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .accessibilityLabel("Custom relay URL")

                    Button {
                        Task { @MainActor in await viewModel.testRelay(url: customURL) }
                    } label: {
                        HStack {
                            if viewModel.isTestingRelay { ProgressView().tint(AegisColors.accent) }
                            Text(viewModel.isTestingRelay ? "Testing…" : "Test relay")
                        }
                    }
                    .disabled(viewModel.isTestingRelay || customURL.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityLabel("Test relay connection")

                    if let result = viewModel.relayTestResult {
                        HStack(spacing: AegisLayout.s) {
                            Image(systemName: result.reachable ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(result.reachable ? AegisColors.success : AegisColors.danger)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading) {
                                Text(result.detail)
                                    .font(AegisType.callout)
                                    .foregroundStyle(AegisColors.textPrimary)
                                if let ms = result.latencyMs {
                                    Text("\(ms) ms")
                                        .font(AegisType.caption)
                                        .foregroundStyle(AegisColors.textSecondary)
                                }
                            }
                        }
                        .accessibilityLabel("Relay test: \(result.detail)")
                    }
                } header: {
                    Text("Your relay")
                } footer: {
                    Text("Host the open-source relay on any server you control. It never sees plaintext — only encrypted envelopes addressed by opaque ids.")
                }
            }

            Section {
                Button {
                    Task { @MainActor in await apply() }
                } label: {
                    HStack {
                        if isApplying { ProgressView().tint(AegisColors.textOnAccent) }
                        Text(isApplying ? "Applying…" : "Apply configuration")
                            .frame(maxWidth: .infinity, minHeight: AegisLayout.minTapTarget)
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(AegisColors.accent)
                .disabled(isApplying)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .accessibilityLabel("Apply relay configuration")
            }
        }
        .navigationTitle("Relay")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in
            let config = await viewModel.currentRelayConfig()
            mode = config.mode
            customURL = config.customRelayURL ?? ""
        }
    }

    private var statusColor: Color {
        switch appState.connectionState {
        case .relayConnected: return AegisColors.success
        case .lanOnly: return AegisColors.success
        case .relayConnecting: return AegisColors.textSecondary
        case .relayUnreachable: return AegisColors.warning
        case .offline: return AegisColors.danger
        }
    }

    private func modeTitle(_ mode: RelayConfig.Mode) -> String {
        switch mode {
        case .automatic: return "Automatic"
        case .lanOnly: return "LAN only"
        case .customRelay: return "Custom relay"
        }
    }

    private func modeDetail(_ mode: RelayConfig.Mode) -> String {
        switch mode {
        case .automatic: return "Local network first, community relay as fallback"
        case .lanOnly: return "Never touches the internet"
        case .customRelay: return "Your own self-hosted relay"
        }
    }

    private func apply() async {
        isApplying = true
        defer { isApplying = false }
        let url = customURL.trimmingCharacters(in: .whitespacesAndNewlines)
        await viewModel.applyRelayConfig(RelayConfig(
            mode: mode,
            customRelayURL: mode == .customRelay && !url.isEmpty ? url : nil
        ))
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        RelaySettingsView(appState: appState)
            .environmentObject(appState)
    }
}
