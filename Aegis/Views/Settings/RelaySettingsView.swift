import Foundation
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

                if let health = viewModel.relayHealth {
                    HStack(alignment: .top, spacing: AegisLayout.s) {
                        Image(systemName: health.status == .reachable ? "checkmark.circle.fill"
                             : health.status == .checking ? "arrow.triangle.2.circlepath"
                             : "xmark.circle.fill")
                            .foregroundStyle(health.status == .reachable ? AegisColors.success
                                             : health.status == .checking ? AegisColors.textSecondary
                                             : AegisColors.warning)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(healthShortURL(health.url))
                                .font(AegisType.callout)
                                .foregroundStyle(AegisColors.textPrimary)
                            Text(health.detail)
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                            if let ms = health.latencyMs, let checked = health.lastCheckedAt {
                                Text("\(ms) ms · checked \(relativeTime(checked))")
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                        }
                        Spacer()
                    }
                    .accessibilityLabel("Relay health: \(health.detail)")
                }

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
                        viewModel.relayConfigError = nil
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

            if mode == .automatic {
                Section {
                    if let url = viewModel.effectiveRelayURL {
                        HStack(alignment: .top, spacing: AegisLayout.s) {
                            Image(systemName: "server.rack")
                                .foregroundStyle(AegisColors.textSecondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Using relay")
                                    .font(AegisType.callout)
                                    .foregroundStyle(AegisColors.textPrimary)
                                Text(healthShortURL(url))
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                        }
                        .accessibilityLabel("Automatic mode is using relay \(healthShortURL(url))")
                    } else {
                        HStack(alignment: .top, spacing: AegisLayout.s) {
                            Image(systemName: "house.fill")
                                .foregroundStyle(AegisColors.textSecondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("No relay configured — running on local network only.")
                                    .font(AegisType.callout)
                                    .foregroundStyle(AegisColors.textPrimary)
                                Text("Messages work with nearby devices. Add your own relay below to reach anyone beyond your network.")
                                    .font(AegisType.caption)
                                    .foregroundStyle(AegisColors.textSecondary)
                            }
                        }
                        .accessibilityLabel("No relay configured. Running on local network only.")
                    }
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
                if let configError = viewModel.relayConfigError {
                    HStack(alignment: .top, spacing: AegisLayout.s) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(AegisColors.danger)
                            .accessibilityHidden(true)
                        Text(configError)
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.danger)
                    }
                    .accessibilityLabel("Configuration error: \(configError)")
                }
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
            await viewModel.refreshRelayStatus()
        }
    }

    private var statusColor: Color {
        switch appState.connectionState {
        case .relayConnected: return AegisColors.success
        case .lanOnly: return AegisColors.success
        case .localNetworkOnly: return AegisColors.textSecondary
        case .relayConnecting: return AegisColors.textSecondary
        case .relayUnreachable: return AegisColors.warning
        case .offline: return AegisColors.danger
        }
    }

    /// Short display form of a relay URL (host only, no scheme clutter).
    private func healthShortURL(_ urlString: String) -> String {
        if let url = URL(string: urlString), let host = url.host, !host.isEmpty {
            return host
        }
        return urlString
    }

    private func relativeTime(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
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
        case .automatic: return "Local network first, your verified relay as fallback"
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
        await viewModel.refreshRelayStatus()
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        RelaySettingsView(appState: appState)
            .environmentObject(appState)
    }
}
