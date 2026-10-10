import AegisTransport
import Foundation

/// Settings: identity, privacy, relay, storage, and the danger zone.
/// Toggles persist to UserDefaults immediately; structural actions (backup,
/// relay test, wipe) run through the service protocols.
@MainActor
final class SettingsViewModel: ObservableObject {
    @Published private(set) var identity: LocalIdentity?
    @Published private(set) var fingerprint = ""
    @Published private(set) var qrPayload = ""
    @Published private(set) var inviteCode = ""
    @Published private(set) var storageUsage: StorageUsage?
    @Published private(set) var isLoadingStorage = false
    @Published var error: String?

    // Relay testing
    @Published private(set) var relayTestResult: RelayTestResult?
    @Published private(set) var isTestingRelay = false
    // Relay configuration
    @Published var relayConfigError: String?
    @Published private(set) var relayHealth: RelayHealth?
    @Published private(set) var effectiveRelayURL: String?
    @Published private(set) var isApplyingRelay = false

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    func load() async {
        do {
            let identity = try await appState.crypto.loadIdentity()
            self.identity = identity
            self.fingerprint = appState.crypto.fingerprint(of: identity.publicKey)
            self.qrPayload = (try? await appState.crypto.qrPayload(for: identity)) ?? ""
            self.inviteCode = (try? await appState.crypto.inviteCode(for: identity)) ?? ""
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Storage

    func loadStorage() async {
        isLoadingStorage = true
        defer { isLoadingStorage = false }
        do {
            storageUsage = try await appState.store.storageUsage()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func clearCaches() async {
        do {
            try await appState.store.clearCaches()
            await loadStorage()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Relay

    func currentRelayConfig() async -> RelayConfig {
        await appState.transport.currentRelayConfig()
    }

    func applyRelayConfig(_ config: RelayConfig) async {
        relayConfigError = nil
        var config = config
        if config.mode == .customRelay {
            // 1. Format validation — blocks apply with a clear message.
            let raw = (config.customRelayURL ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            switch RelayURLValidator.normalize(raw) {
            case .failure(let validationError):
                relayConfigError = validationError.description
                Haptics.notification(.error)
                return
            case .success(let url):
                config.customRelayURL = url.absoluteString
            }
            // 2. Reachability probe — blocks apply when the relay doesn't
            // answer. Never silently save a dead endpoint.
            isTestingRelay = true
            defer { isTestingRelay = false }
            let probe = await appState.transport.testRelay(url: config.customRelayURL ?? "")
            relayTestResult = probe
            guard probe.reachable else {
                relayConfigError = "That relay didn't answer (\(probe.detail)). Check the URL and your connection, then try again."
                Haptics.notification(.error)
                return
            }
        }
        isApplyingRelay = true
        defer { isApplyingRelay = false }
        do {
            try await appState.transport.configureRelay(config)
            UserDefaults.standard.set(config.mode.rawValue, forKey: SettingsKeys.relayMode)
            UserDefaults.standard.set(config.customRelayURL, forKey: SettingsKeys.relayCustomURL)
            await refreshRelayStatus()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
            Haptics.notification(.error)
        }
    }

    /// Refreshes the health readout and resolved relay URL shown in Settings.
    func refreshRelayStatus() async {
        relayHealth = await appState.transport.relayHealth()
        effectiveRelayURL = await appState.transport.effectiveRelayURL()
    }

    func testRelay(url: String) async {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            relayTestResult = RelayTestResult(reachable: false, latencyMs: nil, detail: "Enter a relay URL first.")
            return
        }
        isTestingRelay = true
        relayTestResult = nil
        defer { isTestingRelay = false }
        relayTestResult = await appState.transport.testRelay(url: trimmed)
        Haptics.selection()
    }

    func retryConnection() async {
        await appState.transport.retryConnection()
    }

    // MARK: - Backup

    func exportBackup(passphrase: String) async -> Data? {
        do {
            return try await appState.crypto.exportEncryptedBackup(passphrase: passphrase)
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }

    // MARK: - Danger zone

    func deleteIdentity() async {
        await appState.deleteIdentityAndReset()
    }
}
