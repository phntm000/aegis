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
        do {
            try await appState.transport.configureRelay(config)
            UserDefaults.standard.set(config.mode.rawValue, forKey: SettingsKeys.relayMode)
            UserDefaults.standard.set(config.customRelayURL, forKey: SettingsKeys.relayCustomURL)
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
            Haptics.notification(.error)
        }
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
