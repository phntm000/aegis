import Foundation
import LocalAuthentication

/// Face ID / Touch ID / passcode gate in front of the app's content.
/// The setting lives in Settings → Security; when enabled the app locks on
/// backgrounding and on demand.
@MainActor
final class AppLockManager: ObservableObject {
    @Published private(set) var isLocked = false
    @Published private(set) var biometryType: LABiometryType = .none
    @Published var lastError: String?

    var isEnabled: Bool {
        UserDefaults.standard.bool(forKey: SettingsKeys.appLock)
    }

    var biometryLabel: String {
        switch biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Device passcode"
        }
    }

    func refreshBiometry() {
        let context = LAContext()
        // canEvaluatePolicy populates biometryType as a side effect.
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        biometryType = context.biometryType
    }

    /// Lock immediately if the setting is on (called on backgrounding).
    func lockIfEnabled() {
        if isEnabled {
            isLocked = true
        }
    }

    func lockNow() {
        isLocked = true
    }

    /// Prompt for biometrics / passcode. Returns true on success.
    @discardableResult
    func unlock() async -> Bool {
        let context = LAContext()
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Unlock Aegis to access your encrypted conversations."
            )
            if success {
                isLocked = false
                lastError = nil
            }
            return success
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }
}
