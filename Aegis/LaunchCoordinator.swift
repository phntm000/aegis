import Foundation

/// Owns app launch: resolves the service factory, holds the resulting
/// `AppState`, and surfaces an initialization failure as retryable UI
/// state instead of crashing the process.
///
/// A launch failure means the encrypted store could not be opened (almost
/// always: the device Keychain key is unavailable). The app stays fail
/// closed — nothing is decrypted, no conversation is shown — but the user
/// gets an explanation and a retry path.
@MainActor
final class LaunchCoordinator: ObservableObject {
    /// The live app state, once the factory resolves successfully.
    @Published private(set) var appState: AppState?
    /// The factory initialization failure, when resolution failed.
    @Published private(set) var launchError: Error?

    init() {
        resolve()
    }

    /// Attempts factory resolution again (e.g. after the user taps
    /// "Try Again"). Keychain failures can be transient — a retry after
    /// the device is unlocked or the system settles may succeed.
    func retry() {
        resolve()
    }

    private func resolve() {
        switch Bootstrap.makeFactoryResult() {
        case .success(let factory):
            appState = AppState(factory: factory)
            launchError = nil
        case .failure(let error):
            appState = nil
            launchError = error
        }
    }
}
