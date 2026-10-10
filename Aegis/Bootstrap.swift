import Foundation

/// Service wiring. Single seam between the app and the three packages.
///
/// LIVE: the app now runs against the real AegisCrypto / AegisTransport /
/// AegisStore packages through the adapters in Aegis/Adapters.
/// `LiveServiceFactory` builds one shared AegisCore; the three protocols in
/// `Aegis/Protocols/` are the only contract the UI depends on.
///
/// To go back to previews (mock crypto/transport/store), swap the factory
/// below for `PreviewServiceFactory()`. Never ship the preview factory.
enum Bootstrap {
    /// Attempts to build the live factory: SQLCipher store + real crypto +
    /// real transports.
    ///
    /// The failure is returned — never thrown past here and never turned
    /// into a crash. `AegisApp` renders `LaunchErrorView` on failure:
    /// fail closed (nothing is ever decrypted or shown), but with an
    /// explanation and a retry path instead of a `fatalError`.
    static func makeFactoryResult() -> Result<any ServiceFactory, Error> {
        if NSClassFromString("XCTestCase") != nil {
            // Unit tests run injected into the app host, where the
            // Keychain-backed database key is unavailable
            // (errSecMissingEntitlement under the XCTest runner), so tests
            // boot the in-memory preview factory — exactly as SwiftUI
            // previews do. Production always uses the live factory.
            return .success(PreviewServiceFactory())
        }
        return Result { try LiveServiceFactory() }.map { $0 as any ServiceFactory }
    }

    /// The factory the app boots with. Kept for previews and tests that
    /// need a factory without going through the launch coordinator.
    /// Production launch goes through `LaunchCoordinator`, which surfaces
    /// initialization failures as UI instead of crashing.
    static var serviceFactory: any ServiceFactory {
        (try? makeFactoryResult().get()) ?? PreviewServiceFactory()
    }
}
