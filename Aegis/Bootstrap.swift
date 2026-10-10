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
    /// The live factory: SQLCipher store + real crypto + real transports.
    /// Initialized lazily on first access; fails fast when the database key
    /// cannot be loaded — fail closed, never silently unencrypted.
    static let liveFactory: LiveServiceFactory = {
        do {
            return try LiveServiceFactory()
        } catch {
            fatalError("Aegis live services failed to initialize: \(error)")
        }
    }()

    /// The factory the app boots with. Unit tests run injected into the app
    /// host, where the Keychain-backed database key is unavailable
    /// (errSecMissingEntitlement under the XCTest runner), so tests boot the
    /// in-memory preview factory — exactly as SwiftUI previews do.
    /// Production always uses the live factory.
    static let serviceFactory: any ServiceFactory = {
        if NSClassFromString("XCTestCase") != nil {
            return PreviewServiceFactory()
        }
        return liveFactory
    }()
}
