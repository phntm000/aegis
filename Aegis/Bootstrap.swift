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
    static let liveFactory: LiveServiceFactory = {
        do {
            return try LiveServiceFactory()
        } catch {
            fatalError("Aegis live services failed to initialize: \(error)")
        }
    }()

    static let serviceFactory: any ServiceFactory = liveFactory
}
