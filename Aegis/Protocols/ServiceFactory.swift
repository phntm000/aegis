import Foundation

/// Builds the three service packages behind the app's protocol boundaries.
/// Swapping the preview factory for the live one is the entire integration.
protocol ServiceFactory: Sendable {
    func makeCrypto() -> any CryptoService
    func makeTransport() -> any TransportService
    func makeStore() -> any StoreService
    func makeVoiceRoom() -> any VoiceRoomService
    func makeDeviceLink() -> any DeviceLinkService
}
