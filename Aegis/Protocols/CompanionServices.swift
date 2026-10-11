import Foundation
import WebRTCBridge

// MARK: - VoiceRoomService
//
// Voice-room sessions (join/leave/mute/deafen + room state events).
// Live implementation drives AegisCore.voiceRooms; the preview mock keeps
// an in-memory room for SwiftUI previews.

protocol VoiceRoomService: Sendable {
    /// Room state snapshots for the UI.
    var events: AsyncStream<VoiceRoomEvent> { get async }
    /// The currently joined room, if any.
    func currentRoom() async -> VoiceRoom?
    func joinRoom(conversationID: UUID, groupName: String) async
    func leaveRoom() async
    func retryJoin() async
    func setMuted(_ muted: Bool) async
    func setDeafened(_ deafened: Bool) async
    /// Camera publishing for the local user.
    func setCameraEnabled(_ enabled: Bool) async
    /// Local-only per-user mute (disables their audio track on this
    /// device). The stock WebRTC iOS SDK exposes no per-track gain, so
    /// continuous volume is not offered; mute is the honest control.
    func setParticipantMuted(fingerprintHex: String, muted: Bool) async
    /// Room mode (open floor / stage). Host-only; ignored otherwise.
    func setRoomMode(_ mode: VoiceRoomMode) async
    /// Raise/lower the local user's hand (stage audience).
    func raiseHand(_ raised: Bool) async
    /// Approve/deny a raised hand (host-only).
    func setSpeakerApproval(fingerprintHex: String, approved: Bool) async
    /// This side's WebRTC session UUID for a peer (video sinks).
    func videoCallID(for fingerprintHex: String) async -> UUID?
    /// Local camera preview plumbing for the room UI.
    func attachLocalPreview(_ renderer: RTCVideoRenderer) async
    func detachLocalPreview(_ renderer: RTCVideoRenderer) async
}

// MARK: - DeviceLinkService
//
// Linked-device pairing and sync. Live implementation drives
// AegisCore.deviceLink; the preview mock is inert.

protocol DeviceLinkService: Sendable {
    /// True when this device is a linked secondary (relays via primary).
    func isLinkedDevice() async -> Bool
    /// This device's stable identifier.
    func localDeviceID() async -> UUID
    /// Primary: linked secondaries. Secondary: the primary (single entry).
    func linkedDevices() async -> [DeviceInfo]
    /// Pairing UI events (SAS ready / aborted / provisioned).
    var pairingEvents: AsyncStream<DeviceLinkManager.PairingEvent> { get async }
    /// Inbound paired-channel traffic for the app layer to apply.
    var syncEvents: AsyncStream<DeviceLinkManager.SyncEvent> { get async }

    // MARK: Pairing — primary side
    /// Starts pairing; returns the QR payload to display.
    func beginPairingAsPrimary() async throws -> DeviceLinkManager.PrimaryPairingContext
    /// SAS words once the new device has scanned (nil until then).
    func pairingSASWords() async -> [String]?
    /// User confirmed the SAS match; sends the provisioning bundle.
    func confirmPairing(provisioning: ProvisioningBundle) async throws
    func cancelPairing() async

    // MARK: Pairing — secondary side
    /// Scans the QR, sends hello, returns the SAS words to display.
    func beginPairingAsSecondary(qrPayload: String, deviceName: String) async throws -> [String]

    // MARK: Sync
    /// Sends a sync message over the paired channel (to the primary when
    /// linked; fanned out to linked devices when primary).
    func sendSync(kind: DeviceSyncKind, body: Data) async throws
    /// Sends a sync message to one specific paired device (chunk streams).
    func sendSync(to deviceID: UUID, kind: DeviceSyncKind, body: Data) async throws
    func unpair(deviceID: UUID) async
}
