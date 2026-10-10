import AegisCrypto
import CryptoKit
import Foundation
import OSLog
#if os(iOS)
import UIKit
#endif

// MARK: - DeviceLinkManager
//
// Linked-device pairing and sync (paired-device relay model). The primary
// device holds the identity; a linked device pairs over an E2EE channel and
// relays all traffic through the primary.
//
// Pairing (all on the pairing mailbox, HKDF-derived from the QR pairing ID):
//   1. Primary: beginPairingAsPrimary() → QR payload + binds pairing mailbox.
//   2. Linked: beginPairingAsSecondary(qr:) → sends hello, shows SAS words.
//   3. Primary: hello arrives → shows SAS words; the user compares the two
//      screens and taps "Confirm" → confirmPairing() sends the AES-GCM-sealed
//      provisioning bundle (contacts, conversations, recent history).
//   4. Linked: applies the bundle, derives the long-term paired channel key,
//      binds the paired mailbox. Both sides persist the link.
//
// The SAS is derived from the DH shared secret, so matching words prove no
// man-in-the-middle between the QR scan and key agreement.

/// Which mailbox a device-link frame arrived on.
enum DeviceLinkChannel: Sendable {
    /// Short-lived pairing mailbox (one pairing attempt).
    case pairing
    /// Long-term paired channel mailbox.
    case paired
}

actor DeviceLinkManager {

    private let log = Logger(subsystem: "app.aegis.ios", category: "devicelink")
    /// Assigned via setCore after AegisCore finishes init.
    private weak var core: AegisCore?
    private let provider = CryptoKitProvider.shared

    // MARK: - Persisted state

    private enum Keys {
        static let deviceID = "aegis.deviceID"
        static let linkedDevices = "aegis.linkedDevices"
        static let linkedMode = "aegis.isLinkedDevice"
        static let keychainService = "app.aegis.pairedkeys"
    }

    /// Stable per-device identifier (generated once, survives reinstalls only
    /// if the keychain survives — a fresh install is a new device, which is
    /// the safe default).
    var localDeviceID: UUID {
        if let s = UserDefaults.standard.string(forKey: Keys.deviceID),
           let id = UUID(uuidString: s) { return id }
        let id = UUID()
        UserDefaults.standard.set(id.uuidString, forKey: Keys.deviceID)
        return id
    }

    /// True when THIS device is a linked secondary (relays via primary).
    var isLinkedDevice: Bool {
        get { UserDefaults.standard.bool(forKey: Keys.linkedMode) }
        set { UserDefaults.standard.set(newValue, forKey: Keys.linkedMode) }
    }

    /// Primary: linked secondaries. Linked device: exactly one entry (primary).
    private(set) var linkedDevices: [DeviceInfo] = []

    // MARK: - Pairing attempt (ephemeral)

    private struct PairingAttempt {
        enum Role { case primary, secondary }
        var role: Role
        var pairingID: Data
        var ephemeral: X25519KeyPair
        var peerEphemeralPublicKey: Data?
        var peerDeviceID: UUID?
        var peerDeviceName: String?
        var peerDeviceModel: String?
        /// DH shared secret, once the peer's ephemeral key is known.
        var sharedSecret: (any DHSecret)?
    }

    private var pairing: PairingAttempt?

    init() {
        if let data = UserDefaults.standard.data(forKey: Keys.linkedDevices),
           let devices = try? JSONDecoder().decode([DeviceInfo].self, from: data) {
            self.linkedDevices = devices
        }
        let (stream, cont) = AsyncStream<PairingEvent>.makeStream()
        self.pairingEvents = stream
        self.pairingEventCont = cont
        let (syncStream, syncCont) = AsyncStream<SyncEvent>.makeStream()
        self.syncEvents = syncStream
        self.syncEventCont = syncCont
    }

    /// Called once by AegisCore after its init completes. Re-binds the
    /// paired mailbox so a linked device keeps receiving after restart
    /// (channel keys live in the keychain).
    func setCore(_ core: AegisCore) async {
        self.core = core
        await rebindPairedMailboxes()
    }

    /// Re-binds every known paired-channel mailbox. Actor-isolated so the
    /// non-Sendable channel keys never cross an actor boundary.
    private func rebindPairedMailboxes() async {
        for device in linkedDevices {
            if let key = loadPairedKey(for: device.deviceID) {
                await core?.bindDeviceLinkMailbox(
                    Self.pairedMailbox(channelKey: key),
                    channel: .paired
                )
            }
        }
    }

    private func persistDevices() {
        if let data = try? JSONEncoder().encode(linkedDevices) {
            UserDefaults.standard.set(data, forKey: Keys.linkedDevices)
        }
    }

    private func pairedKeyAccount(for deviceID: UUID) -> String {
        "paired-\(deviceID.uuidString)"
    }

    private func savePairedKey(_ key: SymmetricKey, for deviceID: UUID) throws {
        try KeychainHelper.save(
            key.withUnsafeBytes { Data($0) },
            service: Keys.keychainService,
            account: pairedKeyAccount(for: deviceID)
        )
    }

    private func loadPairedKey(for deviceID: UUID) -> SymmetricKey? {
        guard let data = try? KeychainHelper.load(service: Keys.keychainService, account: pairedKeyAccount(for: deviceID)),
              data.count == 32
        else { return nil }
        return SymmetricKey(data: data)
    }

    private func deletePairedKey(for deviceID: UUID) {
        try? KeychainHelper.delete(service: Keys.keychainService, account: pairedKeyAccount(for: deviceID))
    }

    // MARK: - Pairing: primary side

    struct PrimaryPairingContext: Sendable {
        /// Contents for the QR code shown to the new device.
        var qrPayload: String
        var pairingIDHex: String
    }

    /// Starts a pairing attempt as primary. Returns the QR payload; the
    /// caller displays it and then awaits `pairingSASWords` (published via
    /// `pairingEvents`) once the new device scans.
    func beginPairingAsPrimary() async throws -> PrimaryPairingContext {
        await cancelPairing(silent: true)
        let pairingID = try provider.randomBytes(count: 16)
        let ephemeral = try provider.generateX25519KeyPair()
        let mailbox = Self.pairingMailbox(pairingID: pairingID)
        pairing = PairingAttempt(role: .primary, pairingID: pairingID, ephemeral: ephemeral)
        await core?.bindDeviceLinkMailbox(mailbox, channel: .pairing)
        let payload = "aegis-pair:v1:\(pairingID.base64URLEncoded()).\(ephemeral.publicKey.base64URLEncoded())"
        log.info("Primary pairing started; awaiting hello on pairing mailbox")
        return PrimaryPairingContext(qrPayload: payload, pairingIDHex: pairingID.hexString)
    }

    /// SAS words for the current attempt, once the peer's ephemeral key
    /// arrived (nil until then).
    func pairingSASWords() -> [String]? {
        guard let attempt = pairing,
              let secret = attempt.sharedSecret
        else { return nil }
        return PairingSAS.words(for: Self.sha256(secret: secret))
    }

    /// The user confirmed the SAS words match on both screens. Sends the
    /// caller-built provisioning bundle (sealed with the pairing key) and
    /// establishes the long-term paired channel.
    func confirmPairing(provisioning bundle: ProvisioningBundle) async throws {
        guard let attempt = pairing, attempt.role == .primary,
              let secret = attempt.sharedSecret,
              let peerDeviceID = attempt.peerDeviceID,
              let core
        else { throw DeviceLinkError.noActivePairing }
        let pairKey = secret.derivedKey(
            salt: attempt.pairingID,
            info: Data("aegis-pair-key".utf8),
            outputByteCount: 32
        )
        let sealed = try Self.seal(
            try JSONEncoder().encode(bundle),
            key: pairKey,
            provider: provider
        )
        var msg = PairingMessage(kind: .provisioning, pairingIDHex: attempt.pairingID.hexString)
        msg.sealedBundle = sealed
        let mailbox = Self.pairingMailbox(pairingID: attempt.pairingID)
        try await core.sendDeviceLinkFrame(
            try JSONEncoder().encode(msg),
            mailbox: mailbox
        )
        // Establish the long-term channel.
        let channelKey = secret.derivedKey(
            salt: attempt.pairingID,
            info: Data("aegis-paired-channel".utf8),
            outputByteCount: 32
        )
        try savePairedKey(channelKey, for: peerDeviceID)
        let info = DeviceInfo(
            deviceID: peerDeviceID,
            deviceName: attempt.peerDeviceName ?? "Linked device",
            deviceModel: attempt.peerDeviceModel,
            pairedAt: Date(),
            lastSeen: Date()
        )
        linkedDevices.removeAll { $0.deviceID == peerDeviceID }
        linkedDevices.append(info)
        persistDevices()
        await core.bindDeviceLinkMailbox(Self.pairedMailbox(channelKey: channelKey), channel: .paired)
        await core.unbindDeviceLinkMailbox(mailbox)
        pairing = nil
        log.info("Pairing confirmed; linked device added")
    }

    // MARK: - Pairing: secondary side

    /// Scans the QR payload, sends hello on the pairing mailbox, and returns
    /// the SAS words once the shared secret is computable (immediately — the
    /// primary's ephemeral key is in the QR). The caller shows the words and
    /// waits for the provisioning bundle (applied automatically on arrival).
    func beginPairingAsSecondary(qrPayload: String, deviceName: String) async throws -> [String] {
        await cancelPairing(silent: true)
        let parts = qrPayload.split(separator: ":")
        guard parts.count == 4, parts[0] == "aegis-pair", parts[1] == "v1",
              let pairingID = Data(base64URLEncoded: String(parts[2])),
              let primaryPub = Data(base64URLEncoded: String(parts[3])),
              primaryPub.count == 32
        else { throw DeviceLinkError.invalidQRPayload }
        let ephemeral = try provider.generateX25519KeyPair()
        let secret = try ephemeral.withPrivateKeyBytes { priv in
            try provider.x25519DH(privateKey: priv, peerPublicKey: primaryPub)
        }
        let mailbox = Self.pairingMailbox(pairingID: pairingID)
        pairing = PairingAttempt(
            role: .secondary,
            pairingID: pairingID,
            ephemeral: ephemeral,
            peerEphemeralPublicKey: primaryPub,
            sharedSecret: secret
        )
        await core?.bindDeviceLinkMailbox(mailbox, channel: .pairing)
        var hello = PairingMessage(kind: .hello, pairingIDHex: pairingID.hexString)
        hello.ephemeralPublicKey = ephemeral.publicKey
        hello.deviceID = localDeviceID
        hello.deviceName = deviceName
        #if os(iOS)
        hello.deviceModel = UIDevice.current.model
        #endif
        try await core?.sendDeviceLinkFrame(try JSONEncoder().encode(hello), mailbox: mailbox)
        log.info("Secondary pairing hello sent; awaiting provisioning")
        return PairingSAS.words(for: Self.sha256(secret: secret))
    }

    /// Aborts the in-progress pairing attempt (unbinds the pairing mailbox).
    func cancelPairing(silent: Bool = false) async {
        if let attempt = pairing {
            await core?.unbindDeviceLinkMailbox(Self.pairingMailbox(pairingID: attempt.pairingID))
            if !silent, let core {
                // Best-effort abort notice on the pairing mailbox.
                let abort = PairingMessage(kind: .abort, pairingIDHex: attempt.pairingID.hexString)
                if let data = try? JSONEncoder().encode(abort) {
                    try? await core.sendDeviceLinkFrame(data, mailbox: Self.pairingMailbox(pairingID: attempt.pairingID))
                }
            }
        }
        pairing = nil
    }

    // MARK: - Inbound frames

    /// Dispatches one frame from a device-link mailbox.
    func handleDeviceLinkFrame(_ payload: Data, channel: DeviceLinkChannel) async {
        switch channel {
        case .pairing:
            await handlePairingMessage(payload)
        case .paired:
            await handlePairedMessage(payload)
        }
    }

    private func handlePairingMessage(_ payload: Data) async {
        guard let msg = try? JSONDecoder().decode(PairingMessage.self, from: payload),
              var attempt = pairing,
              msg.pairingIDHex == attempt.pairingID.hexString
        else { return }
        switch msg.kind {
        case .hello where attempt.role == .primary:
            // The new device scanned our QR.
            guard let peerPub = msg.ephemeralPublicKey, peerPub.count == 32,
                  let peerID = msg.deviceID
            else { return }
            do {
                let secret = try attempt.ephemeral.withPrivateKeyBytes { priv in
                    try provider.x25519DH(privateKey: priv, peerPublicKey: peerPub)
                }
                attempt.peerEphemeralPublicKey = peerPub
                attempt.peerDeviceID = peerID
                attempt.peerDeviceName = msg.deviceName
                attempt.peerDeviceModel = msg.deviceModel
                attempt.sharedSecret = secret
                pairing = attempt
                log.info("Pairing hello received; SAS ready for user confirmation")
                pairingEventCont.yield(.sasReady(words: PairingSAS.words(for: Self.sha256(secret: secret))))
            } catch {
                log.error("Pairing DH failed")
            }
        case .provisioning where attempt.role == .secondary:
            guard let sealed = msg.sealedBundle,
                  let secret = attempt.sharedSecret
            else { return }
            let pairKey = secret.derivedKey(
                salt: attempt.pairingID,
                info: Data("aegis-pair-key".utf8),
                outputByteCount: 32
            )
            do {
                let plain = try Self.open(sealed, key: pairKey, provider: provider)
                let bundle = try JSONDecoder().decode(ProvisioningBundle.self, from: plain)
                try await applyProvisioning(bundle, secret: secret, pairingID: attempt.pairingID)
                await core?.unbindDeviceLinkMailbox(Self.pairingMailbox(pairingID: attempt.pairingID))
                pairing = nil
            } catch {
                log.error("Provisioning bundle failed to open: \(error.localizedDescription)")
            }
        case .abort:
            await cancelPairing(silent: true)
            pairingEventCont.yield(.aborted)
        case .hello, .provisioning:
            break // wrong role; ignore
        }
    }

    private func applyProvisioning(
        _ bundle: ProvisioningBundle,
        secret: any DHSecret,
        pairingID: Data
    ) async throws {
        guard let core else { return }
        let channelKey = secret.derivedKey(
            salt: pairingID,
            info: Data("aegis-paired-channel".utf8),
            outputByteCount: 32
        )
        try savePairedKey(channelKey, for: bundle.primaryDeviceID)
        isLinkedDevice = true
        linkedDevices = [DeviceInfo(
            deviceID: bundle.primaryDeviceID,
            deviceName: bundle.primaryDeviceName,
            deviceModel: nil,
            pairedAt: Date(),
            lastSeen: Date()
        )]
        persistDevices()
        await core.bindDeviceLinkMailbox(Self.pairedMailbox(channelKey: channelKey), channel: .paired)
        syncEventCont.yield((message: DeviceSyncMessage(
            kind: .provisioningApplied,
            senderDeviceID: bundle.primaryDeviceID,
            body: try JSONEncoder().encode(bundle)
        ), fromDevice: bundle.primaryDeviceID))
        pairingEventCont.yield(.provisioned)
        log.info("Provisioning applied; device is now linked")
    }

    // MARK: - Paired-channel sync

    /// Sends a sync message to every linked device (primary) or to the
    /// primary (linked device).
    func sendSync(kind: DeviceSyncKind, body: Data) async throws {
        guard let core else { return }
        // Primary: fan out to every linked device. Linked device: the single
        // entry is the primary.
        for device in linkedDevices {
            guard let key = loadPairedKey(for: device.deviceID) else { continue }
            let msg = DeviceSyncMessage(kind: kind, senderDeviceID: localDeviceID, body: body)
            let sealed = try Self.seal(try JSONEncoder().encode(msg), key: key, provider: provider)
            try await core.sendDeviceLinkFrame(sealed, mailbox: Self.pairedMailbox(channelKey: key))
        }
    }

    private func handlePairedMessage(_ payload: Data) async {
        // Try each known paired key (exactly one in practice).
        for device in linkedDevices {
            guard let key = loadPairedKey(for: device.deviceID),
                  let plain = try? Self.open(payload, key: key, provider: provider),
                  let msg = try? JSONDecoder().decode(DeviceSyncMessage.self, from: plain)
            else { continue }
            touchDevice(device.deviceID)
            syncEventCont.yield((message: msg, fromDevice: device.deviceID))
            return
        }
        log.warning("Paired-channel frame matched no known device key")
    }

    private func touchDevice(_ deviceID: UUID) {
        if let idx = linkedDevices.firstIndex(where: { $0.deviceID == deviceID }) {
            linkedDevices[idx].lastSeen = Date()
            persistDevices()
        }
    }

    // MARK: - Unpair

    /// Removes a linked device (primary side) or unlinks from the primary
    /// (linked side), wiping channel keys.
    func unpair(deviceID: UUID) async {
        guard let core else { return }
        if let key = loadPairedKey(for: deviceID) {
            let msg = DeviceSyncMessage(
                kind: .unpair,
                senderDeviceID: localDeviceID,
                body: Data()
            )
            if let sealed = try? Self.seal(try JSONEncoder().encode(msg), key: key, provider: provider) {
                try? await core.sendDeviceLinkFrame(sealed, mailbox: Self.pairedMailbox(channelKey: key))
            }
            await core.unbindDeviceLinkMailbox(Self.pairedMailbox(channelKey: key))
        }
        deletePairedKey(for: deviceID)
        linkedDevices.removeAll { $0.deviceID == deviceID }
        persistDevices()
        if isLinkedDevice {
            // This device was the secondary: drop back to unpaired.
            isLinkedDevice = false
        }
        log.info("Unpaired device")
    }

    // MARK: - Pairing UI events

    enum PairingEvent: Sendable {
        /// Primary: the new device scanned the QR; show these words for
        /// the user to compare with the words on the new device.
        case sasReady(words: [String])
        /// Pairing was aborted by the other side.
        case aborted
        /// Secondary: provisioning applied; the device is now linked.
        case provisioned
    }

    private let pairingEventCont: AsyncStream<PairingEvent>.Continuation
    let pairingEvents: AsyncStream<PairingEvent>

    /// Inbound paired-channel traffic (and applied provisioning bundles)
    /// for the app layer to persist/act on.
    typealias SyncEvent = (message: DeviceSyncMessage, fromDevice: UUID)
    private let syncEventCont: AsyncStream<SyncEvent>.Continuation
    let syncEvents: AsyncStream<SyncEvent>

    // MARK: - Wire helpers

    /// Pairing mailbox: SHA256("aegis-pair-mbox" || pairingID). Only the QR
    /// holder knows the pairing ID, so only they can find this mailbox.
    static func pairingMailbox(pairingID: Data) -> Data {
        var h = SHA256()
        h.update(data: Data("aegis-pair-mbox".utf8))
        h.update(data: pairingID)
        return Data(h.finalize())
    }

    /// Paired-channel mailbox: SHA256("aegis-paired-mbox" || channelKey).
    /// Both sides derive the same mailbox from the shared channel key.
    static func pairedMailbox(channelKey: SymmetricKey) -> Data {
        let keyData = channelKey.withUnsafeBytes { Data($0) }
        var h = SHA256()
        h.update(data: Data("aegis-paired-mbox".utf8))
        h.update(data: keyData)
        return Data(h.finalize())
    }

    private static func sha256(secret: any DHSecret) -> Data {
        let key = secret.derivedKey(salt: Data(), info: Data("aegis-pair-sas".utf8), outputByteCount: 32)
        let data = key.withUnsafeBytes { Data($0) }
        var h = SHA256()
        h.update(data: data)
        return Data(h.finalize())
    }

    /// Sealed envelope: nonce(12) || ciphertext || tag(16).
    static func seal(_ plaintext: Data, key: SymmetricKey, provider: CryptoKitProvider) throws -> Data {
        let nonce = try provider.randomBytes(count: 12)
        let (ct, tag) = try provider.aesGCMSeal(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            associatedData: Data("aegis-devicelink".utf8)
        )
        return nonce + ct + tag
    }

    static func open(_ sealed: Data, key: SymmetricKey, provider: CryptoKitProvider) throws -> Data {
        guard sealed.count >= 12 + 16 else { throw DeviceLinkError.malformedSealedEnvelope }
        let nonce = sealed.prefix(12)
        let tag = sealed.suffix(16)
        let ct = sealed.dropFirst(12).dropLast(16)
        return try provider.aesGCMOpen(
            nonce: Data(nonce),
            ciphertext: Data(ct),
            tag: Data(tag),
            key: key,
            associatedData: Data("aegis-devicelink".utf8)
        )
    }
}

enum DeviceLinkError: Error, LocalizedError {
    case noActivePairing
    case invalidQRPayload
    case malformedSealedEnvelope

    var errorDescription: String? {
        switch self {
        case .noActivePairing: return "No pairing attempt is in progress."
        case .invalidQRPayload: return "This QR code is not an Aegis pairing code."
        case .malformedSealedEnvelope: return "The encrypted message was malformed."
        }
    }
}

// MARK: - Small Data helpers

private extension Data {
    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded s: String) {
        var b64 = s
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = b64.count % 4
        if pad > 0 { b64 += String(repeating: "=", count: 4 - pad) }
        self.init(base64Encoded: b64)
    }
}
