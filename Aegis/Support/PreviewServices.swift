import AegisTransport
import Foundation

// MARK: - Preview services
//
// PREVIEW-ONLY implementations of the app's service protocols.
//
// These exist so every screen renders in Xcode previews and the app target
// compiles before AegisCrypto / AegisTransport / AegisStore land. They perform
// NO real cryptography, NO networking, and NO durable persistence.
//
// SECURITY: nothing here is a substitute for the real packages. The mock
// crypto is labeled at every method. `Bootstrap.serviceFactory` must be
// replaced with the live factory before any TestFlight or distribution build
// (see INTEGRATION_NOTES.md).

enum PreviewServiceError: Error, LocalizedError {
    case noIdentity
    case invalidPayload
    case notFound

    var errorDescription: String? {
        switch self {
        case .noIdentity: return "No identity in the preview store."
        case .invalidPayload: return "That invite code or QR payload is not valid."
        case .notFound: return "Preview item not found."
        }
    }
}

struct PreviewServiceFactory: ServiceFactory {
    func makeCrypto() -> any CryptoService { MockCrypto() }
    func makeTransport() -> any TransportService { MockTransport() }
    func makeStore() -> any StoreService { MockStore() }
    func makeVoiceRoom() -> any VoiceRoomService { MockVoiceRoom() }
    func makeDeviceLink() -> any DeviceLinkService { MockDeviceLink() }
}

// MARK: - Mock voice room (in-memory room for previews)

final class MockVoiceRoom: VoiceRoomService, @unchecked Sendable {
    private let lock = NSLock()
    private var room: VoiceRoom?
    private let cont: AsyncStream<VoiceRoomEvent>.Continuation
    private let stream: AsyncStream<VoiceRoomEvent>

    var events: AsyncStream<VoiceRoomEvent> {
        get async { stream }
    }

    init() {
        let (s, c) = AsyncStream<VoiceRoomEvent>.makeStream()
        self.stream = s
        self.cont = c
    }

    func currentRoom() async -> VoiceRoom? {
        lock.withLock { room }
    }

    func joinRoom(conversationID: UUID, groupName: String) async {
        let me = VoiceRoomParticipant(
            fingerprintHex: "local", displayName: "You",
            isMuted: false, isDeafened: false,
            joinedAt: Date(), lastHeartbeat: Date(), isLocal: true
        )
        let sample = VoiceRoomParticipant(
            fingerprintHex: "peer", displayName: "Preview Peer",
            isMuted: false, isDeafened: false,
            joinedAt: Date(), lastHeartbeat: Date()
        )
        lock.withLock {
            room = VoiceRoom(
                conversationID: conversationID, groupName: groupName,
                participants: [me, sample],
                localMuted: false, localDeafened: false, joinedAt: Date()
            )
        }
        cont.yield(.updated(lock.withLock { room }))
    }

    func leaveRoom() async {
        lock.withLock { room = nil }
        cont.yield(.updated(nil))
    }

    func setMuted(_ muted: Bool) async {
        lock.withLock {
            room?.localMuted = muted
            if let i = room?.participants.firstIndex(where: \.isLocal) {
                room?.participants[i].isMuted = muted
            }
        }
        cont.yield(.updated(lock.withLock { room }))
    }

    func setDeafened(_ deafened: Bool) async {
        lock.withLock {
            room?.localDeafened = deafened
            if let i = room?.participants.firstIndex(where: \.isLocal) {
                room?.participants[i].isDeafened = deafened
            }
        }
        cont.yield(.updated(lock.withLock { room }))
    }
}

// MARK: - Mock device link (inert)

struct MockDeviceLink: DeviceLinkService {
    func isLinkedDevice() async -> Bool { false }
    func localDeviceID() async -> UUID { UUID() }
    func linkedDevices() async -> [DeviceInfo] { [] }
    var pairingEvents: AsyncStream<DeviceLinkManager.PairingEvent> {
        get async { AsyncStream { _ in } }
    }
    var syncEvents: AsyncStream<DeviceLinkManager.SyncEvent> {
        get async { AsyncStream { _ in } }
    }
    func beginPairingAsPrimary() async throws -> DeviceLinkManager.PrimaryPairingContext {
        throw PreviewServiceError.noIdentity
    }
    func pairingSASWords() async -> [String]? { nil }
    func confirmPairing(provisioning: ProvisioningBundle) async throws {}
    func cancelPairing() async {}
    func beginPairingAsSecondary(qrPayload: String, deviceName: String) async throws -> [String] {
        throw PreviewServiceError.noIdentity
    }
    func sendSync(kind: DeviceSyncKind, body: Data) async throws {}
    func unpair(deviceID: UUID) async {}
}

// MARK: - Mock crypto (NOT real cryptography)

actor MockCrypto: CryptoService {
    private var identity: LocalIdentity?

    func hasIdentity() async -> Bool { identity != nil }

    func createIdentity(displayName: String) async throws -> LocalIdentity {
        // PREVIEW ONLY: random bytes, not a real keypair.
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let identity = LocalIdentity(id: UUID(), displayName: displayName, publicKey: key, createdAt: Date())
        self.identity = identity
        return identity
    }

    func loadIdentity() async throws -> LocalIdentity {
        guard let identity else { throw PreviewServiceError.noIdentity }
        return identity
    }

    func updateDisplayName(_ name: String) async throws -> LocalIdentity {
        guard var identity else { throw PreviewServiceError.noIdentity }
        identity.displayName = name
        self.identity = identity
        return identity
    }

    func deleteIdentity() async throws {
        identity = nil
    }

    // MARK: Fingerprints (pure functions — safe to call off-actor)

    nonisolated func fingerprint(of publicKey: Data) -> String {
        // PREVIEW ONLY: deterministic digits, NOT a real fingerprint.
        Self.digits(from: publicKey, count: 60)
    }

    nonisolated func safetyNumber(local localKey: Data, remote remoteKey: Data) -> String {
        // PREVIEW ONLY: NOT a real safety number.
        Self.digits(from: localKey + remoteKey, count: 60)
    }

    nonisolated func qrPayload(for identity: LocalIdentity) async throws -> String {
        let name = identity.displayName.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "user"
        return "AEGIS1:\(identity.publicKey.base64EncodedString()):\(name)"
    }

    nonisolated func inviteCode(for identity: LocalIdentity) async throws -> String {
        "aegis-invite-\(identity.publicKey.base64EncodedString())"
    }

    nonisolated func remoteIdentity(fromInvitePayload payload: String) async throws -> RemoteIdentity {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("AEGIS1:") {
            let parts = trimmed.split(separator: ":", maxSplits: 2).map(String.init)
            guard parts.count == 3, let key = Data(base64Encoded: parts[1]) else {
                throw PreviewServiceError.invalidPayload
            }
            let name = parts[2].removingPercentEncoding
            return RemoteIdentity(displayName: name, publicKey: key)
        }
        if trimmed.hasPrefix("aegis-invite-") {
            let b64 = String(trimmed.dropFirst("aegis-invite-".count))
            guard let key = Data(base64Encoded: b64) else {
                throw PreviewServiceError.invalidPayload
            }
            return RemoteIdentity(displayName: nil, publicKey: key)
        }
        throw PreviewServiceError.invalidPayload
    }

    nonisolated func supersededIdentityFingerprint() async -> Data? { nil }

    // MARK: Session crypto (NOT real encryption)

    func encryptMessage(_ plaintext: Data, conversationID: UUID, recipientKeys: [Data]) async throws -> Data {
        // PREVIEW ONLY: reversible marker, NOT encryption.
        Data("MOCK:".utf8) + plaintext
    }

    func decryptMessage(_ ciphertext: Data, conversationID: UUID, senderKey: Data) async throws -> (plaintext: Data, senderIdentity: Data) {
        let prefix = Data("MOCK:".utf8)
        guard ciphertext.starts(with: prefix) else { throw PreviewServiceError.invalidPayload }
        // PREVIEW ONLY: no real sender authentication; echo senderKey as the
        // "identity" so preview flows typecheck.
        return (ciphertext.dropFirst(prefix.count), senderKey)
    }

    func encryptAttachment(at fileURL: URL, conversationID: UUID) async throws -> EncryptedFile {
        // PREVIEW ONLY: copies the file untouched.
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.copyItem(at: fileURL, to: dest)
        let attrs = try FileManager.default.attributesOfItem(atPath: dest.path)
        let size = (attrs[.size] as? Int64) ?? 0
        return EncryptedFile(
            fileURL: dest,
            wrappedKey: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            nonce: Data((0..<12).map { _ in UInt8.random(in: 0...255) }),
            byteCount: size
        )
    }

    func decryptAttachment(ciphertextURL: URL, wrappedKey: Data, nonce: Data, to destinationURL: URL) async throws {
        try? FileManager.default.removeItem(at: destinationURL)
        try FileManager.default.copyItem(at: ciphertextURL, to: destinationURL)
    }

    // MARK: Backup

    func exportEncryptedBackup(passphrase: String) async throws -> Data {
        guard let identity else { throw PreviewServiceError.noIdentity }
        return try JSONEncoder().encode(identity)
    }

    func importEncryptedBackup(_ data: Data, passphrase: String) async throws -> LocalIdentity {
        let identity = try JSONDecoder().decode(LocalIdentity.self, from: data)
        self.identity = identity
        return identity
    }

    nonisolated func backupPassphraseStrength(_ passphrase: String) -> PassphraseStrength {
        switch passphrase.count {
        case ..<8: return .weak
        case 8..<16: return .fair
        default: return .strong
        }
    }

    // MARK: Helpers

    private static func digits(from data: Data, count: Int) -> String {
        var seed = data.reduce(5381) { ($0 &* 33) &+ Int($1) }
        var digits = ""
        while digits.count < count {
            seed = (seed &* 1103515245 &+ 12345) & 0x7fffffff
            digits.append(Character(String(seed % 10)))
        }
        return digits
    }
}

// MARK: - Mock transport (no networking)

actor MockTransport: TransportService {
    nonisolated let connectionEvents: AsyncStream<ConnectionState>
    nonisolated let incomingEnvelopes: AsyncStream<IncomingEnvelope>
    nonisolated let incomingCallEvents: AsyncStream<IncomingCall>
    nonisolated let callStateEvents: AsyncStream<CallStateEvent>
    nonisolated let groupEvents: AsyncStream<GroupEvent>
    nonisolated let screenShareSupported = true

    private let connectionContinuation: AsyncStream<ConnectionState>.Continuation
    private let envelopeContinuation: AsyncStream<IncomingEnvelope>.Continuation
    private let incomingCallContinuation: AsyncStream<IncomingCall>.Continuation
    private let callStateContinuation: AsyncStream<CallStateEvent>.Continuation
    private let groupContinuation: AsyncStream<GroupEvent>.Continuation

    private var relayConfig = RelayConfig.default
    private var sentEnvelopes: [OutgoingEnvelope] = []

    init() {
        let (connStream, connCont) = AsyncStream<ConnectionState>.makeStream()
        let (envStream, envCont) = AsyncStream<IncomingEnvelope>.makeStream()
        let (callStream, callCont) = AsyncStream<IncomingCall>.makeStream()
        let (stateStream, stateCont) = AsyncStream<CallStateEvent>.makeStream()
        let (groupStream, groupCont) = AsyncStream<GroupEvent>.makeStream()
        self.connectionEvents = connStream
        self.incomingEnvelopes = envStream
        self.incomingCallEvents = callStream
        self.callStateEvents = stateStream
        self.groupEvents = groupStream
        self.connectionContinuation = connCont
        self.envelopeContinuation = envCont
        self.incomingCallContinuation = callCont
        self.callStateContinuation = stateCont
        self.groupContinuation = groupCont
        // Previews start connected.
        connCont.yield(.relayConnected)
    }

    // MARK: Connectivity

    func currentConnectionState() async -> ConnectionState { .relayConnected }

    func configureRelay(_ config: RelayConfig) async throws {
        relayConfig = config
        switch config.mode {
        case .lanOnly: connectionContinuation.yield(.lanOnly)
        case .automatic, .customRelay: connectionContinuation.yield(.relayConnected)
        }
    }

    func currentRelayConfig() async -> RelayConfig { relayConfig }

    func retryConnection() async {
        connectionContinuation.yield(.relayConnecting)
        try? await Task.sleep(nanoseconds: 600_000_000)
        connectionContinuation.yield(.relayConnected)
    }

    nonisolated func testRelay(url: String) async -> RelayTestResult {
        try? await Task.sleep(nanoseconds: 500_000_000)
        let valid = url.lowercased().hasPrefix("https://") || url.lowercased().hasPrefix("wss://")
        return RelayTestResult(
            reachable: valid,
            latencyMs: valid ? 42 : nil,
            detail: valid ? "Relay responded correctly." : "URL must start with https:// or wss://."
        )
    }

    func effectiveRelayURL() async -> String? { nil }

    func relayHealth() async -> RelayHealth? { nil }

    // MARK: Messaging

    func sendEnvelope(_ envelope: OutgoingEnvelope) async throws {
        sentEnvelopes.append(envelope)
    }

    func sendTypingIndicator(conversationID: UUID, isTyping: Bool) async throws {}
    func sendReadReceipt(conversationID: UUID, messageIDs: [UUID]) async throws {}
    func sendScreenshotNotice(conversationID: UUID) async throws {}

    // MARK: Blobs

    nonisolated func uploadBlob(from fileURL: URL, conversationID: UUID, id: UUID) -> AsyncStream<Double> {
        Self.progressStream()
    }

    nonisolated func downloadBlob(locator: String, id: UUID, to fileURL: URL) -> AsyncStream<Double> {
        Self.progressStream()
    }

    func blobLocator(attachmentID: UUID, conversationID: UUID) async throws -> String {
        attachmentID.uuidString
    }

    private static func progressStream() -> AsyncStream<Double> {
        AsyncStream { continuation in
            Task {
                for step in 1...20 {
                    try? await Task.sleep(nanoseconds: 90_000_000)
                    continuation.yield(Double(step) / 20.0)
                }
                continuation.finish()
            }
        }
    }

    // MARK: Calls

    func placeCall(to contactID: UUID, kind: CallKind) async throws -> UUID {
        let callID = UUID()
        callStateContinuation.yield(CallStateEvent(callID: callID, state: .dialing))
        // Capture the continuation (Sendable) rather than self for the detached work.
        let continuation = callStateContinuation
        Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            continuation.yield(CallStateEvent(callID: callID, state: .ringing))
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            continuation.yield(CallStateEvent(callID: callID, state: .connected))
        }
        return callID
    }

    func answerCall(_ callID: UUID) async throws {
        callStateContinuation.yield(CallStateEvent(callID: callID, state: .connecting))
        try? await Task.sleep(nanoseconds: 700_000_000)
        callStateContinuation.yield(CallStateEvent(callID: callID, state: .connected))
    }

    func declineCall(_ callID: UUID) async throws {
        callStateContinuation.yield(CallStateEvent(callID: callID, state: .ended))
    }

    func endCall(_ callID: UUID) async throws {
        callStateContinuation.yield(CallStateEvent(callID: callID, state: .ended))
    }

    func setCallMuted(_ muted: Bool, callID: UUID) async throws {}
    func setCallVideoEnabled(_ enabled: Bool, callID: UUID) async throws {}
    func setCallSpeaker(_ enabled: Bool, callID: UUID) async throws {}
    func startScreenShare(callID: UUID) async throws {}
    func stopScreenShare(callID: UUID) async throws {}
    nonisolated func setVideoSink(_ sink: (any VideoSink)?, for callID: UUID) {}

    // MARK: Groups

    func createGroup(name: String, memberKeys: [Data]) async throws -> UUID { UUID() }
    func createChannel(name: String, topic: String?, announcementOnly: Bool) async throws -> UUID { UUID() }
    func inviteMember(_ contactID: UUID, to conversationID: UUID) async throws {}
    func removeMember(_ contactID: UUID, from conversationID: UUID) async throws {}
    func setMemberRole(_ contactID: UUID, role: MemberRole, in conversationID: UUID) async throws {}
    func setAnnouncementOnly(_ enabled: Bool, conversationID: UUID) async throws {}
    func setGroupTopic(_ topic: String?, conversationID: UUID) async throws {}
    func rotateSenderKey(conversationID: UUID) async throws {}
    func leaveConversation(_ conversationID: UUID) async throws {}
    func requestGroupJoin(code: String) async throws {}
    func approveJoinRequest(_ request: JoinRequest) async throws {}

    // MARK: Identity-change tracking (preview: not simulated)

    func noteIdentityChange(_ change: PendingIdentityChange, conversationID: UUID) async {}
    func resolveIdentityChange(conversationID: UUID, adoptNewKey: Bool) async {}
    func pendingIdentityChange(for conversationID: UUID) async -> PendingIdentityChange? { nil }
}

// MARK: - Mock store (in-memory)

actor MockStore: StoreService {
    private var conversations: [UUID: Conversation] = [:]
    private var messages: [UUID: [Message]] = [:] // conversationID -> newest-first
    private var contacts: [UUID: Contact] = [:]
    private var callRecords: [CallRecord] = []

    init() {
        let data = SampleData.seed()
        for c in data.conversations { conversations[c.id] = c }
        messages = data.messages
        for c in data.contacts { contacts[c.id] = c }
        callRecords = data.callRecords
    }

    func fetchConversations() async throws -> [Conversation] {
        Array(conversations.values)
    }

    func fetchConversation(id: UUID) async throws -> Conversation? {
        conversations[id]
    }

    func saveConversation(_ conversation: Conversation) async throws {
        conversations[conversation.id] = conversation
    }

    func deleteConversation(id: UUID) async throws {
        conversations.removeValue(forKey: id)
        messages.removeValue(forKey: id)
    }

    func fetchMessages(conversationID: UUID, limit: Int, before: Date?) async throws -> [Message] {
        var list = messages[conversationID] ?? []
        if let before {
            list = list.filter { $0.sentAt < before }
        }
        return Array(list.prefix(limit))
    }

    func saveMessage(_ message: Message) async throws {
        var list = messages[message.conversationID] ?? []
        list.insert(message, at: 0)
        messages[message.conversationID] = list
    }

    func updateMessage(_ message: Message) async throws {
        guard var list = messages[message.conversationID] else { return }
        if let idx = list.firstIndex(where: { $0.id == message.id }) {
            list[idx] = message
            messages[message.conversationID] = list
        }
    }

    func deleteMessage(id: UUID, conversationID: UUID) async throws {
        messages[conversationID]?.removeAll { $0.id == id }
    }

    func purgeExpiredMessages() async throws -> Int {
        let now = Date()
        var purged = 0
        for (cid, list) in messages {
            let kept = list.filter { m in
                guard let exp = m.expiresAt else { return true }
                if exp <= now { purged += 1; return false }
                return true
            }
            messages[cid] = kept
        }
        return purged
    }

    func searchMessages(query: String, limit: Int) async throws -> [Message] {
        let q = query.lowercased()
        return messages.values.flatMap { $0 }
            .filter { $0.body?.lowercased().contains(q) ?? false }
            .sorted { $0.sentAt > $1.sentAt }
            .prefix(limit)
            .map { $0 }
    }

    func pendingOutbox() async throws -> [Message] {
        messages.values.flatMap { $0 }.filter { $0.status == .sending && $0.isFromMe }
    }

    func fetchContacts() async throws -> [Contact] {
        Array(contacts.values).sorted { $0.displayName < $1.displayName }
    }

    func saveContact(_ contact: Contact) async throws {
        contacts[contact.id] = contact
    }

    func deleteContact(id: UUID) async throws {
        contacts.removeValue(forKey: id)
    }

    func fetchCallHistory(limit: Int) async throws -> [CallRecord] {
        Array(callRecords.sorted { $0.startedAt > $1.startedAt }.prefix(limit))
    }

    func saveCallRecord(_ record: CallRecord) async throws {
        callRecords.append(record)
    }

    func clearCallHistory() async throws {
        callRecords.removeAll()
    }

    func fetchMembershipRoles(conversationID: UUID) async throws -> [String: MemberRole] { [:] }

    func storageUsage() async throws -> StorageUsage {
        StorageUsage(messagesBytes: 4_200_000, attachmentsBytes: 128_000_000, voiceNotesBytes: 12_000_000)
    }

    func clearCaches() async throws {}

    func exportAll() async throws -> Data {
        // Preview-only: encode the mock's dictionaries. The live adapter
        // uses AegisStore.snapshot() instead.
        struct PreviewExport: Codable {
            var conversations: [Conversation]
            var messages: [UUID: [Message]]
            var contacts: [Contact]
        }
        return try JSONEncoder().encode(PreviewExport(
            conversations: Array(conversations.values),
            messages: messages,
            contacts: Array(contacts.values)
        ))
    }

    func importAll(_ data: Data) async throws {
        struct PreviewExport: Codable {
            var conversations: [Conversation]
            var messages: [UUID: [Message]]
            var contacts: [Contact]
        }
        let decoded = try JSONDecoder().decode(PreviewExport.self, from: data)
        conversations = Dictionary(uniqueKeysWithValues: decoded.conversations.map { ($0.id, $0) })
        messages = decoded.messages
        contacts = Dictionary(uniqueKeysWithValues: decoded.contacts.map { ($0.id, $0) })
    }
}
