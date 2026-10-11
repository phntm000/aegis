import AegisCrypto
import AegisDeviceLink
import CryptoKit
import Foundation
import OSLog

// MARK: - DeviceLinkBlobRelay
//
// Chunked attachment / voice-note sync over the paired device-link channel.
//
// The linked secondary holds no conversation keys, so it can never unwrap
// an attachment's file key itself and cannot fetch blobs from the relay.
// The primary therefore acts as its media proxy:
//
//   Primary:  offerBlobs(for:) — after forwarding a message that carries an
//             attachment/voice note, downloads the *ciphertext* blob from
//             the relay, unwraps the file key, and sends a LinkedBlobManifest
//             to each linked device (small, fan-out).
//   Linked:   taps the attachment → download(manifest) sends a
//             LinkedBlobRequest → the primary streams LinkedBlobChunks
//             (32 KiB ciphertext slices, each sealed by the paired
//             channel's AES-GCM) → the linked device reassembles,
//             SHA-256-verifies, and decrypts with the manifest's file key
//             via AttachmentCrypto — the same framing as the relay path.
//
// Resume: chunks are indexed; the linked device persists the manifest and
// the received indexes, so an interrupted download resumes from the first
// missing chunk instead of restarting (across reconnects and relaunches).
//
// Honest limits (also in Models/DeviceLink.swift):
// - The primary must be reachable. Downloads fail (with a clear message,
//   retried by tapping again) when the primary is offline — the linked
//   device cannot fetch media on its own. Nothing is faked.
// - The manifest carries the raw file key sealed inside the paired
//   envelope. The paired channel key is static (no forward secrecy), so a
//   compromised channel key exposes synced blobs retroactively.
// - Unpairing wipes channel keys but cannot remote-wipe blobs already
//   synced to the other device.

/// One event in a linked-device blob download.
enum LinkedDownloadEvent: Sendable {
    case progress(Double) // 0...1
    case done(URL)        // decrypted file, ready to view/play
    case failed(String)   // human-readable; tapping the row retries
}

actor DeviceLinkBlobRelay {

    private let log = Logger(subsystem: "app.aegis.ios", category: "devlink-blobs")
    private let deviceLink: any DeviceLinkService
    private let transport: any TransportService
    private let crypto: any CryptoService
    /// Primary-side outbound progress → AppState → Settings UI.
    private let onOutboundProgress: @Sendable (DeviceSyncProgress) -> Void

    /// Primary: transferID → staged ciphertext + manifest.
    private var stagedBlobs: [UUID: URL] = [:]
    private var offered: [UUID: LinkedBlobManifest] = [:]
    /// Linked: transferID → reassembly / active download.
    private var inbound: [UUID: InboundBlobTransfer] = [:]
    private var inboundContinuations: [UUID: AsyncStream<LinkedDownloadEvent>.Continuation] = [:]
    private var lastChunkAt: [UUID: Date] = [:]
    private var watchdogs: [UUID: Task<Void, Never>] = [:]
    /// Linked: blind downloads waiting for a re-offered manifest, keyed by
    /// attachmentID (== transferID). Created when the manifest offer was
    /// missed — e.g. this device was offline, or the primary couldn't stage
    /// the blob at forward time.
    private var parkedBlind: [UUID: AsyncStream<LinkedDownloadEvent>.Continuation] = [:]
    private var blindWatchdogs: [UUID: Task<Void, Never>] = [:]

    /// Removes and returns a parked blind-download continuation, if any.
    /// Actor-isolated `async` so the nonisolated watchdog `Task` can claim it
    /// across the actor boundary: `Dictionary.removeValue` is a *mutating*
    /// struct method, and Swift forbids forming the required inout access to
    /// actor-isolated state from a nonisolated context, even with `await`.
    private func takeParkedBlind(forKey id: UUID) async -> AsyncStream<LinkedDownloadEvent>.Continuation? {
        parkedBlind.removeValue(forKey: id)
    }
    /// Throttle UserDefaults writes while chunks stream in.
    private var persistCounters: [UUID: Int] = [:]

    private enum PersistKeys {
        static let inboundManifests = "aegis.devlink.inboundManifests"
        static let inboundReceived = "aegis.devlink.inboundReceived"
        static let offeredManifests = "aegis.devlink.offeredManifests"
    }

    /// Staging cap for primary-side ciphertext kept for linked serving.
    /// Oldest evicted first; serving re-downloads from the relay on demand.
    private static let maxStagedBytes: Int64 = 256 * 1024 * 1024

    init(
        deviceLink: any DeviceLinkService,
        transport: any TransportService,
        crypto: any CryptoService,
        onOutboundProgress: @escaping @Sendable (DeviceSyncProgress) -> Void
    ) {
        self.deviceLink = deviceLink
        self.transport = transport
        self.crypto = crypto
        self.onOutboundProgress = onOutboundProgress
        // Warm the primary-side offer registry so resume requests survive
        // a primary restart (the staged blob re-downloads from the relay).
        if let dict = UserDefaults.standard.dictionary(forKey: PersistKeys.offeredManifests) as? [String: Data] {
            let decoder = JSONDecoder()
            for (key, data) in dict {
                if let id = UUID(uuidString: key),
                   let manifest = try? decoder.decode(LinkedBlobManifest.self, from: data) {
                    self.offered[id] = manifest
                }
            }
        }
    }

    // MARK: - Primary: offering

    /// Downloads each blob on `message` and offers it to linked devices.
    /// Called after the message itself is forwarded. Skips silently when
    /// there is nothing to sync or nobody to sync to.
    ///
    /// The eager download is deliberate: the linked device cannot fetch
    /// from the relay itself (no conversation keys), so the primary stages
    /// the ciphertext once and serves chunk requests from disk. Bounded by
    /// `maxStagedBytes` with oldest-first eviction.
    ///
    /// The transfer ID IS the attachment ID: one transfer per attachment.
    /// Re-offers reuse the ID, so resume and dedupe work naturally and a
    /// linked device that missed the manifest can blind-request with the
    /// attachment ID as the correlation ID.
    func offerBlobs(for message: Message, to deviceID: UUID? = nil) async {
        guard await !deviceLink.isLinkedDevice() else { return }
        let targets: [UUID]
        if let deviceID {
            targets = [deviceID]
        } else {
            targets = await deviceLink.linkedDevices().map(\.deviceID)
        }
        guard !targets.isEmpty else { return }
        if let attachment = message.attachment {
            await offerOne(
                attachmentID: attachment.id,
                messageID: message.id,
                conversationID: message.conversationID,
                kind: .attachment,
                filename: attachment.filename,
                mimeType: attachment.mimeType,
                wrappedKey: attachment.wrappedKey,
                locator: attachment.remoteLocator,
                thumbnail: attachment.thumbnailData,
                voiceDuration: nil,
                voiceLevels: nil,
                transcript: nil,
                to: targets
            )
        }
        if let note = message.voiceNote {
            await offerOne(
                attachmentID: note.id,
                messageID: message.id,
                conversationID: message.conversationID,
                kind: .voiceNote,
                filename: "voice-note.m4a",
                mimeType: "audio/x-m4a",
                wrappedKey: note.wrappedKey,
                locator: note.remoteLocator,
                thumbnail: nil,
                voiceDuration: note.duration,
                voiceLevels: note.levels,
                transcript: note.transcript,
                to: targets
            )
        }
    }

    private func offerOne(
        attachmentID: UUID,
        messageID: UUID,
        conversationID: UUID,
        kind: LinkedBlobKind,
        filename: String,
        mimeType: String,
        wrappedKey: Data?,
        locator: String?,
        thumbnail: Data?,
        voiceDuration: TimeInterval?,
        voiceLevels: [Float]?,
        transcript: String?,
        to targets: [UUID]
    ) async {
        guard let wrappedKey, let locator else {
            log.info("Skipping blob offer: no wrapped key or locator")
            return
        }
        guard let fileKey = await crypto.fileKey(forWrappedKey: wrappedKey), fileKey.count == 32 else {
            log.warning("Skipping blob offer: file key unavailable")
            await sendFailure(
                LinkedBlobFailure(
                    transferID: attachmentID,
                    attachmentID: attachmentID,
                    reason: "This file couldn't be prepared for syncing."
                ),
                to: targets
            )
            return
        }
        // One transfer per attachment: the transfer ID is the attachment ID.
        let transferID = attachmentID
        let staged = AegisPaths.ensureStaging()
            .appendingPathComponent("devlink-\(transferID.uuidString).blob", isDirectory: false)
        do {
            for await _ in transport.downloadBlob(locator: locator, id: attachmentID, to: staged) {}
            let attrs = try FileManager.default.attributesOfItem(atPath: staged.path)
            let size = (attrs[.size] as? Int64) ?? 0
            guard size > 0, size <= BlobTransfer.maxBlobBytes else {
                throw BlobRelayError.blobUnavailable
            }
            let bytes = try Data(contentsOf: staged)
            let chunkSize = BlobTransfer.chunkSize
            let manifest = LinkedBlobManifest(
                transferID: transferID,
                attachmentID: attachmentID,
                messageID: messageID,
                conversationID: conversationID,
                kind: kind,
                filename: filename,
                mimeType: mimeType,
                byteCount: Int64(bytes.count),
                chunkSize: chunkSize,
                chunkCount: BlobTransfer.chunkCount(byteCount: Int64(bytes.count), chunkSize: chunkSize),
                blobSHA256: BlobTransfer.sha256(bytes),
                relayLocator: locator,
                fileKey: fileKey,
                thumbnail: thumbnail,
                voiceDuration: voiceDuration,
                voiceLevels: voiceLevels,
                transcript: transcript
            )
            stagedBlobs[transferID] = staged
            offered[transferID] = manifest
            persistOfferedManifest(manifest)
            evictStagedIfNeeded()
            let body = try JSONEncoder().encode(manifest)
            for target in targets {
                try await deviceLink.sendSync(to: target, kind: .attachmentManifest, body: body)
            }
            log.info("Offered blob \(filename) to \(targets.count) device(s), \(manifest.chunkCount) chunks")
        } catch {
            try? FileManager.default.removeItem(at: staged)
            log.warning("Blob offer failed: \(error.localizedDescription)")
            await sendFailure(
                LinkedBlobFailure(
                    transferID: transferID,
                    attachmentID: attachmentID,
                    reason: "This file couldn't be fetched for syncing."
                ),
                to: targets
            )
        }
    }

    private func sendFailure(_ failure: LinkedBlobFailure, to targets: [UUID]) async {
        guard let body = try? JSONEncoder().encode(failure) else { return }
        for target in targets {
            try? await deviceLink.sendSync(to: target, kind: .attachmentFailure, body: body)
        }
    }

    // MARK: - Primary: serving

    enum ServeOutcome: Sendable {
        /// Chunks streamed (or are streaming) to the requester.
        case served
        /// The blob couldn't be served; a failure notice was sent.
        case failed
        /// Unknown transfer — the caller should rebuild the offer from the
        /// stored message (the linked device missed the manifest).
        case unknownTransfer
    }

    /// Streams chunks for `request` to one linked device, starting at
    /// `fromIndex` (resume). Re-downloads the ciphertext from the relay
    /// when the staged copy was evicted.
    func serve(_ request: LinkedBlobRequest, to deviceID: UUID) async -> ServeOutcome {
        guard let manifest = offered[request.transferID] ?? persistedOfferedManifest(id: request.transferID) else {
            return .unknownTransfer
        }
        offered[request.transferID] = manifest
        let deviceName = await deviceLink.linkedDevices()
            .first(where: { $0.deviceID == deviceID })?.deviceName ?? "Linked device"

        // Ensure the ciphertext is staged.
        var blobURL = stagedBlobs[request.transferID]
        if blobURL == nil || !FileManager.default.fileExists(atPath: blobURL!.path) {
            let staged = AegisPaths.ensureStaging()
                .appendingPathComponent("devlink-\(request.transferID.uuidString).blob", isDirectory: false)
            var downloaded = false
            for await _ in transport.downloadBlob(
                locator: manifest.relayLocator, id: manifest.attachmentID, to: staged
            ) {}
            downloaded = FileManager.default.fileExists(atPath: staged.path)
            if downloaded {
                blobURL = staged
                stagedBlobs[request.transferID] = staged
            }
        }
        guard let url = blobURL else {
            await sendFailure(
                LinkedBlobFailure(
                    transferID: request.transferID,
                    attachmentID: request.attachmentID,
                    reason: "This file is no longer available for syncing."
                ),
                to: [deviceID]
            )
            onOutboundProgress(DeviceSyncProgress(
                id: request.transferID, filename: manifest.filename,
                deviceName: deviceName, progress: 0,
                state: .failed("Unavailable")))
            return .failed
        }

        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let total = manifest.chunkCount
            var index = max(0, request.fromIndex)
            while index < total {
                let range = BlobTransfer.range(
                    forChunk: index, byteCount: manifest.byteCount, chunkSize: manifest.chunkSize)
                try handle.seek(toOffset: UInt64(range.lowerBound))
                guard let bytes = try handle.read(upToCount: range.count),
                      bytes.count == range.count
                else { throw BlobRelayError.blobUnavailable }
                let chunk = LinkedBlobChunk(transferID: manifest.transferID, index: index, bytes: bytes)
                try await deviceLink.sendSync(
                    to: deviceID, kind: .attachmentChunk, body: JSONEncoder().encode(chunk))
                index += 1
                onOutboundProgress(DeviceSyncProgress(
                    id: manifest.transferID, filename: manifest.filename,
                    deviceName: deviceName,
                    progress: Double(index) / Double(total), state: .streaming))
            }
            onOutboundProgress(DeviceSyncProgress(
                id: manifest.transferID, filename: manifest.filename,
                deviceName: deviceName, progress: 1, state: .done))
            log.info("Served \(total) chunks of \(manifest.filename) to \(deviceName)")
            return .served
        } catch {
            log.warning("Blob serve failed: \(error.localizedDescription)")
            await sendFailure(
                LinkedBlobFailure(
                    transferID: request.transferID,
                    attachmentID: request.attachmentID,
                    reason: "Syncing was interrupted. Try again."
                ),
                to: [deviceID]
            )
            onOutboundProgress(DeviceSyncProgress(
                id: manifest.transferID, filename: manifest.filename,
                deviceName: deviceName, progress: 0,
                state: .failed(error.localizedDescription)))
            return .failed
        }
    }

    // MARK: - Linked: receiving

    /// Records a manifest offer (persists it for resume across relaunches).
    func noteManifest(_ manifest: LinkedBlobManifest) async {
        persistInboundManifest(manifest)
        if inbound[manifest.transferID] == nil {
            inbound[manifest.transferID] = InboundBlobTransfer(
                manifest: manifest,
                receivedIndexes: persistedReceived(for: manifest.attachmentID)
            )
        }
        log.info("Manifest recorded for \(manifest.filename) (\(manifest.chunkCount) chunks)")
        // A blind download was parked waiting for this re-offer: start it.
        if let parked = parkedBlind.removeValue(forKey: manifest.attachmentID) {
            blindWatchdogs[manifest.attachmentID]?.cancel()
            blindWatchdogs[manifest.attachmentID] = nil
            Task {
                for await event in await self.download(manifest) {
                    parked.yield(event)
                }
                parked.finish()
            }
        }
    }

    /// Manifest for an attachment the linked device knows about (nil when
    /// the offer was missed — e.g. the device was offline past the mailbox
    /// TTL — in which case tapping download asks the primary to re-offer).
    func manifest(for attachmentID: UUID) -> LinkedBlobManifest? {
        persistedInboundManifests().first { $0.attachmentID == attachmentID }
    }

    /// Starts (or resumes) a download. The primary only streams after this
    /// request — nothing is fetched speculatively, and resume picks up at
    /// the first missing chunk.
    func download(_ manifest: LinkedBlobManifest) async -> AsyncStream<LinkedDownloadEvent> {
        let (stream, continuation) = AsyncStream<LinkedDownloadEvent>.makeStream()
        let transferID = manifest.transferID
        // Supersede any previous stream for this transfer.
        inboundContinuations[transferID]?.finish()
        watchdogs[transferID]?.cancel()
        let transfer = InboundBlobTransfer(
            manifest: manifest,
            receivedIndexes: persistedReceived(for: manifest.attachmentID)
        )
        inbound[transferID] = transfer
        inboundContinuations[transferID] = continuation
        persistInboundManifest(manifest)
        if await transfer.isComplete {
            await finalize(transferID: transferID)
        } else {
            let fromIndex = await transfer.nextMissingIndex
            do {
                try await deviceLink.sendSync(
                    kind: .attachmentRequest,
                    body: JSONEncoder().encode(LinkedBlobRequest(
                        transferID: transferID,
                        attachmentID: manifest.attachmentID,
                        messageID: manifest.messageID,
                        conversationID: manifest.conversationID,
                        fromIndex: fromIndex
                    ))
                )
                startWatchdog(transferID: transferID)
            } catch {
                fail(transferID: transferID, reason: error.localizedDescription)
            }
        }
        return stream
    }

    /// Linked: download without a known manifest (the offer was missed).
    /// Sends a blind request correlated by attachmentID (== transferID);
    /// the primary re-offers from the stored message, and the download
    /// starts when the manifest arrives. Fails honestly when the primary
    /// is unreachable or the message is gone.
    func downloadBlind(
        attachmentID: UUID,
        messageID: UUID,
        conversationID: UUID
    ) async -> AsyncStream<LinkedDownloadEvent> {
        let (stream, continuation) = AsyncStream<LinkedDownloadEvent>.makeStream()
        // A manifest may have arrived between the caller's check and now.
        if let manifest = manifest(for: attachmentID) {
            Task {
                for await event in await self.download(manifest) {
                    continuation.yield(event)
                }
                continuation.finish()
            }
            return stream
        }
        parkedBlind[attachmentID]?.finish()
        parkedBlind[attachmentID] = continuation
        do {
            // transferID == attachmentID: the primary treats an unknown
            // transfer ID as "re-offer this attachment".
            try await deviceLink.sendSync(
                kind: .attachmentRequest,
                body: JSONEncoder().encode(LinkedBlobRequest(
                    transferID: attachmentID,
                    attachmentID: attachmentID,
                    messageID: messageID,
                    conversationID: conversationID,
                    fromIndex: 0
                ))
            )
            startBlindWatchdog(attachmentID: attachmentID)
        } catch {
            parkedBlind.removeValue(forKey: attachmentID)
            continuation.yield(.failed(error.localizedDescription))
            continuation.finish()
        }
        return stream
    }

    /// No manifest for 90s → the primary is unreachable or the message is
    /// gone. Honest failure with retry, never a silent stall.
    private func startBlindWatchdog(attachmentID: UUID) {
        blindWatchdogs[attachmentID]?.cancel()
        blindWatchdogs[attachmentID] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 90_000_000_000)
            guard let self else { return }
            if Task.isCancelled { return }
            if let parked = await self.takeParkedBlind(forKey: attachmentID) {
                parked.yield(.failed(
                    "Couldn't reach your primary device. Make sure it's online, then try again."))
                parked.finish()
            }
        }
    }

    /// Routes one inbound chunk into its transfer.
    func ingest(_ chunk: LinkedBlobChunk) async {
        if inbound[chunk.transferID] == nil {
            // Chunks arriving with no active download (e.g. the primary
            // kept streaming across a reconnect): rebuild from the
            // persisted manifest so progress isn't lost.
            if let manifest = persistedInboundManifests().first(where: { $0.transferID == chunk.transferID }) {
                inbound[chunk.transferID] = InboundBlobTransfer(
                    manifest: manifest,
                    receivedIndexes: persistedReceived(for: manifest.attachmentID)
                )
            } else {
                return
            }
        }
        guard let transfer = inbound[chunk.transferID] else { return }
        lastChunkAt[chunk.transferID] = Date()
        guard let progress = await transfer.ingest(chunk) else { return }
        if let continuation = inboundContinuations[chunk.transferID] {
            continuation.yield(.progress(progress))
        }
        // Throttle persistence: every 16 chunks is plenty for resume.
        let count = (persistCounters[chunk.transferID] ?? 0) + 1
        persistCounters[chunk.transferID] = count
        if count % 16 == 0 {
            await persistReceived(for: transfer)
        }
        if await transfer.isComplete {
            await persistReceived(for: transfer)
            await finalize(transferID: chunk.transferID)
        }
    }

    /// Routes a primary-side failure notice to the waiting download.
    func noteFailure(_ failure: LinkedBlobFailure) async {
        log.warning("Blob transfer failed remotely: \(failure.reason)")
        fail(transferID: failure.transferID, reason: failure.reason)
    }

    /// Rebuilds in-flight reassembly after the paired channel rebinds
    /// (app launch). Does NOT auto-download: transfers with a live waiter
    /// re-request from their resume offset; the rest wait for the next tap.
    func resumeIncomplete() async {
        for manifest in persistedInboundManifests() {
            let destination = destinationURL(for: manifest)
            if FileManager.default.fileExists(atPath: destination.path) {
                // Already fully downloaded in a previous run.
                clearInboundPersistence(attachmentID: manifest.attachmentID)
                continue
            }
            if inbound[manifest.transferID] == nil {
                inbound[manifest.transferID] = InboundBlobTransfer(
                    manifest: manifest,
                    receivedIndexes: persistedReceived(for: manifest.attachmentID)
                )
            }
            // A live waiter means the user is actively watching this
            // download: resume it instead of letting the watchdog fail.
            if inboundContinuations[manifest.transferID] != nil,
               let transfer = inbound[manifest.transferID],
               await !transfer.isComplete
            {
                let fromIndex = await transfer.nextMissingIndex
                try? await deviceLink.sendSync(
                    kind: .attachmentRequest,
                    body: JSONEncoder().encode(LinkedBlobRequest(
                        transferID: manifest.transferID,
                        attachmentID: manifest.attachmentID,
                        messageID: manifest.messageID,
                        conversationID: manifest.conversationID,
                        fromIndex: fromIndex
                    ))
                )
                startWatchdog(transferID: manifest.transferID)
            }
        }
    }

    /// Linked-side unpair: stops everything, drops staged bytes and
    /// persisted manifests. (Channel keys are wiped by DeviceLinkManager;
    /// already-downloaded files stay — unpairing cannot remote-wipe.)
    func dropAll() async {
        for transferID in inboundContinuations.keys {
            fail(transferID: transferID, reason: "Device unpaired.")
        }
        for attachmentID in parkedBlind.keys {
            blindWatchdogs[attachmentID]?.cancel()
            if let parked = parkedBlind.removeValue(forKey: attachmentID) {
                parked.yield(.failed("Device unpaired."))
                parked.finish()
            }
        }
        blindWatchdogs.removeAll()
        inbound.removeAll()
        let staging = AegisPaths.ensureStaging()
        if let files = try? FileManager.default.contentsOfDirectory(
            at: staging, includingPropertiesForKeys: nil) {
            for file in files where file.lastPathComponent.hasPrefix("devlink-in-") {
                try? FileManager.default.removeItem(at: file)
            }
        }
        UserDefaults.standard.removeObject(forKey: PersistKeys.inboundManifests)
        UserDefaults.standard.removeObject(forKey: PersistKeys.inboundReceived)
    }

    // MARK: - Linked: finalize

    private func finalize(transferID: UUID) async {
        guard let transfer = inbound[transferID] else { return }
        let manifest = await transfer.manifest
        do {
            let blob = try await transfer.verifiedData()
            let staged = AegisPaths.ensureStaging()
                .appendingPathComponent("devlink-in-\(transferID.uuidString).blob", isDirectory: false)
            try blob.write(to: staged, options: .completeFileProtection)
            let destination = destinationURL(for: manifest)
            if FileManager.default.fileExists(atPath: destination.path) {
                try? FileManager.default.removeItem(at: destination)
            }
            // Same framing as the relay path: the blob is AttachmentCrypto
            // ciphertext (nonce || ct || tag); the file key came sealed
            // inside the paired manifest.
            try AttachmentCrypto.decryptFile(
                at: staged, key: SymmetricKey(data: manifest.fileKey), to: destination)
            try? FileManager.default.removeItem(at: staged)
            clearInboundPersistence(attachmentID: manifest.attachmentID)
            inbound[transferID] = nil
            persistCounters[transferID] = nil
            watchdogs[transferID]?.cancel()
            watchdogs[transferID] = nil
            lastChunkAt[transferID] = nil
            log.info("Blob download complete: \(manifest.filename)")
            if let continuation = inboundContinuations.removeValue(forKey: transferID) {
                continuation.yield(.done(destination))
                continuation.finish()
            }
        } catch {
            log.warning("Blob finalize failed: \(error.localizedDescription)")
            fail(transferID: transferID, reason: "This file failed verification. Try downloading again.")
        }
    }

    private func fail(transferID: UUID, reason: String) {
        watchdogs[transferID]?.cancel()
        watchdogs[transferID] = nil
        lastChunkAt[transferID] = nil
        if let continuation = inboundContinuations.removeValue(forKey: transferID) {
            continuation.yield(.failed(reason))
            continuation.finish()
        }
    }

    /// No chunk for 90s → the primary is unreachable or stopped serving.
    /// Honest failure (with retry), never a silent stall.
    private func startWatchdog(transferID: UUID) {
        watchdogs[transferID]?.cancel()
        lastChunkAt[transferID] = Date()
        watchdogs[transferID] = Task { [weak self] in
            while true {
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                guard let self else { return }
                if Task.isCancelled { return }
                guard await self.inbound[transferID] != nil else { return }
                let last = await self.lastChunkAt[transferID] ?? .distantPast
                if Date().timeIntervalSince(last) > 90 {
                    await self.fail(
                        transferID: transferID,
                        reason: "Couldn't reach your primary device. Make sure it's online, then try again."
                    )
                    return
                }
            }
        }
    }

    /// Destination matches the primary's local layout so the existing
    /// viewers (AttachmentContentView / VoiceNoteBubbleView) find the file
    /// without changes: "<attachmentID>-<filename>" / "<id>.m4a".
    private func destinationURL(for manifest: LinkedBlobManifest) -> URL {
        switch manifest.kind {
        case .voiceNote:
            return AegisPaths.attachmentsDirectory
                .appendingPathComponent("\(manifest.attachmentID.uuidString).m4a", isDirectory: false)
        case .attachment:
            return AegisPaths.attachmentsDirectory
                .appendingPathComponent(
                    "\(manifest.attachmentID.uuidString)-\(manifest.filename)", isDirectory: false)
        }
    }

    // MARK: - Persistence (UserDefaults; small JSON)

    private func persistInboundManifest(_ manifest: LinkedBlobManifest) {
        var dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.inboundManifests) as? [String: Data]) ?? [:]
        if let data = try? JSONEncoder().encode(manifest) {
            dict[manifest.attachmentID.uuidString] = data
            UserDefaults.standard.set(dict, forKey: PersistKeys.inboundManifests)
        }
    }

    private func persistedInboundManifests() -> [LinkedBlobManifest] {
        let dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.inboundManifests) as? [String: Data]) ?? [:]
        let decoder = JSONDecoder()
        return dict.values.compactMap { try? decoder.decode(LinkedBlobManifest.self, from: $0) }
    }

    private func persistedReceived(for attachmentID: UUID) -> [Int] {
        let dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.inboundReceived) as? [String: [Int]]) ?? [:]
        return dict[attachmentID.uuidString] ?? []
    }

    private func persistReceived(for transfer: InboundBlobTransfer) async {
        let manifest = await transfer.manifest
        var dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.inboundReceived) as? [String: [Int]]) ?? [:]
        dict[manifest.attachmentID.uuidString] = await transfer.receivedIndexes
        UserDefaults.standard.set(dict, forKey: PersistKeys.inboundReceived)
    }

    private func clearInboundPersistence(attachmentID: UUID) {
        if var dict = UserDefaults.standard.dictionary(forKey: PersistKeys.inboundManifests) as? [String: Data] {
            dict.removeValue(forKey: attachmentID.uuidString)
            UserDefaults.standard.set(dict, forKey: PersistKeys.inboundManifests)
        }
        if var dict = UserDefaults.standard.dictionary(forKey: PersistKeys.inboundReceived) as? [String: [Int]] {
            dict.removeValue(forKey: attachmentID.uuidString)
            UserDefaults.standard.set(dict, forKey: PersistKeys.inboundReceived)
        }
    }

    private func persistOfferedManifest(_ manifest: LinkedBlobManifest) {
        var dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.offeredManifests) as? [String: Data]) ?? [:]
        if let data = try? JSONEncoder().encode(manifest) {
            dict[manifest.transferID.uuidString] = data
            // Bound the registry: manifests are small; 256 entries max.
            while dict.count > 256 {
                if let oldest = dict.keys.sorted().first { dict.removeValue(forKey: oldest) }
                else { break }
            }
            UserDefaults.standard.set(dict, forKey: PersistKeys.offeredManifests)
        }
    }

    private func persistedOfferedManifest(id: UUID) -> LinkedBlobManifest? {
        let dict = (UserDefaults.standard.dictionary(forKey: PersistKeys.offeredManifests) as? [String: Data]) ?? [:]
        guard let data = dict[id.uuidString] else { return nil }
        return try? JSONDecoder().decode(LinkedBlobManifest.self, from: data)
    }

    private func evictStagedIfNeeded() {
        let staging = AegisPaths.ensureStaging()
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: staging, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey]
        ) else { return }
        let active = Set(stagedBlobs.values.map(\.lastPathComponent))
        var total: Int64 = 0
        var candidates: [(URL, Int64, Date)] = []
        for file in files where file.lastPathComponent.hasPrefix("devlink-") {
            guard !active.contains(file.lastPathComponent) else { continue }
            let values = try? file.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
            let size = Int64(values?.fileSize ?? 0)
            total += size
            candidates.append((file, size, values?.creationDate ?? .distantPast))
        }
        guard total > Self.maxStagedBytes else { return }
        for (file, size, _) in candidates.sorted(by: { $0.2 < $1.2 }) {
            try? FileManager.default.removeItem(at: file)
            total -= size
            if total <= Self.maxStagedBytes { break }
        }
    }
}

enum BlobRelayError: Error, LocalizedError {
    case blobUnavailable

    var errorDescription: String? {
        switch self {
        case .blobUnavailable: return "The file is no longer available."
        }
    }
}
