# Aegis iOS App — Integration Notes

> **Wave 2 status (2026-10-10): all 7 mismatches below are RESOLVED.**
> See `docs/INTEGRATION.md` for the verified module map, every
> cross-package contract, and the macOS gate checklist. This document is
> kept as the historical record of what Wave 1 flagged.

Owner: Agent 2 (SwiftUI app). The app is **feature-complete against mock
services** and every screen renders in Xcode previews. This document is the
contract the other workstreams must satisfy to go live.

## 1. Current wiring status

- `Aegis/Bootstrap.swift` → `PreviewServiceFactory()` (mock crypto/transport/store).
- **Before any TestFlight or distribution build, replace this with the live
  factory** that constructs the real `AegisCrypto` / `AegisTransport` /
  `AegisStore`-backed services. The app only depends on the three protocols in
  `Aegis/Protocols/` — the swap is mechanical.
- The mock crypto is explicitly **not real cryptography** (labeled at every
  method). Never ship it.

## 2. What I need from the project / packages

- `project.yml` (repo root) defines the `Aegis` app target + the three local
  packages. Generate with `xcodegen generate` (Xcode 16+, iOS 17+ deployment
  target, Swift 6.0, strict concurrency = complete).
- If Agent 4's `Package.swift` names the library products differently from the
  package directories, update the `products:` lists in `project.yml`.
- The app's `WirePayload` (`Aegis/Support/WirePayload.swift`) is the app's own
  JSON envelope schema, `version: 1`. Crypto and transport must treat it as
  **opaque bytes** — encrypt/decrypt and ship it, nothing more. Bump
  `currentVersion` if the schema ever changes.

## 3. CryptoService — what AegisCrypto must provide

Boundary rule (already enforced in the protocol): **private key material never
crosses into the app.** Keygen, Keychain/Secure Enclave storage, X3DH, Double
Ratchet, and sender-key sessions all live in AegisCrypto.

| App calls | Notes for the crypto workstream |
|---|---|
| `createIdentity(displayName:)` | Generate the Ed25519/X25519 identity keypair on-device. Return public facts only. |
| `fingerprint(of:)` | Deterministic string per key (my UI groups it in 5s). Must be **stable** — it anchors safety-number verification. |
| `safetyNumber(local:remote:)` | 60-digit style combined number, stable for a key pair. |
| `qrPayload(for:)` / `remoteIdentity(fromInvitePayload:)` | My mock format: `AEGIS1:<base64-std pubkey>:<pct-encoded name>` and short code `aegis-invite-<base64-std pubkey>`. Keep the `AEGIS1:` version prefix so formats can evolve; the parser must reject garbage with a typed error. |
| `inviteCode(for:)` | Short, copy-pasteable. |
| `encryptMessage(_:conversationID:recipientKeys:)` | DM → Double Ratchet; group/channel → sender-key session. `recipientKeys` lets you pick sessions. |
| `decryptMessage(_:conversationID:senderKey:)` | Mirror of the above. |
| `encryptAttachment(at:conversationID:) -> EncryptedFile` | Fresh random file key per attachment; return ciphertext URL + wrapped key + nonce + byte count. |
| `decryptAttachment(ciphertextURL:wrappedKey:nonce:to:)` | **Open question — nonce framing.** My `ConversationViewModel` currently passes `nonce: Data()` (empty) because the framing isn't settled. Decide: is the nonce prepended to the ciphertext file, or carried separately in the message? Tell me and I'll adapt the two call sites. |
| `exportEncryptedBackup(passphrase:)` / `importEncryptedBackup(_:passphrase:)` | Passphrase → Argon2id/scrypt → XChaCha20-Poly1305 blob. **Scope question:** my export currently covers what crypto knows (identity + sessions). The *store snapshot* (messages/contacts) needs a home — either crypto pulls it via a StoreService it owns, or I add `exportAll()`/`importAll()` to `StoreService` and the app assembles the backup. Recommend the latter; say the word and I'll add the methods. |
| `backupPassphraseStrength(_:)` | Local strength estimate for the meter UI. |

## 4. TransportService — what AegisTransport must provide

- Hot streams: `connectionEvents`, `incomingEnvelopes`, `incomingCallEvents`,
  `callStateEvents` (all `AsyncStream`).
- `configureRelay(_:)` / `currentRelayConfig()` / `retryConnection()` /
  `testRelay(url:) -> RelayTestResult` — powers Settings → Relay, including
  LAN-only mode (my UI banners it) and custom self-hosted relays.
- `sendEnvelope(_:)` / `sendTypingIndicator` / `sendReadReceipt` /
  `sendScreenshotNotice` — the last one fires when the local user screenshots
  with the setting on; peers display the notice.
- `uploadBlob(from:id:) -> AsyncStream<Double>` and
  `downloadBlob(locator:id:to:) -> AsyncStream<Double>` — 0…1 progress, finish
  on completion. Ciphertext only; the locator is an opaque id.
- Calls: `placeCall` → call id; `answerCall` / `declineCall` / `endCall`;
  `setCallMuted` / `setCallVideoEnabled` / `setCallSpeaker`;
  `startScreenShare` / `stopScreenShare`; `screenShareSupported`.
- **MISSING — remote video rendering.** `ActiveCallView` currently shows an
  avatar placeholder with an honest comment. I need one of: `func
  remoteVideoView(for callID: UUID) -> UIView` (UIKit view I can wrap), or a
  `VideoSink` protocol + `setVideoSink(_:for:)`. Without this, video calls are
  presence + audio only.
- **MISSING — group membership events.** `GroupDetailView` refreshes on
  appear only. I want `groupEvents: AsyncStream<GroupEvent>` with
  `memberJoined` / `memberRemoved` / `roleChanged` / `topicChanged` /
  `announcementModeChanged` so the roster updates live.
- Group ops: `createGroup` / `createChannel` / `inviteMember` / `removeMember`
  / `setMemberRole` / `setAnnouncementOnly` / `setGroupTopic` /
  `rotateSenderKey` / `leaveConversation`.
- **Sealed sender:** the app exposes the toggle (`SettingsKeys.sealedSender`,
  default ON). The transport must honor it at the envelope layer — with it on,
  the relay must not learn sender↔recipient pairs.

## 5. StoreService — what AegisStore must provide

- Conversations: `fetchConversations()` / `fetchConversation(id:)` (added by
  me — please implement) / `saveConversation(_:)` / `deleteConversation(id:)`.
- Messages: `fetchMessages(conversationID:limit:before:)` (newest-first page),
  `saveMessage` / `updateMessage` / `deleteMessage(id:conversationID:)`,
  `purgeExpiredMessages() -> Int`, `searchMessages(query:limit:)` (FTS for
  in-app search).
- Contacts, call history, `storageUsage()` / `clearCaches()` (caches only —
  never messages/identity).
- **Encryption at rest is the store's job.** The app hands you plaintext
  models; document the guarantee (Data Protection class + encrypted DB/file).
- Backup scope question — see §3.

## 6. Architecture decisions already settled (do not relitigate in code)

- **No APNs, no push server.** Delivery is realtime when the app is
  open/nearby, store-and-forward via the relay otherwise; `NotificationManager`
  schedules **on-device** local notifications. Background modes: `audio` +
  `fetch` only.
- **No accounts.** Identity = keypair. No phone numbers, no email, no
  discovery — contacts are added explicitly via QR/invite code.
- UI consumes the packages **only** through `Aegis/Protocols/`. Do not reach
  around them.

## 7. Previews

Every major view has a `#Preview` powered by `Support/PreviewServices.swift`
(mock services) and `Support/SampleData.swift` (deterministic fictional data:
pinned/muted/archived chats, reactions, edits, tombstones, attachments, voice
notes, identity-change warning, call history). Open any view file in Xcode 16+
and it renders.

## 8. Paths I own vs. paths I don't touch

- Mine: `Aegis/**`, `project.yml`, this file.
- Not mine (owned by other agents): `Packages/AegisCrypto`,
  `Packages/AegisTransport`, `Packages/AegisStore`, `relay/`, `docs/`,
  `.github/`, root `Package.swift`, `README.md`.
