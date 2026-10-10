# Aegis — Integration Map (Wave 2)

How the four Wave 1 workstreams fit together, every cross-package contract,
and exactly what still needs a Mac. This document is verified against the
actual sources — it describes what the code does, not what was planned.

**Status:** integration complete on Linux to the extent Linux allows.
Swift cannot compile here; every new/edited Swift file received a careful
manual review pass (see §8 for what the compiler still must confirm).

---

## 1. Verified module map

```
~/workspace/aegis/
├── Aegis/                      # iOS app (SwiftUI, iOS 17+, XcodeGen)
│   ├── Adapters/               # ← Wave 2. The ONLY place packages meet the app.
│   │   ├── AegisCore.swift         # One actor: engine + store + hub + dispatch
│   │   ├── CryptoEngine.swift      # X3DH/ratchet/groups/sealed-sender/backup
│   │   ├── LiveAdapters.swift      # CryptoService/TransportService/StoreService impls
│   │   ├── StoreMapping.swift      # App models ↔ AegisStore models, sidecars
│   │   └── KeychainHelper.swift    # Keychain access (identity, wrapped keys)
│   ├── Protocols/              # CryptoService, TransportService, StoreService
│   ├── Core/AppState.swift     # Single consumer of all transport streams
│   ├── Bootstrap.swift         # LiveServiceFactory is the wired factory
│   └── INTEGRATION_NOTES.md    # Wave 1's 7 mismatches — all resolved (§2)
├── Packages/
│   ├── AegisCrypto/            # X3DH + Double Ratchet + Sender Keys + sealed sender
│   ├── AegisTransport/         # AegisFrame, TransportHub, RelayTransport, LANTransport,
│   │                           # DeliveryCoordinator, CallMediaRouter/VideoSink, GroupEvents
│   └── AegisStore/             # Repositories, InMemoryStore, StoreSnapshot
├── relay/relay.py              # Dumb relay (asyncio). `--self-test` green on Linux.
├── docs/                       # CRYPTO, THREAT_MODEL, NETWORKING, SELF_HOSTING,
│                               # FEATURES, ROADMAP, + this file
├── project.yml                 # XcodeGen: app target + 3 local packages (names verified
│                               # against each Package.swift product name)
├── Package.swift               # Umbrella SPM manifest (documented; the app builds via XcodeGen)
└── .github/workflows/ci.yml    # 3 jobs: swift-packages, app, relay (YAML valid)
```

**Boundary rule:** the app talks ONLY to the three protocols in
`Aegis/Protocols/`. The adapters are the only files that import the
packages. UI code never imports AegisCrypto/AegisTransport/AegisStore
directly. Private key material never crosses into the app layer — the
protocols carry only public keys, ciphertext, and opaque wrapped keys.

---

## 2. The 7 integration mismatches — all resolved

From `Aegis/INTEGRATION_NOTES.md`:

| # | Item | Resolution |
|---|------|------------|
| 1 | Video sink protocol | `VideoSink` protocol + `CallMediaRouter` added to AegisTransport (`CallMedia.swift`); `TransportService.setVideoSink(_:for:)` wired through `LiveTransportService` → core's router. |
| 2 | Group membership events stream | Transport emits `GroupEvents`; `TransportService.groupEvents` is live. `AegisCore` translates verified `GroupControlMessage`s into `GroupEvent`s; `AppState` (single stream consumer) re-broadcasts on `NotificationCenter` (`.aegisGroupEvent`) so any number of views observe without competing for the `AsyncStream`; `GroupDetailViewModel` refreshes roster/topic/announcement mode live. |
| 3 | Attachment nonce framing | **Nonce prepended**: blob layout is `nonce(12) \|\| ciphertext \|\| tag(16)` (`AttachmentCrypto`). The `nonce:` parameter on `decryptAttachment` is vestigial by design (documented at the call site); the VM passes `Data()`. |
| 4 | Backup export scope | Crypto exports identity+sessions (`KeyBackup`); the store exports `StoreSnapshot` (new `snapshot()`/`restore()` on the `AegisStore` protocol + `InMemoryStore`); **the app assembles both halves** — `CryptoEngine.BackupEnvelope{v=1, displayName, cryptoBlob, storeSnapshot}`, passphrase-encrypted. `StoreService.exportAll()`/`importAll()` added for the store half. |
| 5 | `fetchConversation(id:)` | `LiveStoreService.fetchConversation` maps `InMemoryStore.fetch(id:)`. |
| 6 | Sealed-sender toggle honoring | Toggle at `SettingsKeys.sealedSender` (`@AppStorage` in PrivacySettingsView, default ON registered in `AegisApp`); honored in `CryptoEngine.maybeSeal`/`maybeOpen`. Honest note: sender anonymity is structural — no sender field exists on the wire at any layer; the toggle controls the extra SealedSender envelope (cert + padding). Inbound accepts sealed and unsealed regardless of the toggle (must, for interop). |
| 7 | Bootstrap live factory swap | `Bootstrap.serviceFactory` is now `LiveServiceFactory` (one shared `AegisCore`); `PreviewServiceFactory` remains for `#Preview` only. `AegisCore` self-boots transports on init; `LiveServiceFactory.boot()` re-entry is idempotent. |

Plus, from the transport agent's §14 and the crypto rule:

- **Sender-key distributions travel encrypted inside 1:1 sessions.** `CryptoEngine.distributeEncrypted` encrypts each `OutgoingDistribution` with `encryptDirect` to the recipient; `AegisCore.distribute` frames the already-encrypted wire directly as a `flagTransportControl` envelope (a double-encryption bug found in review was fixed). The receiver detects distributions by `SenderKeyDistribution` try-parse after `decryptDirect`; other control kinds (`callSignal`, `groupInvite`, `knock`, `sessionReset`) are JSON `TransportControl` envelopes.
- **16B vs 32B mailbox reconciliation** (a real inconsistency found in Wave 2): the crypto 16-byte `Identity.mailboxID` is the *sealed-sender addressing* identity (KDF salt/AAD); the transport 32-byte `MailboxID` is the *wire routing label*. New `RoutingMailbox` enum in AegisCrypto: `identityRoute(fingerprint)` (stable, pre-session first contact), `directRoute(localFP, remoteFP, ephemeralPub)` (stable per X3DH session — rotates at re-handshake, documented), `groupRoute(groupID, epoch)` (rotates on membership change; core rebinds the mailbox after every epoch bump).
- **Simultaneous X3DH initiation:** deterministic tie-break — the lexicographically smaller fingerprint wins and keeps its session; the winner still decrypts the loser's first message via a one-shot `SessionEstablishment.respond` so nothing is silently lost.
- **Invite flow (no central server):** invites carry the bundle: `AEGIS1:<b64url(IdentityPublic)>:<b64url(PreKeyBundle)>:<pct-name>`. Legacy `aegis-invite-` payloads are rejected loudly, not misparsed.

---

## 3. Cross-package contracts

### 3.1 Wire framing (verified byte-identical)

`AegisFrame` (Swift) and `relay.py` agree exactly:

```
0  2   magic "AG" (0x41 0x47)
2  1   version (1)
3  1   flags: bit0 finalChunk | bit1 knock | bit2 transportControl
4  32  mailbox (routing label)
36 16  envelope ID
52  4   ttl seconds BE (0 = relay default)
56  4   payload length BE
60  …   payload (≤ 5 MiB)
```

Relay behavior (verified in `relay.py`, matches `docs/NETWORKING.md`):
TTL default 7 days, max 14 days, queue 1,000 envelopes/mailbox with
oldest-drop, operator-tunable via `AEGIS_*` env. App-side TTLs:
typing 60s; read receipts, screenshot notices, call signals, knocks 300s;
messages/group control 0 (relay default); blob chunks 7 days.

### 3.2 Session-layer inner messages (inside the frame payload)

First byte is always the protocol version; second byte dispatches
(`RatchetMessage` 0x01, `PreKeyMessage` 0x02, `GroupMessage` 0x10).
**Exception:** `SealedEnvelope` does *not* write its 0x20 wire-type byte —
it is detected by strict try-parse + AEAD open, never by the type byte
(the receiver tries sealed first, falls back to the type byte).

Layering: the transport emits session-layer **ciphertext** opaquely for
user messages — `IncomingEnvelope.ciphertext` is decrypted only by
`CryptoService.decryptMessage` in the app. The transport never sees
plaintext. Group user messages are `GroupInnerPayload{kind:"message",
body}` inside the sender-key session; group control messages use
`kind:"control"`.

### 3.3 Attachments & blobs

- File crypto: fresh 32B key per file; blob = `nonce(12)‖ct‖tag(16)`.
- The wrapped file key travels **inside the message envelope**
  (sender-key-encrypted for groups, ratchet-encrypted for DMs). The key
  never touches the relay or the DB — it lives in the Keychain
  (`app.aegis.wrappedkeys`).
- Blob transfer: chunked sealed frames, `BlobChunkHeader(uploadID(16)‖
  index u32‖count u32)` + ciphertext chunk, ≤ 5 MiB − 24 B per frame.
  Locator stored with the attachment:
  `<routing-mailbox hex>:<attachment UUID hex>`.
  100 MB per-file cap (relay `MAX_PAYLOAD`, `AttachmentCrypto.readBounded`).

### 3.4 Backup

`BackupEnvelope{v:1, displayName, cryptoBlob, storeSnapshot}` →
passphrase-encrypted via `KeyBackup` (Argon2id). Restoring keeps the
**backed-up signed prekey** (`PreKeyManager(restoring:identity:)`, added
in Wave 2) so bundles peers already hold keep working; one-time prekeys
refill fresh. Attachment ciphertext files are copied by the app
separately (documented on `StoreService.exportAll`).

### 3.5 Calls

Sealed knock-and-rendezvous: knock = `flagKnock` frame, TTL 300s,
`TransportControl{kind:"knock", body: KnockInfo{callID, offer, mediaKind}}`
encrypted in the 1:1 session. Signaling continues over the same channel
(`CallSignal`: offer/answer/ice/control, manually `Codable` with a `t`
discriminator). Media is the app's WebRTC stack behind
`CallMediaDelegate` — without it, signaling runs with empty SDP (the
honest seam; see §5).

### 3.6 Identity & trust

- Identity: Ed25519 + X25519, Keychain (`app.aegis.identity`), 32B seeds.
- Fingerprint = `SHA256(signingPub ‖ agreementPub)`; safety numbers via
  `SafetyNumber` (60-digit display).
- Trust decisions live in the store's verification state; crypto exposes
  fingerprints, the app decides what "verified" means in UI.
- Contact full public keys live in `ContactKeyDirectory` (JSON, app
  support dir); the package `Contact` stores only the fingerprint hex —
  as designed.

---

## 4. Data flow (one message, end to end)

**Outbound DM:** UI → `CryptoService.encryptMessage` → `CryptoEngine`
(X3DH lazily on first message, else Double Ratchet; sealed envelope when
the toggle is on) → `TransportService.sendEnvelope` → `AegisCore`
mailbox lookup (direct route) → `TransportHub.send` (LAN + relay) with
per-kind TTL.

**Inbound DM:** `TransportHub.inbound` (broadcast — every consumer sees
every frame) → `AegisCore.handleFrame` → route by mailbox → control?
(`flagTransportControl`: decrypt → distribution-parse or
`TransportControl` dispatch; consumed fully by the core) : user message
→ `IncomingEnvelope{ciphertext}` → `AppState.handleIncoming` →
`CryptoService.decryptMessage` → `WirePayload` dispatch → store + UI.

**Group message:** `encryptGroup` → sender-key session → frame on the
epoch's group mailbox. Rotation distributions go out first, each
1:1-encrypted (§2). Frames arriving before their sender key are stashed
(bounded 50/group) and retried when the distribution lands.

**Group membership change:** `updateGroupMembership` → epoch bump →
mailbox rebind → distributions (1:1-encrypted) + `GroupControlMessage`
on the group channel → receivers update package memberships and emit
`GroupEvent` → `AppState` → `NotificationCenter` → `GroupDetailViewModel`
live refresh.

---

## 5. Seams (designed extension points)

| Seam | Location | Swap |
|------|----------|------|
| Crypto provider | `AegisCrypto` (`CryptoProvider` protocol, `CryptoKitProvider` default) | **libsignal swap**: implement `CryptoProvider` (+ the X3DH/ratchet types) on libsignal-protocol; `CryptoEngine` is untouched — it programs to `AegisCrypto`'s API, not CryptoKit. |
| Onion transport | `TransportHub(transports:)` | Add an onion-routing `Transport`; `DeliveryCoordinator` and `AegisCore` only see `any Transport` + `AegisFrame`. Mailbox abstraction is already unlinked from identity. |
| WebRTC media | `CallMediaDelegate` on `AegisCore` | The app's WebRTC stack implements `createOffer/createAnswer/setRemoteSDP/addIceCandidate`; signaling, knock, and call state machine work without it. |
| Encrypted store | `AegisStore` protocol | `InMemoryStore` today; the SQLCipher adapter implements the same protocol (incl. new `snapshot()`/`restore()` and `calls.delete(id:)`). `StoreMapping` isolates all model translation. |
| Relay | `relay/relay.py` | Any implementation of the 60-byte frame + `bind`/`collect` semantics; `--self-test` is the conformance check. |

---

## 6. Honest limitations (architectural, not temporary)

- **No crypto audit.** The protocol design is documented (`docs/CRYPTO.md`,
  `docs/THREAT_MODEL.md`); endpoint security is the trust boundary.
- **Sessions are in-memory.** Restart drops them; the next outbound
  message transparently re-establishes via X3DH; undecryptable inbound in
  the gap surfaces visibly rather than silently. Durable session
  persistence needs `Codable` ratchet state (a package change).
- **No APNs push, by design.** No push token is ever registered (Apple
  learns nothing). Real-time when open/nearby; async store-and-forward +
  local notifications when closed; knock-and-rendezvous for calls.
  Closed-app latency is OS-scheduled and shown honestly.
- **Relay sees timing/size per rotating mailbox.** Content and identity
  are sealed; traffic analysis resistance is explicitly out of scope
  (see `docs/THREAT_MODEL.md`).
- **100 MB attachment cap**; one-time prekeys refill in memory across
  restarts; `directRoute` mailboxes rotate at re-handshake, not per message.

---

## 7. Docs corrected in Wave 2

- `docs/ROADMAP.md`: APNs removed as a "Phase 2 enhancement" — replaced
  with the settled no-APNs delivery design (background fetch + relay
  queue + local notifications; knock-and-rendezvous calls) in Phase 1
  risks, Phase 2 scope/exit criteria/risks, and the paid-account header.
- `README.md`: architecture diagram and Honest Limitations §(a) updated
  to the no-APNs design.
- Feature IDs cross-checked: `FEATURES.md` A-numbers (A1, A6–A8, A29–A34,
  A36, A37, A45, A47, …) all match `ROADMAP.md` references.

---

## 8. Verification

**Done on Linux (2026-10-10):**
- `python3 relay/relay.py --self-test` — PASS (all checks).
- Wire framing byte-identical Swift ↔ Python (60-byte header, field order,
  BE uint32s) — verified by reading both implementations.
- `ci.yml` parses as valid YAML; 3 jobs (swift-packages/app on
  macos-14, relay on ubuntu-latest).
- `project.yml` package names ↔ each `Package.swift` product name —
  match (`AegisCrypto`, `AegisTransport`, `AegisStore`).
- README + docs cross-links — all local targets exist.
- Manual review pass over every new/edited Swift file for syntax/API
  errors (no compiler available). Findings fixed in-review:
  sealed-envelope detection (try-parse, not type byte), a double
  encryption of sender-key distributions, `hexString` fileprivate
  redeclaration, a duplicated block in `StoreMapping`, missing
  `CallSignal` wire types (new `CallSignaling.swift`), sync/async
  mismatches on `qrPayload`/`inviteCode`/`remoteIdentity` (protocol made
  `async`, 4 call sites updated), `.memberAdded` → `.memberJoined`,
  `clearCallHistory` no-op → real implementation (new
  `CallRecordRepository.delete(id:)`), backup dropping display name and
  signed prekey (both fixed), blob tasks blocking the core actor
  (detached), group-event stream contention (AppState re-broadcast via
  `NotificationCenter`).

**macOS/Xcode gate — must run before any "done" claim:**
1. `swift test --package-path Packages/AegisCrypto`
2. `swift test --package-path Packages/AegisTransport`
3. `swift test --package-path Packages/AegisStore`
   (add tests: `PreKeyManager(restoring:)`, `calls.delete(id:)`,
   `RoutingMailbox` vectors, `CallSignal` Codable round-trip)
4. `brew install xcodegen && xcodegen generate` (from `project.yml`)
5. `xcodebuild build -scheme Aegis -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO`
6. `xcodebuild test` (same destination, `CODE_SIGNING_ALLOWED=NO`)
7. `python3 relay/relay.py --self-test` (also runs in CI on ubuntu)
8. Manual device-pair test: two devices exchange 1,000 messages over
   relay + LAN; intercept relay traffic and confirm only opaque
   envelopes; safety-number-change warning on simulated MITM key swap;
   sealed sender ON by default; outbox survives app kill + 24h offline;
   SQLCipher DB opens only with the correct key.
9. No paid Apple Developer account is needed for any of the above
   (simulator + sideloading); it is needed only for App Store/TestFlight
   distribution.

**Uncertainties the compiler must settle:** none are known-remaining —
every API used was checked against the defining source — but Swift's
type checker is the final authority, particularly around actor
isolation in `AegisCore`/`CryptoEngine` call chains, `Sendable`
closures in the detached blob tasks, and the manual `Codable` on
`CallSignal`.
