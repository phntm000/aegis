# Aegis — Delivery Roadmap

Phased, honest, and gated on evidence. A phase exits only when its exit
criteria are *demonstrated*, not asserted. Phases overlap in research but not
in "done" claims.

**Paid Apple Developer account — where it bites:**
- **Push notifications (APNs)** require a paid Apple Developer account
  ($99/yr), and Aegis deliberately does not use them: **no push token is
  ever registered**, so Apple learns nothing about who messages whom. The
  app is therefore designed to be **fully usable without push** —
  real-time when open/nearby (WebSocket relay, LAN Multipeer), async
  store-and-forward with local notifications when closed (relay queue +
  Background App Refresh), and sealed knock-and-rendezvous for calls.
  Closed-app latency is OS-scheduled; this is documented honestly in-app.
- **App Store / TestFlight distribution** also requires the paid account.
  Without it: Xcode sideloading to personally-owned devices (free, 7-day
  provisioning expiry, re-sign weekly) or ad-hoc distribution. CI builds and
  simulator tests need no paid account.
- Everything else — all crypto, relay, LAN, storage — is free forever.

---

## Phase 1 — MVP: trusted 1:1 chat
**Scope:** E2EE 1:1 messaging (A1) · sealed sender (A6) · offline-first
outbox (A7) · replies (A8) · contact verification / safety numbers (A30) ·
message requests (A31) · LAN-only mode (A45) · relay client + dumb relay
envelopes · encrypted local store via AegisStore/SQLCipher (A47) ·
biometric app lock (A34, lock only — decoy vault in Phase 4) ·
QR contact add (subset of A32).

**Exit criteria:**
- Two devices exchange 1,000 messages over relay + LAN with zero plaintext
  anywhere off-device (verified by intercepting relay traffic in test and
  confirming only opaque envelopes).
- Safety-number-change warning fires on simulated MITM key swap; sealed
  sender on by default.
- Outbox survives app kill + 24h offline; ordering preserved per conversation.
- SQLCipher DB opens only with correct key; wrong key fails closed.
- `swift test` green on all three packages; relay `--self-test` green.

**Known risks:**
- Sealed sender + spam: no server-side filtering exists, so the requests
  inbox UX must be excellent or first-contact becomes a spam vector.
  *Mitigation:* aggressive client-side heuristics + silent block, tuned in
  Phase 1 dogfooding.
- Double Ratchet multi-device comes later; Phase 1 is single-device per
  identity. *Mitigation:* architecture reserves per-device keys (A29) from
  day one so Phase 4 isn't a rewrite.
- iOS background execution limits: without APNs (a deliberate design choice —
  no push token is ever registered), incoming-message latency when the app
  is closed depends on background fetch scheduling (opaque, OS-controlled).
  *Mitigation:* document honestly in the connectivity UI; the relay's 7-day
  store-and-forward queue means nothing is lost, only delayed; LAN mode
  covers the office case.

## Phase 2 — Groups, media, and reach
**Scope:** E2EE groups (A2) · broadcast + announcement channels (A3, A4) ·
threads (A9) · reactions (A10) · polls (A12) · edit/delete + tombstones
(A11) · disappearing messages (A5) · read receipts / typing toggles (A13) ·
scheduled messages (A14) · starred/pinned (A15) · chunked encrypted
attachments (A18) · voice notes + on-device transcription (A19) · link
previews on-device (A17) · QR invites with expiry (A32) · nearby BLE
discovery (A33) · roles & permissions (A36) · slow mode (A37) · **no APNs
push, by design** (see Delivery below) · encrypted chat export (A16).

**Delivery (no APNs — settled design):** Aegis deliberately registers no
push token: Apple never learns who messages whom. Real-time delivery
happens when the app is open/nearby (WebSocket relay, LAN Multipeer);
otherwise the relay's store-and-forward queue (7-day TTL) plus iOS
Background App Refresh deliver on wake, surfaced as local notifications.
Calls use the sealed knock-and-rendezvous flow. Latency when closed is
OS-scheduled and documented honestly in-app; a paid Apple Developer
account is not required for any of it.

**Exit criteria:**
- 200-member group: key rotation on add/remove completes < 5s on iPhone 12;
  removed member provably cannot decrypt post-removal messages (test harness).
- 2 GB attachment uploads/resumes across app restart; per-chunk integrity
  verified; storage endpoint sees ciphertext only.
- Transcription runs with network entitlement disabled (build-setting audit).
- Closed-app delivery: relay queue + background fetch delivers within one
  OS wake cycle; local notification fires with content only after the app
  decrypts on-device — the relay and Apple see ciphertext/timing only.

**Known risks:**
- Sender-keys group ratchet at 1,000 members: re-key storms on membership
  churn. *Mitigation:* batch rotations, epoch coalescing; load-test in CI.
- Closed-app latency is OS-controlled (no APNs by design). *Mitigation:*
  document honestly in the connectivity UI; LAN mode covers the office case.
- BLE discovery battery cost. *Mitigation:* off by default, time-boxed
  sessions, measured in perf budget.

## Phase 3 — Calls and voice rooms
**Scope:** E2EE voice (A20) + video calls (A21) · group voice rooms (A23) ·
screen sharing view-only (A22) · push-to-talk (A24) · live captions
on-device (A25) · local call recording + consent signaling (A26) · noise
suppression (A27) · adaptive Opus (A28) · call records in store.

**Exit criteria:**
- 1:1 call setup < 2s on LTE; SRTP keys never touch the relay (packet capture
  shows ciphertext; relay operator test confirms no key material in logs).
- 20-person voice room: join/leave re-key < 1s; departed member's client
  cannot decrypt subsequent audio (test harness with recorded key material).
- Recording requires all-party signed consent ack before capture starts;
  consent events verify in the audit log.
- Call quality: MOS-equivalent ≥ 3.8 at 5% packet loss in network emulation.

**Known risks:**
- iOS CallKit + E2EE signaling interplay (CallKit wants phone-number-ish
  handles; we use opaque IDs). *Mitigation:* CallKit integration tested on
  device early in the phase, not at the end.
- NAT traversal without a central TURN fleet: users self-configure a
  forwarder or accept P2P IP exposure. *Mitigation:* relay-software ships an
  optional bundled media forwarder; UI discloses IP exposure before first
  P2P call (A20).
- Battery during long voice rooms. *Mitigation:* adaptive Opus + suspended
  video when backgrounded; measured, not assumed.

## Phase 4 — Multi-device and beyond-parity
**Scope:** Multi-device linking + revocation (A29) · duress PIN / decoy vault
(A34) · screenshot detection alerts (A35) · relay transparency canary (A38) ·
local signed admin audit log (A43) · per-message forward-secrecy re-key
(A39) · compromise-recovery ceremony (A40) · ghost mode presence (A41) ·
local-only vault chats (A42) · scheduled briefing channels (A44) ·
account-less encrypted cloud backup (A46) · global on-device search (A48).

**Exit criteria:**
- Primary + 2 companions: message sync converges, revocation of one device
  rotates all shared group keys and notifies contacts < 30s.
- Decoy vault opens under duress PIN with zero access to real DB (forensic
  check: real DB file untouched, mtime unchanged).
- Recovery ceremony walkthrough completes end-to-end in user testing with
  non-expert participants.
- Ghost-mode traffic indistinguishable from real traffic to a relay-level
  observer in the test harness (size/cadence distribution test).

**Known risks:**
- Multi-device ratchet state divergence (the classic Signal-desktop class of
  bugs). *Mitigation:* per-device ratchets + server-side fan-out of sealed
  envelopes per device; conflict resolution is "both deliver, dedupe by ID."
- Decoy vault realism: a staged-looking decoy is worse than none.
  *Mitigation:* optional upkeep synthesizer; honest in-app caveats (A34).
- This phase is where "never been done before" claims get tested — the
  ceremony UX and ghost-mode traffic shaping need real user studies, not just
  unit tests.

---

## Non-goals (explicitly out of scope)
- Server-side anything that reads content: search, preview, transcription,
  moderation, spam filtering. These stay client-side permanently.
- Federation with other networks, bridges to Discord/Telegram (bridges
  inherently break E2EE and metadata promises).
- Desktop apps in v1 (protocol is designed for them; clients are not
  scheduled).
- A hosted "official" relay with uptime SLAs — the relay is self-hostable
  open source; operating one is the operator's responsibility (see A38).
