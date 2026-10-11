# Aegis — Delivery Roadmap

Phased, honest, and gated on evidence. A phase exits only when its exit
criteria are *demonstrated*, not asserted. Phases overlap in research but not
in "done" claims.

**Status snapshot — October 2026 (parity grind).** Six workstreams landed:
messaging richness (A8–A12, A15 shipped), voice-rooms-plus (room video,
speaking indicators, stage mode, per-user mute, 1:1 screen sharing incl.
ReplayKit broadcast extension), multidevice-v2 (attachments + voice notes
over the paired relay), permissions-moderation (granular permissions, slow
mode, requests inbox, block/report, signed audit log), polish-hig (HIG/
accessibility sweep), first-launch-fix (simulator keychain fallback + launch
smoke CI). Remaining gaps are listed under each phase below and in
`docs/FEATURES.md`'s implementation-status section.

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
**Status (Oct 2026): substantially complete.** Shipped: E2EE 1:1 messaging
(A1) · sealed sender (A6, default-on) · offline-first outbox (A7) · replies
(A8) · contact verification / safety numbers (A30) · message requests
(A31) · encrypted local store via AegisStore/SQLCipher (A47) · biometric
app lock (A34) · QR contact add (subset of A32) · identity-change detection
with blocking warnings. Partial: LAN-only mode (policy enum exists,
enforcement unverified). Decoy vault remains Phase 4.
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
**Status (Oct 2026): substantially complete.** Shipped: E2EE groups (A2) ·
broadcast + announcement channels (A3, A4) · threads (A9) · reactions
+ custom emoji packs (A10) · polls (A12: single/multi-choice, anonymous,
timed close, quorum) · edit/delete + signed tombstones (A11) ·
disappearing messages (A5: 10s…7d + after-read, tombstone propagation) ·
read receipts / typing toggles (A13) · starred/pinned (A15) · chunked
encrypted attachments (A18) · voice notes (A19, AAC — on-device
transcription not yet implemented) · QR invites (A32, revocation
generations) · roles & permissions (A36: 9 granular permissions,
client-enforced) · slow mode (A37) · message-requests inbox (A31) ·
local signed admin audit log (A43). **Not yet built:** scheduled messages
(A14) · encrypted chat export (A16) · on-device link previews (A17) ·
nearby BLE discovery (A33) · relay canary (A38) · global on-device search
(A48).
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
**Status (Oct 2026): substantially complete.** Shipped: E2EE voice (A20) +
video calls (A21, DTLS-SRTP, 1:1 SAS ceremony) · group voice rooms (A23:
audio + video, speaking indicators from `audioLevel` stats, stage vs
open-floor modes, per-user *mute* — continuous per-user volume is
infeasible with stock WebRTC, documented limitation) · screen sharing in
1:1 calls, view-only (A22: in-app + full-device via ReplayKit broadcast
upload extension) · call-history records in the store. The spec's
room-bound text sidecar is not yet built. **Not yet built:**
push-to-talk (A24) · live captions (A25) · local call recording with
consent signaling (A26) · noise suppression (A27) · bandwidth-adaptive
Opus (A28).
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
- Battery during long voice rooms. *Mitigation:* suspended video when
  backgrounded; measured, not assumed. (Adaptive Opus — A28 — is not
  implemented; WebRTC's built-in codec behavior applies.)

## Phase 4 — Multi-device and beyond-parity
**Status (Oct 2026): partially complete.** Shipped: multi-device linking
(A29: QR + 44-bit SAS paired relay; text relay working; attachments +
voice notes now sync via `DeviceLinkBlobRelay` — 32 KiB chunked,
manifest sealed in paired envelope, resume across reconnects; primary
must be reachable, text-first architecture) · local signed admin audit
log (A43) · screenshot alerts + app-switcher shield (A35) · biometric
app lock (A34) · HIG/accessibility sweep · launch smoke CI. **Not yet
built:** duress PIN / decoy vault (A34) · relay canary (A38) ·
per-message forward-secrecy re-key (A39) · compromise-recovery ceremony
(A40) · ghost mode (A41) · vault chats (A42) · briefing channels (A44) ·
backup UI (A46: Argon2id key backup exists at crypto layer only) ·
screen-*recording* detection (screenshot detection shipped; recording
detection unverified).
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
- **Bots**: a bot needs message content, and anything that reads group
  content must hold the group keys — that breaks the "no silent
  participant" guarantee. A bot-safe variant needs per-message capability
  grants (wire-format work), not a bolt-on.
- **Per-device sender keys**: needs a wire-format revision — future work,
  not v1.
- **Continuous per-user voice-room volume**: infeasible with stock WebRTC
  (verified against the pinned M154 headers — no `RTCAudioSink`, no
  per-track gain API). Per-user *mute* (`RTCAudioTrack.isEnabled`) is the
  per-user control the platform supports; a volume slider would be a fake
  control.
- The ReplayKit broadcast upload extension cannot be installed on the iOS
  simulator (platform limitation, verified); it ships on device builds.
