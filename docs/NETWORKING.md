# Aegis Networking — Transport Architecture

> **The network is untrusted and dumb.** All intelligence, all keys, and all
> identity live on devices. The relay is a blind courier: it moves opaque
> bytes between anonymous mailboxes and knows nothing else.

This document is the contract between the Swift transport layer
(`Packages/AegisTransport`), the reference relay (`relay/relay.py`), and the
app. Crypto internals (X3DH, Double Ratchet, Sender Keys) belong to
`Packages/AegisCrypto` and `docs/CRYPTO.md`; this document only describes what
the network sees — which is, by design, almost nothing.

---

## 1. The sealed envelope

The app encrypts with AegisCrypto and hands the transport layer two things:

| Item | Size | Content |
|---|---|---|
| Sealed payload | ≤ 5 MiB | Opaque ciphertext. The transport never inspects it. |
| Mailbox ID | 32 bytes | Anonymous routing label. Not an identity. |
| Envelope ID | 16 bytes | Random nonce. Receivers dedupe on it. |
| TTL | 4 bytes | Seconds the relay may hold it (`0` = relay default). |
| Flags | 1 byte | Bit 0: final chunk · Bit 1: call knock (see §5). |

There is **no sender field anywhere on the wire** — not in the frame, not in
the control channel, not in the relay's memory. Sealed sender is structural,
not a policy: there is simply nowhere to put a sender identity.

Attachments travel as **encrypted chunks**: the app splits files into
≤ 5 MiB sealed frames, sets bit 0 on the final chunk, and the receiver
reassembles by envelope ID order. The relay sees N unrelated envelopes.

## 2. Wire framing (exact)

Binary frames, big-endian, shared verbatim between `AegisFrame.swift` and
`relay.py`'s `HEADER` struct:

```
offset  size  field
0       2     magic "AG" (0x41 0x47)
2       1     version (1)
3       1     flags
4       32    mailbox ID (opaque routing label)
36      16    envelope ID (random nonce)
52      4     ttl_seconds (0 = relay default, clamped to relay max)
56      4     payload length N (≤ 5 MiB)
60      N     payload: opaque ciphertext
```

Header is 60 bytes. Decoders must reject: bad magic/version, truncated
header, `N` larger than the relay maximum, and `total length != 60 + N`
(length mismatch = drop, no error to the network — an untrusted relay must
not be able to probe the parser).

### Control channel (WebSocket text frames, JSON)

Client → relay:

```json
{"op":"auth","token":"…"}          // only if the relay requires it
{"op":"bind","mailbox":"<64 hex>"} // subscribe; relay sends queued, then live
{"op":"unbind","mailbox":"<64 hex>"}
{"op":"ping"}
```

Relay → client:

```json
{"hello":{"v":1,"max_payload":5242880,"ttl_default":604800,"ttl_max":1209600,
           "send_burst":40,"send_rate":8.0,"auth_required":false}}
{"ack":{"id":"<envelope id hex>"}}
{"drained":{"mailbox":"<64 hex>"}}
{"pong":true}
{"error":{"code":"rate_limited|bad_frame|bad_mailbox|unauthorized|unknown_op"}}
```

Binary frames flow both ways: client→relay = store + forward to live
subscribers; relay→client = delivery of queued/live envelopes.

## 3. Mailbox addressing and unlinkability

A mailbox ID is 256 bits of randomness derived **per conversation per epoch**
by the crypto layer (see `docs/CRYPTO.md`). Properties the transport relies on:

- **Unlinkable**: mailbox IDs for the same conversation rotate; the relay
  cannot tell that two mailboxes belong to the same people, or that a
  mailbox seen today relates to one seen last week.
- **Unaddressable by identity**: there is no directory, no username→mailbox
  mapping anywhere on the network. You learn a peer's mailbox only inside an
  already-encrypted conversation (or via LAN discovery of an ephemeral ID).
- **Multi-device friendly**: the relay is a *dead drop* — envelopes stay
  until TTL expiry and any bound connection can collect them. Two devices
  binding the same mailbox both receive everything; clients dedupe by
  envelope ID. No "first consumer wins" semantics.

## 4. Relay semantics (`relay/relay.py`)

- **In-memory only**: `dict[mailbox_hex → deque[(expire_at, raw_frame)]]`.
  Restart wipes everything. This is the headline privacy feature: seizure,
  compromise, or subpoena of a relay yields no history, no roster, nothing.
- **Per-envelope TTL**: default 7 days, max 14 days (operator-tunable).
  A sweeper purges expired envelopes every 60 s.
- **Queue depth**: 1,000 envelopes per mailbox, oldest-drop under flood.
- **Max envelope**: 5 MiB payload (operator-tunable).
- **Rate limiting**: per-connection token bucket (default burst 40, refill
  8/s; binds cost 2). Honest note: reconnecting buys a fresh bucket, so this
  stops accidents and casual abuse, not a determined spammer. Real protection
  is the optional operator token (`AEGIS_TOKEN`) or a closed-group relay.
  Proof-of-work was evaluated and **rejected**: it taxes every iPhone battery
  per message while barely slowing a botnet — duct tape, not security.
- **Metrics** (opt-in): aggregate counters to stdout — envelope count, bytes,
  drops, expiries, live mailbox *count*. Never identifiers, never mailbox IDs.
- **No logs**: there is deliberately no access log, no message log, no
  who-talked-to-whom anywhere. What isn't recorded can't leak.

## 5. Call knocks and rendezvous

Because there is no push infrastructure (§8), calls use **knock + rendezvous**:

1. The caller builds a sealed knock payload with the crypto layer
   (rendezvous token, proposed time, caller proof) and sends it as an
   `AegisFrame` with **bit 1 (`flagKnock`)** set and a short TTL (≤ 300 s).
   The relay forwards it opaquely — it learns only "a knock-sized envelope
   landed in a mailbox now," never who or why.
2. **App open / LAN-nearby**: the callee's `DeliveryCoordinator` sees the
   knock flag immediately, the app decrypts and verifies, and the phone
   rings for real. Knock → ring in ~seconds.
3. **App closed**: the relay holds the knock; the callee's next background
   wake drains it, the coordinator emits `knockReceived`, the app verifies
   and posts a **local** notification: *"Incoming call — tap to join."*
   Tapping opens the app, which joins the rendezvous.
4. **Scheduled calls**: the knock carries a future time; the callee also
   schedules an exact-time local-notification reminder. No server involved.

The knock bit is an **unauthenticated hint**, not a signal: a malicious relay
can set it on any envelope. The app must decrypt and verify through
AegisCrypto before ringing — all a forged bit buys the attacker is one
wasted decrypt. Knock dedupe (by envelope ID) means a knock arriving over
LAN *and* relay rings exactly once.

## 6. Call signaling and media

Signaling (SDP offers/answers, ICE candidates) travels as ordinary sealed
envelopes to the conversation mailbox over whichever transport is up — the
same frames as messages, same TTL rules (short TTLs recommended).

Media is **peer-to-peer via WebRTC/ICE**:

- Candidates: host + srflx (via a public STUN server). No account, no auth.
- If both peers are on the same LAN, host candidates connect directly —
  media never leaves the building.
- **Relay-routed media** (TURN-like dumb UDP forwarder): ONLY if the
  operator explicitly enables it, and the privacy implication is stated
  plainly — a UDP forwarder sees both IP addresses, packet timing, and
  volume. It never sees content (SRTP keys are negotiated inside sealed
  signaling), but it *does* learn that two IPs are talking *now*. Default:
  disabled. Prefer direct P2P; treat relayed media as a fallback with eyes
  open, not as a default.

## 7. LAN transport (MultipeerConnectivity)

BLE + Wi-Fi (AWDL/infrastructure) + Bonjour discovery. Two devices exchange
sealed frames with **zero internet** — no relay, no server, no cell signal.

| Property | Reality |
|---|---|
| Range | ~10 m BLE, ~30–100 m Wi-Fi (environment-dependent) |
| Throughput | Practically 1–5 Mbps; a 5 MiB attachment takes seconds |
| Peer identity | Ephemeral random ID, rotated every `start()`. No stable fingerprint. |
| Invitations | Auto-accepted by design — link-layer auth would imply identities, which Aegis refuses to have. `MCSession` encryption is `.required` as defense-in-depth, but security never depends on it. |
| Background | iOS throttles discovery/advertising within ~30–60 s of backgrounding. LAN is a foreground-first transport. |
| Filtering | Frames broadcast to connected peers; receivers drop anything not bound locally. Nearby attackers can't probe the parser with junk. |

## 8. Free delivery without APNs

**Aegis never registers an APNs device token.** Apple never learns who uses
Aegis, which devices they own, or when their messages arrive. That is a
concrete metadata win over Signal/Telegram/WhatsApp, all of which must tell
Apple "wake this device now" for every message.

The price: iOS will not wake the app on incoming data. The replacement is
three honest tiers, owned by `DeliveryCoordinator`:

### Tier (a) — app open or LAN-nearby: true real-time
WebSocket relay or Multipeer frames arrive in seconds and are delivered
instantly. Calls ring for real. This is the Discord/Telegram experience,
with no push server in the loop.

### Tier (b) — app closed: async store-and-forward
The relay holds sealed envelopes until TTL. iOS wakes the app
**opportunistically**; on each wake the coordinator drains bound mailboxes
and the *app* posts local notifications for anything worth interrupting:

- `BGAppRefreshTask` polling with **adaptive interval** — 5 min while a
  conversation is active (frame arrived < 15 min ago), 30 min while quiet.
  `earliestBeginDate` is a wish, not an appointment: expect minutes-to-an-hour
  cadence, longer in Low Power Mode.
- **Significant-location-change wakes** (opt-in): arriving home, leaving
  work — free, OS-blessed reasons to run. Requires "Always" location
  permission; the app must justify it in Info.plist copy.
- The coordinator schedules the *next* wake **before** draining, so being
  killed mid-drain never breaks the chain.

Per-conversation **delivery mode** (`DeliveryMode`: `live` / `lan` /
`polling` / `offline`) is exposed for the UI — e.g. "Nearby", "Live",
"Checking periodically". The `.lan` refinement is a documented heuristic: it
requires having *heard that mailbox* over LAN recently, not just a
connected session.

### Tier (c) — calls without push: knock + rendezvous (§5)
Sealed knock envelope (short TTL) → background wake → local notification
("tap to join") → rendezvous. On LAN, knocking rings in real time.

### The privacy dividend, stated plainly
No APNs token means no push metadata trail at Apple: no "device X received a
wake at 02:14" records, no token-to-identity mapping, no dependence on
Apple's push infrastructure working — or being compelled. The relay operator
sees timing/size per anonymous mailbox; Apple sees nothing at all.

### Explicitly rejected
- **Silent-audio background keepalive**: App Store rejection risk, battery
  fraud, and a lie about what the app is. No.
- **VoIP push / PushKit**: requires a paid Apple Developer account and an
  APNs token — exactly the dependency and metadata trail this design
  eliminates. No.
- **"Fake push"** (a helper server polling every N seconds in background):
  iOS suspends it; shipping it would be pretending. No.
- **Force-quit caveat**: if the user swipes the app away, iOS delivers no
  background wakes until the next manual launch. The UI must say so.

### Honest latency expectations

| Situation | Texts | Calls |
|---|---|---|
| App open, relay up | seconds | immediate ring |
| App open, LAN-nearby | < 1 s | immediate ring |
| App closed (not force-quit) | minutes (wake cadence) | knock → local notification in minutes; scheduled calls exact via local reminder |
| App force-quit | on next launch | on next launch |
| Both peers closed | async (relay holds to TTL) | knock waits to TTL; schedule ahead |

## 9. Onion transport (seam, not an implementation)

`AnonymityTransport` defines the seam; `UnavailableOnionTransport` is what
ships until a real implementation exists — it fails loudly rather than
pretending. A real implementation embeds Arti (Rust Tor) on-device, routes
the relay WebSocket through per-mailbox circuits (or reaches the relay as an
onion service), and changes nothing else: `AegisFrame` bytes are
transport-agnostic. Documented costs: +1–3 s handshake latency, battery, and
aggressive iOS background throttling. Anonymity is a tradeoff, not a free
upgrade, and the UI must say so when it lands.

## 10. TransportHub: one logical pipe

The hub owns the transports and presents a single pipe to the app:

- **Inbound**: merged stream from all transports, deduplicated by envelope
  ID (a frame arriving over LAN *and* relay is delivered once; 20k-entry
  bounded dedupe ≈ 320 KB).
- **Send policies**: `allConnected` (default — fan out everywhere; sealed
  idempotent envelopes make this safe), `preferLAN` (multi-MB attachments
  when a LAN peer is up), `relayOnly`, `lanOnly` (explicit offline mode).
- **Bind/unbind** fans out to every capable transport.

Fan-out duplicates bandwidth for large attachments — the app should prefer
`.preferLAN` for multi-MB frames when LAN is available. Small envelopes just
go everywhere; delivery odds beat byte-frugalness.

## 11. What each observer sees

| Observer | Content | Sender/recipient identity | Timing/size/count | IP addresses |
|---|---|---|---|---|
| Relay operator | ❌ never (sealed) | ❌ none exists on the wire | ✅ per anonymous mailbox | ✅ of connected clients |
| LAN eavesdropper | ❌ never (sealed) | ❌ | ✅ nearby frames | ✅ local peers |
| Apple (APNs) | — | — | — | **Nothing. No token is ever registered.** |
| UDP media forwarder (if enabled) | ❌ never (SRTP inside sealed signaling) | ❌ | ✅ packet timing/volume | ✅ both endpoints |
| Tor (future) | ❌ | ❌ | ✅ at exit/guard | ❌ hidden by design |

"Knock" and "final chunk" flag bits are visible to the relay — that is
accepted metadata (a knock reveals "someone was invited to a call now," not
who), and the bits are unauthenticated hints the app verifies by decrypting.

## 12. iOS background reality (read before promising anything)

- The WebSocket dies when the app backgrounds. Reconnect is aggressive on
  foreground; the relay's TTL queues mean nothing is lost, only delayed.
- `BGAppRefreshTask` gives ~30 s and an OS-chosen cadence. Budget for one
  relay reconnect + drain inside it.
- Force-quit = no wakes until manual relaunch. Say it in the UI.
- Multipeer in background is throttled within a minute. LAN is foreground.
- Location wakes need "Always" permission and honest Info.plist copy.

## 14. App-layer integration notes

The app's `TransportService` (in `Aegis/`) works in app concepts
(`OutgoingEnvelope` with `conversationID` + `EnvelopeKind`, blobs, calls,
groups). This package works in network concepts (sealed `AegisFrame`s,
mailboxes, transports). The adapter between them lives in the app layer;
the mapping is:

- **Conversation → mailbox**: the crypto layer derives the current 32-byte
  mailbox ID per conversation per epoch. The adapter asks AegisCrypto, seals
  the payload (with `EnvelopeKind` *inside* the sealed payload — the wire
  has no kind field by design), and wraps it in an `AegisFrame`.
- **`sendEnvelope` / typing / read receipts / screenshot notices** → one
  sealed `AegisFrame` each, sent via `TransportHub.send(_:policy:)`.
- **`uploadBlob` / `downloadBlob`** → chunked sealed frames (≤ 5 MiB each,
  bit 0 on the final chunk) over the same transports. Progress =
  chunks-acked / chunks-total. There is deliberately no separate blob server
  — that would be a new metadata/identity surface for no benefit.
- **`placeCall` / signaling** → sealed signaling envelopes to the
  conversation mailbox; the **knock** (`flagKnock`, §5) is the integration
  point for `incomingCallEvents`: app decrypts the knock frame, verifies via
  AegisCrypto, and constructs its `IncomingCall`. Media (WebRTC peer
  connection, SRTP) is app-layer; the transports move the signaling and,
  optionally, relay the UDP (§6).
- **`RelayConfig.Mode`** → hub policy: `automatic` = all transports +
  default relay; `lanOnly` = `.lanOnly` policy, no relay transport;
  `customRelay` = `RelayTransport(url: customRelayURL, pinnedCertificateSHA256:)`.
- **`testRelay(url:)`** → open a `RelayTransport`, wait for `hello`, measure
  handshake latency, `stop()`. Never blocks the UI; never sends identity.
- **Delivery modes** → `DeliveryCoordinator.deliveryMode(for:)` feeds the
  conversation-level indicator; `DeliveryEvent` feeds badges and local
  notifications.

## 15. Three hardest honest limitations

1. **No true background wake without push.** Tier (b) is minutes, not
   seconds, and force-quit kills it entirely. Anyone promising
   push-grade latency without APNs is selling something.
2. **Metadata, not content, is the remaining exposure.** The relay sees
   timing/size/count per anonymous (rotating) mailbox. Padding and rotation
   raise the cost of traffic analysis; they don't eliminate it. Full
   resistance needs the onion transport, which is a seam today, not a
   feature.
3. **Spam prevention without identity is blunt.** Per-connection token
   buckets stop accidents, not adversaries; real gates are the operator
   token or closed-group relays. There is no free, Sybil-proof,
   battery-friendly anti-spam for an anonymous courier — anyone who claims
   otherwise is selling something too.
