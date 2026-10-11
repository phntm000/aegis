# Aegis — Master Feature Specification

**Status:** Living spec. Every feature below is specified to implementation-ready
detail: behavior, enterprise rationale, and honest privacy/security implications.
Cryptographic mechanics live in `docs/CRYPTO.md`; the adversary model lives in
`docs/THREAT_MODEL.md`. This document covers *product* behavior.

**Design principles (non-negotiable):**
1. **Account-less.** No phone numbers, no email, no usernames registered on any
   server. Identity is a locally-generated keypair. The relay never learns who
   you are.
2. **The relay is dumb.** It stores opaque sealed envelopes with a short TTL and
   forwards them. It cannot read content, sender, or (with sealed sender)
   recipient metadata beyond what the network layer inherently reveals.
3. **Offline-first.** Every feature works against the encrypted local store
   first; the network is a sync layer, not a dependency.
4. **Client-side trust.** Moderation, audit, verification, and abuse handling
   happen on-device, because a server that can moderate can surveil.

**Feature count: 48.** Sections: Core messaging (17) · Media & calls (11) ·
Trust, safety & network (20, incl. 5 beyond-parity).

---

## A. Core messaging

### A1. End-to-end encrypted 1:1 messaging
**What.** Text messaging between two identities, encrypted with the Double
Ratchet (X3DH handshake, per-message forward secrecy and future secrecy).
Messages are sealed envelopes; only the two endpoints hold keys.
**Why it matters.** This is the baseline every serious messenger must clear.
Enterprises handling legal, medical, or financial discussion need a guarantee
stronger than "TLS to our servers" — they need the operator to be
mathematically unable to read content.
**Privacy & security.** Content is unreadable to the relay, the network, and
Apple. Metadata is minimized via sealed sender (A6): the relay sees two
pseudonymous mailboxes exchanging fixed-size padded envelopes. Honest caveat:
network-level timing and volume correlation remains possible against a
global passive adversary; Aegis does not claim to defeat traffic analysis.

### A2. End-to-end encrypted group chats
**What.** Groups of up to 1,000 members with E2EE via per-group symmetric group
key distributed through pairwise ratchet channels (sender-keys style). Adding or
removing a member rotates the group key; removed members cannot read new
messages, new members cannot read history (configurable).
**Why it matters.** Enterprise work happens in groups — deal teams, incident
response, board comms. Discord/Telegram groups are either plaintext to the
operator (Telegram groups) or limited in size/fidelity.
**Privacy & security.** Group membership lists are visible to members but never
to the relay in plaintext; invites carry only opaque tokens. Removing a member
provides *forward* secrecy for future messages only — it cannot un-read what
they already received. The UI must say this plainly at removal time.

### A3. Broadcast channels
**What.** One-to-many channels where only admins post and subscribers read
(Telegram-style). Subscriber lists are hidden from other subscribers; posting
is signed by the admin's identity key so impersonation is impossible.
**Why it matters.** Company announcements, investor updates, and customer
broadcasts need a channel where the audience can't reply-all and can't see
each other — critical for confidential distributions.
**Privacy & security.** The relay learns approximate subscriber counts (it must
fan out envelopes) but never subscriber identities when sealed sender is on.
Admins see per-message delivery counts, not who-read-what, unless a subscriber
opts into read receipts.

### A4. Announcement channels with discussion threads
**What.** A broadcast channel (A3) where each announcement can spawn an
opt-in threaded discussion visible only to members who join the thread.
**Why it matters.** Enterprises need announcements that don't become 400-message
noise, while still allowing focused Q&A. Discord's announcement channels lack
E2EE; this is both encrypted and quieter.
**Privacy & security.** Thread membership is a subset of channel membership;
joining a thread reveals your participation only to thread members and (as
with all groups) to no one on the relay.

### A5. Disappearing messages (per-chat timers)
**What.** Per-conversation timer (10s … 7 days, plus "after read"). Expired
messages are cryptographically wiped from the local SQLCipher store
(`expungeDisappeared`), their attachment chunks deleted, and a tombstone
propagates to all devices and participants.
**Why it matters.** Data-retention policies (GDPR, FINRA, legal hold windows)
require messages to *actually* die on schedule, not just hide in the UI.
**Privacy & security.** Deletion is best-effort against a malicious
participant who screenshots or photographs the screen (see A35 for detection,
not prevention — prevention is impossible). Tombstones are signed so a peer
cannot forge deletions of messages they didn't send. The relay cannot retain
expired content: envelopes carry TTLs and are purged.

### A6. Sealed sender
**What.** Message envelopes hide the sender's identity from the relay using
the Signal sealed-sender construction: the sender certificate is encrypted to
the recipient, and the relay routes on an unlinkable routing token.
**Why it matters.** "Who talks to whom, when" is the metadata intelligence
agencies and data brokers actually want. Enterprises under NDA or in
competitive situations need relationship graphs to stay private.
**Privacy & security.** The relay learns that *some* envelope moved between
two mailboxes, not whose. Trade-off, stated honestly: sealed sender makes
server-side spam/abuse filtering impossible, so abuse handling moves
client-side (message requests A31, blocklists, per-chat slow mode A37).
Sealed sender is default-on; turning it off is a per-chat, explicitly
confirmed choice.

### A7. Offline-first queueing
**What.** Every send is a durable outbox row in the encrypted store first.
The transport drains the outbox when connectivity returns — relay, LAN, or
both — with per-message retry, ordering per conversation, and idempotent
delivery (duplicate envelopes are deduped by message ID).
**Why it matters.** Field teams, travelers, and anyone on bad networks need
"it sent" to mean "it's queued and will send," not "it vanished." Enterprise
reliability starts with the outbox, not the socket.
**Privacy & security.** Queued plaintext lives only in the encrypted local DB
(SQLCipher, device-locked key). No plaintext ever touches the network; queued
items are sealed at enqueue time, so a stolen unlocked device is the only
exposure window — mitigated by app lock (A34).

### A8. Replies (quoted context)
**What.** Reply to any message with quoted context; the quote is a snapshot
(at reply time) plus a live pointer. If the original is edited, the quote
shows both versions.
**Why it matters.** Table-stakes for coherent discussion in busy groups; legal
and compliance review depends on knowing exactly what was being answered.
**Privacy & security.** Quotes duplicate content — if the original message
disappears (A5), the quote in a reply survives unless the reply also expires.
The UI warns when quoting a disappearing message. Quote snapshots inherit the
original's expiry timer.

### A9. Threads
**What.** Side conversations anchored to a message, collapsible, with their own
read state, reply chains, and notification settings. Threads are first-class:
they have IDs, can be linked, and appear in search.
**Why it matters.** Incident channels and deal rooms stay navigable when
sub-discussions don't interleave with the main feed. This is Discord/Slack
parity, encrypted.
**Privacy & security.** Thread read state never leaves the device. Thread
participation is visible to thread members only.

### A10. Reactions (emoji, custom)
**What.** React to messages with emoji or org-uploaded custom emoji packs.
Reactions are signed events tied to message IDs; anyone can add/remove their
own; counts are computed client-side.
**Why it matters.** Lightweight acknowledgment ("👍 seen, approved") replaces
messages in enterprise workflows — approvals, standups, incident acks.
**Privacy & security.** Reaction events are sealed like messages. Custom emoji
packs are fetched as encrypted attachments; a malicious pack can't execute
code (rendered as images only, no SVG/scripts).

### A11. Edit & delete with signed tombstones
**What.** Edit within a configurable window (default 48h, admin-settable);
edits bump a version counter and keep a local version history. Deletes issue
signed tombstones that propagate to all participants and devices; tombstones
replace content but preserve the message's position and metadata shell.
**Why it matters.** Typos in contracts, wrong figures in financials —
enterprises need correction with an audit trail, not silent rewriting.
**Privacy & security.** Only the author (or a group admin, where policy
allows) can tombstone; tombstones are signed, preventing forged deletions.
Version history is local-only and never re-shared — editing doesn't leak the
original to new members. Honest caveat: you cannot delete from someone else's
screenshot or export.

### A12. Polls (including anonymous & quorum)
**What.** Native polls: single/multi-choice, anonymous mode, timed close,
quorum thresholds, and signed ballots. Results are computed client-side from
sealed ballot events; anonymous polls use a per-poll blinding so the tally is
verifiable without revealing who voted what.
**Why it matters.** Board votes, team decisions, incident "are we rolling
back?" calls need a trustworthy in-chat mechanism, not a link to SurveyMonkey
that leaks the question to a third party.
**Privacy & security.** Non-anonymous polls record voter identity to members
only. Anonymous polls hide voter→choice mapping from everyone including
admins, but the *set* of voters is visible (so ballot-stuffing is detectable).
Ballots are sealed envelopes; the relay learns nothing about the question.

### A13. Read receipts & typing indicators (per-chat privacy toggles)
**What.** Per-conversation toggles for read receipts and typing indicators,
defaulting to on for 1:1, off for large groups. "Ghost mode" (A46) can
suppress them globally.
**Why it matters.** Enterprises are split: sales wants receipts, legal wants
none. Per-chat control beats a global switch.
**Privacy & security.** Receipts and typing events are sealed control frames,
never logged by the relay. Turning them off is enforced client-side on both
ends — your client simply doesn't emit them, and honest clients don't display
them. A malicious modified client could ignore your preference; the spec
states this rather than promising the impossible.

### A14. Scheduled messages (device-side)
**What.** Compose now, deliver at a chosen time. Scheduling is computed and
stored on-device; the app wakes (background task / push-less local
notification) to seal and send at fire time.
**Why it matters.** Cross-timezone teams, embargoed announcements, "send the
status update at 9am Monday."
**Privacy & security.** The relay never sees scheduled content in advance —
there is nothing to leak, subpoena, or prematurely deliver. If the device is
off at fire time, delivery slips to next unlock; the UI shows this honestly
instead of pretending server-side scheduling.

### A15. Starred & pinned messages
**What.** Star messages privately (your view only); pin messages per
conversation (visible to members, admin-controlled who can pin). Pins have
optional expiry.
**Why it matters.** Decisions, links, and action items get lost in scroll.
Pins are the shared memory of a channel.
**Privacy & security.** Stars are local-only metadata, never synced. Pins are
shared state signed by the pinner; pinning a disappearing message is blocked
with an explanation.

### A16. Encrypted chat export
**What.** Export any conversation (or everything) to an encrypted archive:
AES-256-GCM with a user-supplied passphrase (Argon2id KDF), containing
messages, attachments, and a manifest. Import restores into the local store.
**Why it matters.** Legal hold, e-discovery response, personal backup, and
org offboarding all require portable records that stay encrypted in transit.
**Privacy & security.** Export is passphrase-encrypted before it touches the
filesystem; the app never writes a plaintext export. Exporting a group chat
requires admin approval per org policy (configurable); every export is written
to the local admin audit log (A43).

### A17. Link previews fetched on-device
**What.** When a message contains a URL, the *recipient's device* fetches the
preview (title, image, description) directly — never a central preview server.
Fetch happens only on Wi-Fi by default, only for senders you haven't blocked,
and never with cookies or credentials.
**Why it matters.** Telegram/WhatsApp-style server-side preview fetching tells
the operator every link anyone shares. On-device fetching keeps browsing
behavior off the relay entirely.
**Privacy & security.** The fetch reveals your IP to the target site (same as
opening the link). To blunt this, previews route through the relay as an
anonymized fetch proxy *only if the user enables it*, and the relay is
architecturally unable to correlate the fetch with the message. Default: direct
fetch, with a per-chat toggle to disable previews entirely.

---

## B. Media & calls

### A18. Attachment encryption with chunked upload/download + resume
**What.** Files up to 2 GB are encrypted client-side (per-attachment random
key, AES-256-GCM), split into 256 KB chunks, uploaded to relay blob storage
or any S3-compatible endpoint the user configures. Downloads resume across
app restarts; integrity is verified per-chunk (hash tree) and whole-file
(SHA-256 in the manifest).
**Why it matters.** Enterprises move contracts, scans, datasets, and builds.
Chunked resume is the difference between "sent" and "actually arrived" on
real networks; 2 GB covers video walkthroughs and disk images.
**Privacy & security.** The storage endpoint sees only ciphertext chunks and
opaque locators — it cannot learn filenames, types, or sizes beyond chunk
counts (padded to reduce size leakage). Attachment keys travel inside the
sealed message envelope, never alongside the chunks. Pause/cancel wipes
partial chunks from the store.

### A19. Voice notes with on-device transcription
**What.** Hold-to-record voice notes (Opus, variable bitrate), with optional
transcription done entirely on-device via Apple's Speech framework in
on-device mode. Transcripts are stored alongside the note and are searchable.
**Why it matters.** Voice is faster than typing for field reports and
incident narration; transcripts make them skimmable and searchable without
sending audio to a transcription vendor.
**Privacy & security.** Audio never leaves the device except as a sealed
attachment to the intended recipients. Transcription runs with no network
entitlement — verify this in code review, because one misconfigured
`SFSpeechRecognizer` defaults to server-based recognition. Transcripts inherit
the message's disappearing timer.

### A20. End-to-end encrypted 1:1 voice calls
**What.** Voice calls with DTLS-SRTP media, keys negotiated through the
existing ratchet channel (no separate PKI, no certificates to manage).
Opus codec, echo cancellation, automatic gain.
**Why it matters.** Encrypted messaging without encrypted calling is half a
product. Keying calls off the messaging identity means no new trust ceremony.
**Privacy & security.** The relay (or any TURN-like forwarder the user
configures) sees only SRTP ciphertext; it cannot decrypt or transcribe.
Signaling messages are sealed envelopes. IP addresses are inherently exposed
to the call peer in P2P mode — the UI discloses this before the first call,
and a "relay media" toggle routes through the forwarder to hide IPs at the
cost of trusting the forwarder with traffic metadata (never content).

### A21. End-to-end encrypted 1:1 video calls
**What.** Video calls with the same DTLS-SRTP keying as A20, H.264/VP8 with
simulcast, camera/mic toggles, background blur done on-device.
**Why it matters.** Face-to-face for remote teams, client calls, and
telemedicine-adjacent use — without Zoom's cloud seeing the stream.
**Privacy & security.** Same guarantees as A20. Background blur/replacement
runs on-device (no frame leaves unencrypted). Screen sharing during a video
call (A22) re-keys the video stream so a compromised share can't leak camera
frames.

### A22. Screen sharing in calls
**What.** Share a screen, window, or app region during any call, with
remote-control explicitly *not* offered (view-only by design). The sharer can
pause, annotate locally, and redact regions.
**Why it matters.** Demos, pair debugging, document review — the core of
remote enterprise collaboration.
**Privacy & security.** View-only is a deliberate security choice: remote
control is the top vector for social-engineering takeovers. Shared frames are
SRTP-encrypted like call media. The OS-level "X is sharing your screen"
indicator is always honored; Aegis never suppresses it. Redaction regions are
applied before encoding, on-device.

### A23. Group voice rooms (Discord-style)
**What.** Persistent voice rooms inside a group or channel: drop in/out
without ringing anyone, see who's speaking, stage vs. open-floor modes,
per-user mute, mute/deafen, and a text sidecar bound to the room.
**Limitation.** Continuous per-user volume is not offered: the stock
WebRTC iOS SDK (verified against the pinned M154 headers) exposes no
per-track audio tap or gain API, so a volume slider would be a fake
control. Per-user mute (local-only, never signaled) is the per-user
control that the platform actually supports.
**Why it matters.** This is the Discord feature enterprises actually miss in
secure messengers: the always-open "office" room, the incident bridge, the
team hangout.
**Why it matters (cont.).** Text sidecar messages are sealed to room
participants; speaking indicators are local-only.
**Privacy & security.** Each room epoch has a fresh SRTP master key
distributed over pairwise ratchets; join/leave triggers re-key so a departed
member can't listen in (forward secrecy for membership changes). The relay
forwards SRTP packets blindly. Speaking volume levels are computed locally
and never transmitted as anything but anonymous energy hints — no voice
biometrics leave the device.

### A24. Push-to-talk (PTT)
**What.** Hold a key/button to transmit in voice rooms; configurable
voice-activity vs. PTT per room; priority speaker channel for incident
commanders.
**Why it matters.** Open mics in 40-person incident bridges are chaos. PTT is
how dispatch, field ops, and event crews actually work.
**Privacy & security.** PTT state is local; the only network signal is SRTP
packets flowing or not. No "is holding the button" presence leaks.

### A25. Live captions on-device
**What.** Real-time speech-to-text captions during calls and voice rooms,
rendered locally using on-device speech recognition. Optional per-participant
caption pane; captions can be saved to the local call notes with consent.
**Why it matters.** Accessibility (deaf/hard-of-hearing participants),
noisy environments, and non-native speakers. Enterprise accessibility
compliance (ADA/EAA) increasingly requires it.
**Privacy & security.** Recognition is on-device-only — captions are derived
from decrypted audio in memory and are never sent anywhere. Saving captions
requires the same consent signaling as call recording (A26); all parties see
an indicator while caption-saving is active.

### A26. Call recording stored locally with consent signaling
**What.** Record any call to the *local* encrypted store (never to a server).
Starting a recording emits a signed consent-request to all participants; the
recording begins only when every participant's client acknowledges (or after
a configurable timeout with explicit on-screen warning that consent is
pending). A persistent in-call indicator shows while recording.
**Why it matters.** Regulated industries (finance, legal) must record certain
calls; doing it locally with cryptographic consent beats cloud recording that
hands the audio to a vendor.
**Privacy & security.** Recordings are encrypted at rest in SQLCipher-managed
storage. Consent acknowledgments are signed — the audit log (A43) can prove
who consented, when. A malicious modified client could record without
signaling; the spec is honest that consent signaling deters and detects
(indicators, logs) but cannot physically prevent a determined endpoint
attacker. One-party vs. all-party consent law varies by jurisdiction — the app
shows the applicable rule based on participants' declared regions and
defaults to the strictest.

### A27. Noise suppression (on-device)
**What.** RNNoise-class neural noise suppression applied to the mic path
before encoding, with a per-call toggle and a "studio" preset for music.
**Why it matters.** Calls from airports, factories, and open offices stay
intelligible — the unglamorous feature that decides whether people actually
use the product.
**Privacy & security.** Purely local DSP on the raw mic stream; no audio is
sent anywhere for "enhancement." The model runs in the app sandbox.

### A28. Bandwidth-adaptive Opus
**What.** The Opus encoder continuously adapts bitrate (6–128 kbps), frame
size, and FEC based on measured loss/jitter, with graceful degradation to
narrowband before dropping. Exposed as a live "connection health" readout.
**Why it matters.** Calls must survive hotel Wi-Fi and rural LTE. Adaptive
codec behavior is what separates "works in the lab" from "works on the road."
**Privacy & security.** Adaptation decisions use only locally-measured
network statistics; no telemetry leaves the device. The health readout shows
what the app measured — useful for debugging without phoning home.

---

## C. Trust, safety & network

### A29. Multi-device linking (companion devices via QR, paired-relay model)
**What.** Link iPads/other iPhones as companion devices by scanning a QR code
on the primary. The companion holds **no** identity keys — it pairs over an
E2EE channel (X25519 ephemeral-ephemeral ECDH + 4-word SAS ceremony) and
thereafter relays all traffic through the primary, which performs all
cryptographic operations (WhatsApp-Web-style). Message history syncs
device-to-device over the AES-GCM paired channel.
**Media sync.** Attachments and voice notes now sync to linked devices too:
the primary offers each blob over the paired channel (manifest + file key
sealed in the paired envelope) and streams the AttachmentCrypto ciphertext
in 32 KiB indexed chunks on request; the linked device reassembles,
SHA-256-verifies, and decrypts locally, with progress / retry / resume
across reconnects in the thread UI and outbound progress in Settings →
Linked devices. Voice-note transcripts ride along in the manifest when the
primary has one. Linked → primary media sending stays unavailable in v1
(text only); the composer hides those affordances on linked devices.
**Why it matters.** People work across phone, tablet, and desktop-class
devices. Single-device messengers lose to incumbents on this alone.
**Privacy & security.** No cloud holds your keys — linking is a local QR
ceremony. Contacts see exactly one identity; there is no "ghost device."
The paired channel uses a static, never-rotating key in the OS Keychain:
it has no forward secrecy, so a seized channel key decrypts captured
sync traffic (see CRYPTO.md §17 and THREAT_MODEL.md §4.11). Unpairing
wipes the channel keys on both sides (dedicated confirmation UI) but
cannot remotely wipe content already synced — treat an unpair like a
device you no longer control. Honest caveat: multi-device multiplies
the endpoint-attack surface; the device list screen exists so users
can audit it.
**Design note.** An earlier revision of this spec described per-device
identity keypairs with primary-signed device certificates, per-device
ratchet state, and revocation-triggered group-key rotation. The shipped
implementation uses the simpler paired-relay model above; the
per-device-keys design remains a possible future direction, not the
current behavior.

### A30. Contact verification (safety numbers)
**What.** Every contact has a safety number — a fingerprint of both identity
keys. Verify in person (QR scan), by voice (read the words), or via a
numeric comparison. Verification state is per-device and shown as a persistent
badge; key changes trigger a prominent "safety number changed" warning and
pause sealed-sender until re-verified (configurable).
**Why it matters.** E2EE is worthless if you're ratcheting with an impostor.
Safety numbers are the anti-MITM ceremony; enterprises need it to be visible
and habitual, not buried.
**Privacy & security.** Fingerprints are computed locally from public keys —
nothing to intercept. The warning-on-change behavior is the real defense
against relay-assisted key substitution. Verification events are local-only;
no server attests to your relationships.

### A31. Message requests from unknown contacts
**What.** Messages from identities you haven't contacted arrive in a Requests
inbox: you see the message (sealed to you, relay can't read it) but the
sender doesn't get read receipts, typing indicators, or your online status
until you accept. One-tap accept/block/report.
**Why it matters.** Account-less systems can't rely on phone-number reputation
or server-side spam filters. The requests inbox is the client-side spam
boundary — and it's also how legitimate first contact happens (recruiters,
clients, new hires).
**Privacy & security.** Accepting reveals nothing beyond what you then choose
to share; blocking is local and silent (the blocker never learns they were
blocked — no "blocked" signal is emitted, to avoid confirming an active
mailbox). Reports are local heuristics only; there is no central abuse desk
to send them to, by design.

### A32. QR invite links with expiry
**What.** Invite someone to a chat, group, or channel via QR code or link
containing a single-use (or N-use, or time-boxed) invite token. Invites can
require admin approval, carry an expiry (1h … 30 days), and be revoked.
**Why it matters.** Onboarding teams, clients, and event attendees without
friction — and without a permanent join link floating around the internet.
**Privacy & security.** Invite tokens are random 256-bit values; the relay
stores only their hashes until redeemed. Revocation is a signed group event.
Expired tokens are purged. A leaked invite lets the holder *request* to join
— with approval-required groups they still can't enter unvetted.

### A33. Nearby contact discovery (BLE)
**What.** Discover nearby Aegis users over Bluetooth Low Energy: both devices
broadcast rotating ephemeral identifiers (derived from identity keys, rotated
every 15 minutes); mutual opt-in reveals identities and opens a verified
chat without either party typing anything.
**Why it matters.** Conferences, offices, and field ops need "add the person
next to me" without exchanging phone numbers or usernames — and without a
central directory to query.
**Privacy & security.** Ephemeral IDs are unlinkable across rotations to a
passive observer; only someone who completes the mutual handshake learns your
identity key. Broadcast is off by default and auto-disables after the
handshake or a timeout. This is strictly better than "find friends via
contacts upload" (which hands your address book to a server).

### A34. Biometric app lock + duress PIN (decoy vault)
**What.** Face ID / Touch ID / passcode lock with configurable auto-lock
(immediately … 1 hour). A separate **duress PIN** opens a fully functional
**decoy vault**: real-looking chats, contacts, and history — a second,
independent encrypted database — while the true database stays locked and
undisturbed.
**Why it matters.** Border crossings, device seizure, and coercion scenarios
are real for journalists, executives, and anyone traveling with sensitive
discussions. A lock screen that just says "no" invites escalation; a plausible
decoy de-escalates.
**Privacy & security.** The decoy is a genuinely separate SQLCipher database
with its own key in the Keychain; entering the duress PIN never touches the
real DB file. Honest caveats, stated in-app: (1) a forensic examiner who
images the device may find two database files and draw conclusions — the
decoy buys time and deniability against casual inspection, not a lab;
(2) the decoy must be *maintained* (seeded with plausible activity) or it
looks staged — the app offers an optional "decoy upkeep" that synthesizes
realistic-looking local activity. Duress PIN entry is itself logged nowhere.

### A35. Screenshot detection alerts
**What.** When a participant screenshots (or screen-records) a chat, other
participants receive a signed "screenshot taken" event naming the chat and
timestamp. Works via iOS screenshot notifications; screen *recording* is
detected while active.
**Why it matters.** Social deterrence. In confidential deal or HR discussions,
knowing that capture is *announced* changes behavior — it's the digital
equivalent of "this meeting is on the record."
**Privacy & security.** Detection is best-effort and the UI says so: it cannot
catch a second phone photographing the screen, a modified client, or (on
some iOS versions) capture via accessibility APIs. It is a deterrent and an
audit signal (feeds A43), not a prevention mechanism. No screenshot *content*
is ever transmitted.

### A36. Roles & permissions
**What.** Per-group role system: Owner, Admin, Moderator, Member, Guest.
Granular permissions: post, invite, pin, manage threads, start voice rooms,
record calls, add/remove members, edit group info, approve join requests.
Role changes are signed events in the group log.
**Why it matters.** A 500-person company channel needs actual governance:
who can announce, who can invite clients, who can remove a departing
employee *right now*.
**Privacy & security.** The permission model is enforced by every honest
client from the signed group log — there is no server to appeal to, so the
log *is* the authority. A malicious client can ignore permissions locally,
but cannot forge another member's signature to escalate itself; other honest
clients will reject its unauthorized actions as invalid events.

### A37. Slow mode
**What.** Per-channel rate limit (5s … 6h between messages per member),
settable by admins, with exemptions for roles.
**Why it matters.** Announcement channels and large groups stay readable
during incidents and launches; it's the standard Discord moderation tool,
encrypted.
**Privacy & security.** Enforced client-side from the shared group state;
attempts to bypass are visible as invalid events to honest clients. No
server-side throttling metadata is generated.

### A38. Relay operator transparency (signed canary/status doc)
**What.** Every relay publishes a signed status document: operator identity,
software version, uptime, envelope TTL policy, abuse-contact, and a
**warrant canary** statement, refreshed at least weekly and signed by the
operator's long-term key. Clients fetch it, verify the signature, and surface
stale/missing canaries as a warning badge on the relay indicator.
**Why it matters.** "Trust us, we're dumb" isn't enough — operators should be
accountable *about* being dumb. Enterprises choosing a relay (self-hosted or
third-party) need verifiable claims about retention and jurisdiction.
**Privacy & security.** The canary attests to *operator behavior* (no secret
orders received, no logging enabled), which is inherently unverifiable by
clients — the spec is explicit that this is a tripwire, not a proof. What it
*does* prove: the relay binary's claimed version and config, which users can
cross-check against the open-source release. Self-hosted relays let an org
sign its own canary.

### A39. Per-message forward-secrecy re-key ★ beyond parity
**What.** Beyond the standard Double Ratchet, Aegis performs an additional
ephemeral DH re-key on a configurable cadence (every N messages or T minutes,
default 100 / 24h) *within* long-lived conversations, and exposes a "re-key
now" control. Each re-key erases the previous chain keys from memory
(`sodium_memzero`-equivalent) and logs the epoch in the audit trail.
**Why it matters.** Standard ratchets already give forward secrecy, but
long-lived groups and devices with big memory footprints benefit from
explicit, auditable, user-visible re-keying — especially for conversations
under legal hold where "when did keys rotate" is a compliance question.
**Privacy & security.** Compromise of a device yields strictly less history
than with ratchet-only rotation, because chain keys are actively destroyed on
schedule rather than merely superseded. The trade-off is a small CPU/battery
cost per re-key (one X25519 op per participant) — measured, not hand-waved,
in the perf budget (see ROADMAP).

### A40. Compromise-recovery re-verification ceremony ★ beyond parity
**What.** If a device is lost, stolen, or suspected compromised: one tap
starts a guided recovery — revoke the device's keys (A29), rotate all group
keys you're part of, notify contacts with signed "key reset" events, and walk
you through re-verifying safety numbers (A30) with your most frequent
contacts. A recovery checklist tracks completion per conversation.
**Why it matters.** Every messenger tells you what to do *before* compromise.
Nobody designs the *morning after*. Enterprises need a runbook, not a FAQ —
this is the runbook, built into the product.
**Privacy & security.** Revocation and rotation are the actual security
mechanisms; the ceremony exists to make sure they *happen completely* instead
of halfway. Recovery events are signed by your remaining trusted device so
contacts can distinguish legitimate recovery from an attacker's key swap —
the exact attack this ceremony is designed to make visible.

### A41. Metadata-minimal "ghost mode" presence ★ beyond parity
**What.** A global presence setting with three levels: **Normal** (online
status, last-seen, typing, receipts per chat settings), **Quiet** (no
last-seen, no typing, receipts off), **Ghost** (additionally: randomized
dummy envelope traffic at low rate, no online indicator ever, fetches on a
jittered schedule so real activity hides in cover traffic).
**Why it matters.** Presence metadata — when you're awake, active, typing —
is surveillance-grade behavioral data. Executives, journalists, and anyone
under targeted attention need a credible way to go dark without going silent.
**Privacy & security.** Ghost mode trades battery and bandwidth for
unlinkability: dummy traffic is indistinguishable from real sealed envelopes
to the relay (same size distribution, same cadence jitter). Honest caveat:
cover traffic defends against a relay-level observer, not a global passive
adversary correlating across the whole network — the UI explains the
difference in one sentence at enable time.

### A42. Local-only "vault chats" ★ beyond parity
**What.** A conversation type that *never touches any relay or network at
all*. Messages live only in the local encrypted store. To share a vault chat
with another device, you physically export an encrypted vault file (QR
sequence or AirDrop-style local transfer) and import it on the other device.
**Why it matters.** Some discussions — M&A terms, whistleblower intake,
personal journals — are safest when they never traverse infrastructure you
don't physically control. Vault chats are the "air-gapped notebook" inside a
modern messenger.
**Privacy & security.** The attack surface collapses to the device itself:
no relay, no push, no sync, no metadata whatsoever. Multi-device for vault
chats is deliberately manual (sneakernet) — convenience is traded for the
guarantee. The UI marks vault chats with a persistent distinct treatment so
they're never confused with synced chats.

### A43. Admin audit log (local, signed) 
**What.** Every administrative action — member add/remove, role change,
permission edit, invite issued/revoked, export performed, recording consent,
recovery events — is appended to a per-group, hash-chained, signed audit
log stored on each member's device. Anyone can verify the chain; gaps are
detectable.
**Why it matters.** SOC 2, ISO 27001, and internal investigations need to
answer "who did what, when." Centralized audit logs are a surveillance
treasure chest; a replicated, signed, client-verified log gives the
accountability without the honeypot.
**Privacy & security.** The log contains administrative events only — never
message content. It replicates to members only (sealed), never to the relay
in plaintext. Exporting the audit log requires admin role and is itself
logged (turtles, but honest, all the way down).

### A44. Scheduled disappearing "briefing" channels ★ beyond parity
**What.** Channels with a lifecycle: they open at a scheduled time, accept
messages for a window (e.g., the 30-minute pre-market briefing), then
auto-expire — all messages cryptographically wiped on every device at close,
leaving only the signed attendance/audit record.
**Why it matters.** Earnings calls, incident standups, board pre-reads:
information with a natural half-life shouldn't live forever in scrollback.
Telegram/Discord make you delete by hand (or not at all); briefings make
ephemerality the default for time-boxed collaboration.
**Privacy & security.** Expiry is enforced by all honest clients from the
channel's signed schedule; the relay's envelope TTLs are set to match so
late-joining devices can't recover content. As with A5, a participant can
still photograph the screen — briefings raise the cost of retention, they
don't make retention impossible.

### A45. LAN-only mode
**What.** A per-conversation (or global) network policy: messages sync only
over the local network — Wi-Fi LAN, or direct device-to-device — never via
any relay. Discovery uses mDNS/BLE; transport is TLS with pinned identity
keys.
**Why it matters.** Offices, SCIF-adjacent environments, and field teams with
a local mesh need collaboration that provably never leaves the building.
"Cloud optional" is a serious enterprise checkbox.
**Privacy & security.** In LAN-only mode there is no relay metadata at all —
no third party learns that communication happened. The trade-off is
availability: no LAN, no sync; the outbox (A7) holds messages until peers
are reachable. The UI shows a persistent "LAN only" indicator so users never
mistake it for relay-backed chat.

### A46. Account-less encrypted cloud backup (user-held key)
**What.** Back up the encrypted database to *any* S3-compatible storage the
user chooses (their own bucket, a personal NAS via MinIO, etc.). The backup
is the SQLCipher file re-encrypted with a backup key derived from a
user-held recovery phrase (BIP-39 style, 24 words); the app never sees the
storage credentials beyond what the user enters, and the storage provider
sees only ciphertext.
**Why it matters.** Device loss shouldn't mean history loss — but iCloud/Google
backups hand your data to a vendor. User-chosen storage + user-held key keeps
recovery self-sovereign.
**Privacy & security.** The recovery phrase *is* the backup: lose it and the
backup is cryptographically unrecoverable — the setup flow forces a
verification quiz before enabling. The storage endpoint learns backup size
and timing only. Restoring to a new device triggers the re-verification
ceremony (A40) for contacts, because a restore looks exactly like a
compromise until proven otherwise.

### A47. Encrypted local database (SQLCipher) + encrypted full-text search
**What.** All persistent state lives in SQLCipher (AES-256-CBC + HMAC)
databases. Full-text search uses FTS5 *inside* the encrypted database, so
the search index gets the same encryption as the messages. See
`Packages/AegisStore/Sources/AegisStore/Docs/SQLCIPHER.md` for the key
derivation, migration, and FTS design.
**Why it matters.** "Encrypted messenger, plaintext SQLite" is an embarrassingly
common failure mode — a stolen unlocked backup or a forensic image yields
everything. The database must be encrypted with a key the OS vendor doesn't
hold.
**Privacy & security.** The DB key is device-bound (Secure Enclave wrapping,
passphrase fallback) and never leaves the device. FTS5 tokenizes message
text — the token index is as sensitive as the messages, which is exactly why
it lives inside the encrypted file rather than in a sidecar. Honest caveat:
while the app is unlocked, decrypted pages live in memory; a live-memory
forensic capture defeats any at-rest encryption — no honest product claims
otherwise.

### A48. Global on-device search
**What.** One search box across all conversations, contacts, attachments
(filenames), polls, and transcripts — powered by the encrypted FTS5 index
(A47), with filters (from:, in:, has:link/file, before:/after:) and
jump-to-message.
**Why it matters.** Institutional memory. "What did we decide about the
renewal?" should be answerable in seconds across a year of encrypted
history — without sending the query to any server.
**Privacy & security.** Queries never leave the device; there is no search
server to subpoena and no query log anywhere. Search respects tombstones and
disappearing timers — expired content is unsearchable because it no longer
exists.
