# Aegis Threat Model

**Version:** 1.0 · **Status:** draft for audit · **Companion:** `docs/CRYPTO.md`

This document says what Aegis's end-to-end encryption protects, what it
cannot protect, and how the design mitigates each threat. It is written
for a skeptical reader. If a claim here sounds like marketing, it is a bug.

---

## 1. System and trust model

- **Two (or N) devices** hold private keys. Everything else — the relay,
  the network, backups in transit — is untrusted infrastructure.
- **No central authority**: no accounts, no directory, no key server, no
  password reset. There is nobody to subpoena for your messages and nobody
  to silently add a participant to your conversations.
- **The relay is honest-but-curious at best**: it routes opaque blobs
  between mailbox IDs. It may be malicious, compromised, or legally
  compelled. The protocol is designed so that a fully malicious relay can
  *deny service* and *observe metadata* but cannot read content, forge
  messages, or undetectably man-in-the-middle sessions (the last depends
  on users actually verifying safety numbers — see §6).

## 2. Adversaries considered

| Adversary | Capability | In scope |
|---|---|---|
| Network observer | Sees all traffic, timing, sizes, IPs | Yes — mitigated, not eliminated |
| Malicious relay | Drops, delays, reorders, replays, forges envelopes | Yes — forgeries fail closed |
| Compromised contact device | Reads that contact's messages until rotation | Yes — contained, not prevented |
| Device seizure (powered on) | Full memory/disk access | Partially — see §5 |
| Device seizure (powered off) | Disk access | Yes — keys protected by OS + backup passphrase |
| Coercion (border, employer) | "Unlock your phone / give the password" | Partially — duress identity, see §4.4 |
| Malicious group member | Reads group content, re-shares keys out-of-band | Yes — documented as unpreventable |
| Global passive observer | Sees the whole network's metadata | Acknowledged — see §4.1 |

## 3. What E2EE protects

- **Message content** (text, attachments, call signaling): encrypted with
  keys the relay never holds. AES-256-GCM with single-use message keys.
- **Past messages after compromise** (forward secrecy): 1:1 message keys
  are deleted on use and chains ratchet forward; X3DH one-time prekeys
  are deleted on consumption. Stealing today's keys does not decrypt
  yesterday's ciphertext.
- **Future messages after transient compromise** (post-compromise
  security, 1:1): every received message with a new ratchet key triggers
  a DH ratchet step, healing the session. Groups heal via sender-key
  rotation (weaker guarantee, stated honestly in CRYPTO.md).
- **Sender identity from the relay** (sealed sender): the relay routes by
  mailbox ID and never sees who sent an envelope.
- **Authenticity**: every message is authenticated (AEAD tags, Ed25519
  signatures on group messages and certificates). Forgeries fail closed;
  the relay cannot inject or alter messages undetectably.
- **No silent participant**: with no central directory, there is no "add
  a ghost device" attack — new devices mean new identities, which show up
  as `changed` fingerprints, which block sending until re-verified.

## 4. What E2EE does NOT protect (residual risks)

### 4.1 Metadata — the honest big one

The relay and any network observer can see: **which mailbox IDs exchange
envelopes, when, how often, and the (padded) size class of each
envelope.** IP addresses are visible at the network layer. This means a
global observer can build a social graph (who talks to whom, when), and
timing/size classes leak conversational dynamics even though content is
hidden.

Mitigations in place: sealed sender (hides *sender* from relay),
fixed-bucket padding (hides exact sizes), no central directory (no
contact list to seize), mailbox IDs are hashes (no usernames). Not in
place: dummy traffic, mixnet routing, constant-rate sending — all would
help against traffic analysis at real battery/bandwidth cost. Documented
future work, not silent gaps.

**If your threat model includes a global passive adversary, use Tor.**
The app should make this easy; the protocol does not depend on it.

### 4.2 Endpoint compromise — game over, by definition

If an attacker owns your device (malware, unlocked seizure), they hold
the keys and read everything. No E2EE protocol survives endpoint
compromise. Mitigations are damage control: keys at rest in the OS
Keychain (device-only, biometric-gated); backups Argon2id-encrypted
(offline brute force is expensive, not impossible — **use a strong
passphrase**); in-memory hygiene is best-effort (`SecureBytes` wipes on
release, but Swift/ARC cannot guarantee no copies linger).

### 4.3 A compromised contact reads the conversation

Cryptography cannot fix trust. A contact's compromised device reads
messages sent to them, past and future until keys rotate. Group sender
keys make this slightly worse than 1:1 (a stolen sender key reads that
sender's messages until rotation), which is why rotation policy is
aggressive (1,000 messages / 7 days / membership change).

### 4.4 Coercion and the duress identity's limits

The duress password opens a valid but empty identity. Honest limits: it
does not prove you have no other identities; an adversary who already
knows your contacts, has relay traffic logs, or simply doesn't believe
you is not fooled; entering the *real* password under coercion is still
catastrophic. It helps against casual, low-information coercion and
nothing more.

### 4.5 Users who don't verify

X3DH without out-of-band verification is vulnerable to an active MITM by
the relay (it can swap prekey bundles — though the swap is *detectable*
the moment anyone compares safety numbers). Aegis makes verification
prominent (safety numbers, QR, `changed` blocking states), but a user who
taps through warnings is unprotected against an active attacker. This is
inherent to any system without a trusted directory — we chose "no trusted
third party" deliberately, and this is its price.

### 4.6 Implementation and supply-chain risk

The protocol can be perfect and the app can still leak: a bug in the
Swift code, a compromised dependency, a malicious keyboard, an OS-level
backdoor, a build system that ships something other than the audited
source. Mitigations: minimal dependencies (this crypto module depends on
*nothing* but the OS), and the audit TODO list in CRYPTO.md §15. **This
module has not yet had an independent audit — treat it as unaudited
pre-release cryptography.**

### 4.7 Denied or degraded service

A malicious relay can drop, delay, or reorder envelopes. The protocol
fails safe (the UI must distinguish sent / delivered / read — silent
loss is never *accepted* as delivered), but it cannot force delivery.
Eclipse attacks (isolating a mailbox) are possible; cross-checking via a
second channel (the LAN transport) is the mitigation.

### 4.8 Group-specific residual risks

- A malicious member can re-share sender keys or plaintext out-of-band.
  Unpreventable; the mitigation is social, not cryptographic.
- Removed members keep old ciphertext. Unpreventable.
- Group membership itself can leak via delivery fan-out: sealed sender
  hides senders per-envelope, but a relay watching one envelope fan out
  to N mailboxes learns those N mailboxes are grouped together.

### 4.9 Calls

DTLS-SRTP protects media content; the SAS ceremony protects against a
media-path MITM. But call *metadata* (who called whom, when, for how
long) is fully visible, and voice biometrics identify speakers regardless
of encryption.

## 5. Endpoint security posture

| Layer | Mechanism |
|---|---|
| Key storage | OS Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, biometric gate for export |
| No Secure Enclave | Stated plainly: the Enclave supports P-256, not Ed25519/X25519; keys live in Keychain, not the Enclave |
| Memory | `SecureBytes` best-effort wipe; chain keys in opaque handles; no key material in logs/crash reports |
| Backup | Argon2id + AES-256-GCM; wrong password indistinguishable from corruption |
| Screenshots | The app should block screenshots on safety-number/QR screens (UI workstream) |

## 6. The verification imperative

The entire "no trusted third party" design rests on users verifying
fingerprints when it matters. The protocol's job is to make MITM
*detectable* (signatures fail, fingerprints change, states block); the
product's job is to make verification *easy and hard to skip*. If the UI
ever lets a `changed` fingerprint send messages silently, that is a
security bug, not a UX choice.

## 7. Out of scope (explicitly)

- Protecting users from each other (screenshots, re-sharing).
- Anonymity against a global adversary (use Tor; we don't claim it).
- Post-quantum security: X25519/Ed25519 are not quantum-resistant.
  Harvest-now-decrypt-later is a real, accepted risk; a PQ hybrid KEM
  (e.g. ML-KEM) in X3DH is the documented migration path, not today's
  claim.
- Legal compulsion of the *user* (we hold no keys to surrender — that is
  the point — but we cannot protect users from being compelled
  themselves).

---

**Bottom line:** Aegis protects message *content* and *authenticity*
against network and infrastructure adversaries, with forward secrecy and
post-compromise healing, and no central party to compromise or compel.
It does not hide metadata from a determined observer, does not survive
endpoint compromise, and is only as strong as its implementation — which
has not yet been independently audited.
