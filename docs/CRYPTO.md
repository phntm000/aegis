# Aegis Cryptographic Protocol Specification

**Version:** 1.0 · **Status:** draft for audit · **Implementation:** `Packages/AegisCrypto`

This document specifies the Aegis end-to-end encryption protocol: what is
encrypted, with what, and why. The Swift implementation in
`Packages/AegisCrypto` follows it section by section; where the two
disagree, this document wins and the code is a bug.

Notation: `||` is concatenation. `BE`/`LE` are big-/little-endian byte
order. All domain-separation strings carry a `_v1` suffix so a future
protocol revision cannot cross-wire with this one.

---

## 1. Design goals

1. **No accounts, no directory, no central auth.** An identity *is* a
   keypair, generated on-device. Contacts are added by exchanging
   fingerprints out-of-band (QR code / invite string). There is no server
   that can enumerate users, reset passwords, or be compelled to add a
   silent participant.
2. **Standard constructions, conservative parameters.** X3DH, Double
   Ratchet, sender keys, AES-256-GCM, Ed25519, X25519, HKDF-SHA256,
   Argon2id. No novel cryptography; novelty lives in how the pieces are
   composed for a serverless design.
3. **The relay is untrusted.** It routes opaque blobs keyed by mailbox
   IDs. It cannot read content, forge messages, enumerate contacts, or
   learn who talks to whom beyond traffic metadata (see
   `THREAT_MODEL.md`).
4. **Honest failure modes.** Every simplification is marked
   `// TODO(security-audit):` in the code and collected in §13.

## 2. Primitives

| Purpose | Algorithm | Parameters |
|---|---|---|
| Key agreement | X25519 (RFC 7748) | via CryptoKit |
| Signatures | Ed25519 (RFC 8032) | via CryptoKit |
| Symmetric encryption | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag, via CryptoKit |
| Key derivation | HKDF-SHA256 (RFC 5869) | pure Swift over CryptoKit HMAC |
| Hashing | SHA-256, SHA-512 | via CryptoKit |
| Variable-output hashing | BLAKE2b (RFC 7693) | pure Swift (Argon2 core) |
| Passphrase KDF | Argon2id (RFC 9106), v=0x13 | pure Swift; default m=64 MiB, t=3, p=1 |
| Randomness | platform CSPRNG | `SecRandomCopyBytes`, no fallback |

CryptoKit is used for every primitive it provides. The two pure-Swift
pieces are BLAKE2b and Argon2id (CryptoKit provides neither), both
validated against RFC test vectors (see `BackupTests`,
`PrimitiveTests`).

### 2.1 Why the identity uses two keys

Signal uses one Curve25519 key for both signing and DH via XEdDSA point
conversion. CryptoKit exposes no XEdDSA conversion, and hand-rolling
ed25519 curve arithmetic in Swift to synthesize it would be unjustifiable
risk. Aegis therefore uses two purpose-separated keys:

- **Ed25519 signing key** — the *fingerprint identity*: what contacts
  verify, what signs bundles/certificates/distributions.
- **X25519 agreement key** — the *DH identity*: what participates in X3DH.

The fingerprint binds both (see §3). A future libsignal-client adapter
behind the `CryptoProvider` seam may collapse them back to one key; the
protocol is written to allow it (the X3DH equations name the agreement
key explicitly).

## 3. Identity and fingerprints

```
fingerprint = SHA256("AegisIdentityFP_v1" || ed25519_pub || x25519_pub)   # 32 bytes
mailboxID   = SHA256("AegisMailbox_v1" || fingerprint)[0..16]            # 16 bytes
```

The fingerprint is the user-visible identity: 64 hex chars (grouped),
the safety-number input, and the QR payload. The mailbox ID is the
relay's only routing handle — a hash output that reveals nothing about
the keys.

Identity keys are generated on-device at first launch and never leave it
except inside a passphrase-encrypted backup (§10). There is no
registration step to intercept.

## 4. Prekeys

Each device publishes a `PreKeyBundle`:

```
bundle = identity_pub(64) || spk_id(u32) || spk_pub(32) || spk_sig(64) ||
         [opk_id(u32) || opk_pub(32)] || bundle_sig(64)
bundle_sig = Ed25519(identity_sign,
                     "AegisIdentityFP_v1"-context encoding of all fields above)
spk_sig    = Ed25519(identity_sign, "AegisSPK_v1" || spk_id_BE || spk_pub)
```

- **Signed prekey**: medium-lived X25519 keypair, rotated at least every
  7 days. Its public half doubles as the responder's *initial* Double
  Ratchet key (§6) — this is what lets the initiator ratchet into her
  first sending chain before the responder has generated any ratchet key.
- **One-time prekeys**: pool of 100 single-use X25519 keypairs, refilled
  when fewer than 20 remain. The responder deletes the private half the
  moment it is consumed. This is what gives the *first* message forward
  secrecy.

**Bundle publication (current limitation)**: the relay key-value slot is
not yet implemented — bundles are exchanged out-of-band today (QR
invite payload, `invitePayload()`), and X3DH initiation only consumes
bundles cached from those invites. There is therefore no async
first-contact with a party you have never exchanged an invite with; the
spec's "dumb key-value slot (one slot per mailbox ID,
last-writer-wins — the relay cannot forge the signatures, so a
malicious overwrite is detectable: verification fails closed)" is the
target design, not the current behavior. If the bundle has no one-time
prekey, X3DH proceeds without the DH4 term; the UI should note reduced
first-message forward secrecy.

## 5. X3DH key agreement

With initiator identity `IKA` (agreement key), ephemeral `EKA`, responder
identity `IKB`, signed prekey `SPKB`, one-time prekey `OPKB`:

```
DH1 = DH(IKA_agree, SPKB)
DH2 = DH(EKA,      IKB_agree)
DH3 = DH(EKA,      SPKB)
DH4 = DH(EKA,      OPKB)            # if present
salt = SHA256("AegisX3DH_v1" || fp_initiator || fp_responder)
```

The KDF is a **cascade**, not Signal's `KDF(DH1||DH2||DH3||DH4)`, because
CryptoKit's `SharedSecret` never exposes raw bytes (a deliberate
platform safeguard we keep). Each stage HKDFs one DH secret with a salt
chained from the previous stage:

```
k0 = HKDF(DH0, salt: salt,                     info: "AegisX3DH_v1/0")
ki = HKDF(DHi, salt: HMAC(k{i-1}, "AegisX3DH_v1/step{i}"),
                       info: "AegisX3DH_v1/{i}")
SK = k_last
```

The final key requires *all* DH secrets: each stage's salt is a MAC under
the previous stage's key, so skipping or substituting any DH breaks the
chain. The salt binds both fingerprints, preventing unknown-key-share
retargeting. The initiator MUST verify the bundle signature before
running X3DH; the responder's X3DH has no live authentication, so the
first Double-Ratchet message authenticates the handshake (its AAD covers
the X3DH parameters — see §7).

## 6. Double Ratchet (1:1 sessions)

Signal's Double Ratchet algorithm with Aegis KDF instantiations. State
per session: root key `RK`, sending/receiving chain keys, current DH
ratchet keypair, peer's ratchet public key, message counters, and a
bounded skipped-message-key store.

```
Root KDF (per DH ratchet step):
    stepSalt = HMAC(RK, "AegisRatchetStep_v1")
    mixKey   = HKDF(DH, salt: stepSalt, info: "AegisRatchetDH_v1")
    RK'      = HMAC(mixKey, "AegisRatchetRoot_v1")
    CK'      = HMAC(mixKey, "AegisRatchetChain_v1")

Chain KDF:
    CK_{n+1} = HMAC(CK_n, 0x01)
    MK_n     = HKDF(HMAC(CK_n, 0x02), salt: "", info: "AegisMessageKey_v1")

Message encryption:
    ct = AES-256-GCM(MK_n, nonce: random 96-bit,
                     aad: version || type || header || appAD, pt: message)
```

Initialization: the initiator DH-ratchets immediately with
`DH(ratchetPriv, responderSPKpub)`; the responder's initial ratchet
keypair *is* her signed-prekey pair, and her first sending chain is born
when she processes the initiator's first ratchet public key.

**Header** (40 bytes, authenticated but not encrypted):
`ratchetPub(32) || pn(u32 BE) || n(u32 BE)`, where `pn` is the previous
sending-chain length (drives skipped-key stashing) and `n` the message
index.

**Out-of-order handling**: skipped message keys are stored per
`(ratchetPub, n)`, bounded at 2,000 entries with oldest-evicted; a
message more than 1,000 positions ahead of the chain is rejected
(`messageTooFarInFuture` — a DoS bound). **Forward secrecy**: a message
key is deleted the moment it is used; chain keys ratchet forward and old
values are overwritten. **Post-compromise security**: every new ratchet
public key triggers a DH ratchet step, healing the session.

On authentication failure the message key is consumed (per the spec),
making the forgery un-replayable; the message is then lost. Sessions are
confined to a single serial queue (not thread-safe by design).

## 7. Message envelopes

Two 1:1 wire types, both version-led (`0x01`):

- **`RatchetMessage` (0x01)**: `version || 0x01 || header(40) || nonce(12)
  || ctLen(u32) || ct || tag(16)`. AAD = `version || 0x01 || header`.
- **`PreKeyMessage` (0x02)**: `version || 0x02 || ephPub(32) ||
  usedOPK(u32) || senderIdentity(65) || header(40) || nonce(12) ||
  ctLen(u32) || ct || tag(16)`. AAD covers the X3DH parameters too, so a
  relay cannot swap the ephemeral key or claimed sender identity.

Decoders are strictly bounds-checked and reject trailing bytes.

## 8. Groups: sender keys

One encryption per group message. Each sender owns a **sender key**:
a 32-byte symmetric chain plus a per-distribution Ed25519 signing key.

```
MK_i = HKDF(HMAC(CK_i, 0x02), info: "AegisGroupMsgKey_v1")
CK_{i+1} = HMAC(CK_i, 0x01)
sig  = Ed25519(senderSignKey, header || nonce || ct)   # verified FIRST
ct   = AES-256-GCM(MK_i, aad: header, pt: pad(message))
```

- **Distribution**: `groupID || epoch || senderID || chainKey || signingPub`,
  sent once per (sender, epoch), **encrypted inside each member's 1:1
  session** — never in the clear. The distribution is the crown jewels.
- **Identity-sealed fallback (`AKD1`)**: when no 1:1 session exists with a
  new member (e.g. they were just invited), the distribution is sealed to
  their *identity key* instead: X25519 ECDH (ephemeral × recipient
  long-term identity agreement key) → HKDF (`AegisIdentityKeyDist_v1`,
  salt = senderFP ‖ recipientFP) → AES-256-GCM, magic `"AKD1"`, Ed25519
  signature from the distributor verified against `knownIdentities`
  (populated from roster-authenticated invites/controls). The joiner
  accepts it only if the distributor is a roster member. **Security
  properties, stated plainly**: (i) unlike the 1:1-session path this is
  **not forward-secret** — anyone holding the recipient's long-term
  identity key can recover the distributed sender key; (ii) **both
  32-byte fingerprints travel in the clear**
  (`magic || senderFP || recipientFP || …`), leaking strictly more
  metadata than sealed sender's 16-byte mailbox ID. The AKD1 fallback
  keeps the "never in the clear" invariant for the *key material* without
  requiring a prior 1:1 session, at the cost of these two properties.
- **Epochs**: every membership change bumps the epoch; the changer
  generates a fresh sender key and distributes it. Removed members get no
  new keys (can't read new messages); added members never get old keys
  (can't read history). A removed member obviously retains ciphertext
  from while she was a member — no protocol can revoke that.
- **Rotation policy**: sender keys also rotate every 1,000 sent messages
  or 7 days, whichever comes first — the group's substitute for the 1:1
  DH ratchet, bounding a compromised sender key's blast radius.
- **Out-of-order**: per-(sender, epoch) skipped-key store, 500-message
  gap bound; the current and immediately previous epoch are accepted (so
  in-flight messages survive a rotation); older epochs are rejected.

Security is weaker than the 1:1 ratchet in exactly one dimension: no DH
ratchet per message, so post-compromise security rests on rotation
discipline rather than mathematics. This is stated plainly because it is
true of every sender-keys design (including Signal's).

## 9. Sealed sender

Envelopes addressed by 16-byte mailbox ID only. Per envelope:

```
eph   = fresh X25519 keypair (never reused)
key   = HKDF(DH(ephPriv, recipientAgreePub), salt: mailboxID,
             info: "AegisSealed_v1")
ct    = AES-256-GCM(key, aad: version || wireType || mailboxID || ephPub,
                    pt: pad(cert || innerMessage))
cert  = fingerprint(32) || timestamp(u64) ||
        Ed25519(senderSign, "AegisSealedCert_v1" || ephPub || mailboxID ||
                             timestamp || SHA256(innerMessage))
```

The relay learns only that *some* envelope is addressed to a mailbox,
plus size class and timing. The recipient resolves the certificate's
fingerprint to a known contact (unknown fingerprints surface as unknown
senders — never silently as contacts) and verifies the certificate,
including a 48-hour freshness window (replay bound). The inner message
must itself be an authenticated envelope. Payloads are padded to fixed
buckets (256 B … 64 KiB) to blunt size analysis.

## 10. Verification ceremonies

- **Safety number**: `SHA-512` once over the sorted fingerprints
  (domain-separated), then `SHA-256` iterated 5,200 times over the digest;
  first 30 bytes, displayed as 75 digits in 15 groups of 5.
  Order-independent; both sides compute the same value and compare
  out-of-band (voice, in person).
- **QR**: 97-byte payload of both public keys plus the fingerprint, with
  the fingerprint binding re-checked on scan. Contains zero secret
  material — photographing it buys an attacker nothing.
- **States**: `unverified` / `verified` / `changed`, surfaced per contact
  and per group. A fingerprint change on a `verified` contact is a
  blocking warning, not a toast.

## 11. Calls

Signaling rides inside the E2EE envelopes (§7 or §9 — the "knock" that
reaches a callee with no push infrastructure). Media is protected by
WebRTC **DTLS-SRTP**: each side's DTLS certificate fingerprint is
exchanged inside the E2EE signaling and pinned during the DTLS
handshake, so the relay (or a LAN peer) sees only SRTP ciphertext. A
**ZRTP-style Short Authentication String** — 20 bits from both DTLS
fingerprints, rendered as 4 unambiguous characters — is read aloud to
bind the *media* keys to the verified conversation, defeating a media-
path MITM even if signaling were somehow compromised. **The SAS
ceremony is implemented for 1:1 calls only** (`callSAS()` /
`ActiveCallView`); voice rooms (full-mesh group calls) have no per-peer
SAS ceremony, so the media-path-MITM defense there rests on the E2EE
signaling channel alone. Group calls start
as full-mesh WebRTC; an SFU with SFrame is the documented scaling path
(see `docs/NETWORKING.md`, owned by the transport workstream).

## 12. Key backup

Passphrase → Argon2id(m=64 MiB, t=3, p=1, v=0x13) → 256-bit
key-encryption key → AES-256-GCM over
`version || exportedAt || ed25519Seed || x25519Priv || spkID || spkPriv`.
AAD covers the KDF parameters and salt. Wrong passwords are
indistinguishable from corrupted files.

**Why Argon2id, not PBKDF2**: PBKDF2 is only CPU-hard — GPUs/ASICs try
passphrases orders of magnitude faster than the defender's phone, so a
stolen backup file falls to offline brute force far sooner. Argon2id is
*memory*-hard: every guess needs tens of megabytes of RAM, which
dedicated hardware cannot cheaply parallelize. The `id` variant keeps
Argon2d's resistance to tradeoff attacks while using data-independent
addressing for the first half of the first pass (side-channel
resistance). PBKDF2-only would be a meaningful downgrade; we don't do it.

**Duress**: a second password exports a fresh, empty identity. It raises
the cost of casual coercion; it does not provide deniability against an
adversary who already knows your contacts (see `THREAT_MODEL.md`).

1:1 sessions are *not* backed up — they re-establish via X3DH after
restore. Group sender keys are re-distributed by peers on demand.

## 13. Nonce discipline and key rotation

- **Nonces**: fresh 96-bit random nonce per encryption, from the platform
  CSPRNG. Every (key, nonce) pair is used exactly once because every
  message key is single-use by construction (ratchet chains, sender-key
  chains, sealed-sender ephemeral keys). No nonce state is stored; with
  2⁹⁶ nonces per key and one use per key, random generation is safe.
- **Signed prekeys**: rotate every 7 days; one-time pool refilled below 20.
- **Sender keys**: every 1,000 messages or 7 days, plus on every
  membership change (which also bumps the epoch).
- **Identity keys**: rotate only by creating a new identity — contacts
  must re-verify (the `changed` state exists for exactly this).

## 14. Implementation seams

- `CryptoProvider` / `DHSecret`: all session logic depends on these, never
  on CryptoKit directly. `CryptoKitProvider` is the production adapter.
- `RatchetEngine`: the Double Ratchet behind a protocol; a
  libsignal-client adapter can implement it without touching callers.
- `PassphraseKDF`: backup KDFs are pluggable.

These seams are load-bearing design, not abstraction for its own sake:
they are where a future audit or a libsignal migration plugs in.

## 15. Audit TODO index

Every item below is marked `// TODO(security-audit):` at the relevant
code site. This list is the audit's table of contents.

1. `SecureBytes`: Swift/ARC cannot guarantee no copies of key bytes
   survive in freed heap pages; evaluate `mlock`'d regions for
   long-lived keys and audit every `toData()` call site's lifetime.
2. `CryptoKitDHSecret` / `CryptoKitProvider`: verify no adapter path logs
   or persists raw secret bytes, and that `derivedKey` is always called
   with a fresh domain-separation `info` per call site.
3. `AegisDoubleRatchet`: the cascade root KDF (§6) is a deliberate
   adaptation of Signal's `HKDF(RK || DH)` to opaque key handles —
   confirm the "all inputs required" property holds under the cascade.
4. `Argon2id`: lanes are filled sequentially (p=1); parallelize (p=4)
   and re-tune defaults; assess cache-timing exposure of the
   data-dependent phase on shared mobile SoCs.
5. `SealedSender`: the 48-hour certificate window is a usability/security
   tradeoff — confirm it matches the product's offline-message lifetime.
6. `GroupSession`: confirm the epoch-grace window (current + previous)
   cannot be abused to keep a removed member reading new messages
   (it can't — rotation changes the chain key — but verify the logic).
7. `PreKeyManager`: one-time-prekey exhaustion behavior under active
   attack (bundle without OPK) and the deletion discipline in
   `consumeOneTimePreKey`.
8. Wire decoders: fuzz `WireDecoder`, envelope parsers, and the backup
   importer with hostile inputs.

## 16. What this spec does not cover

Transport, relay behavior, push delivery, and media stack are owned by
the transport workstream (`docs/NETWORKING.md`). This spec defines the
cryptographic envelope contents; how envelopes move is out of scope —
with one requirement: **sender-key distributions and prekey bundles must
never traverse the network outside an authenticated E2EE envelope**
(the bundle is self-authenticating by signature; the distribution is
not, and relies on the 1:1 session or the AKD1 identity-sealed fallback
in §8).

## 17. Linked-device pairing

A companion device holds **no** identity keys; it pairs over an E2EE
channel and relays all traffic through the primary (WhatsApp-Web-style).
Pairing runs on a short-lived pairing mailbox HKDF-derived from the QR
pairing ID:

1. Primary shows a QR payload; secondary scans it and sends `hello`.
2. Both sides run ephemeral-ephemeral ECDH and derive a 4-word SAS from
   the DH shared secret (first 8 bytes → 4 × 11-bit words = **44 bits**).
3. The user compares the words on both screens and taps Confirm; the
   primary then sends the AES-GCM-sealed provisioning bundle (contacts,
   conversations, recent history).
4. Both sides derive and persist a **long-term static paired channel key**
   in the Keychain.

**Honest limits**: the paired channel has **no forward secrecy and no
post-compromise security** — the static channel key never rotates and has
no ratchet, so a seized channel key decrypts all captured sync traffic,
which includes message bodies. The SAS-match confirmation is enforced in
the UI flow, **not** on the wire: a modified primary could skip the
confirmation step. Unpair is a local wipe plus a best-effort
(best-effort, unauthenticated-by-crypto) message to the peer; there is no
cryptographic revocation or rotation on unpair.

## 18. Anonymous rendezvous (`openAnonymous`)

First-contact prekey messages can arrive via the sealed-sender path with
no sender certificate (`SealedSender.openAnonymous`): the certificate
signature is *not* checked, and trust is deferred entirely to the X3DH
inner message — a successful X3DH/AEAD decrypt against the claimed
sender identity is what authenticates the initiator. The trust model for
first contact is therefore: **anyone able to address the 16-byte
identity mailbox can initiate X3DH**; the responder's defense is that
only the true holder of the claimed identity key can complete the
handshake. (Ordering note: the certificate-fingerprint equality check in
`decryptPreKeyFromUnknownSender` runs *before* `SessionEstablishment.respond`,
not after as one code comment suggests — harmless, since X3DH still
gates trust and a mismatch fails closed either way.)

## 19. Routing mailboxes (dual mailbox scheme)

Two mailbox layers exist:

- **Identity mailbox** (16 bytes): the sealed-sender addressing layer
  (§9), derived from the identity fingerprint. Stable per identity.
- **Routing mailboxes** (32 bytes, `RoutingMailbox`): the wire-transport
  addressing layer, unlinkable to the identity mailbox by construction
  (independent SHA-256 derivations):
  - `identityRoute = SHA256("AegisIdentityRoute_v1" || fingerprint)` —
    used for the first prekey message only. Deterministic and stable per
    identity; the relay can link pre-session traffic, but everything
    after the handshake moves to `directRoute`.
  - `directRoute = SHA256("AegisDirectRoute_v1" || min(fpA,fpB) ||
    max(fpA,fpB) || ephemeralPub)` — one stable label per 1:1 session,
    derived from the X3DH ephemeral public key (visible to both parties
    in the `PreKeyMessage`), never from ratchet state. A fresh handshake
    yields a fresh, unlinkable label; within a session the relay observes
    a single stable label (the same exposure Signal's server has by
    design).
  - `groupRoute = SHA256("AegisGroupRoute_v1" || groupID || epochBE)` —
    rotates every epoch (every membership change). The transport binds
    the current *and* previous epoch's mailbox (matching the crypto
    layer's epoch grace window) so a membership change never partitions
    the group mid-adoption.

## References

- Signal Protocol: X3DH, Double Ratchet, Sesame / Sender Keys
- RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF), RFC 7693
  (BLAKE2), RFC 9106 (Argon2)
- RFC 6189 (ZRTP) — SAS construction inspiration
- WebRTC DTLS-SRTP (RFC 5764, RFC 8842)
