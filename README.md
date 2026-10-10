# Aegis

**A serious, enterprise-grade, fully end-to-end encrypted alternative to
Discord and Telegram — for iOS. No accounts. No phone numbers. No database
that can read you.**

Aegis is an iOS 17+ SwiftUI messenger with E2EE 1:1 and group chat, broadcast
channels, encrypted voice/video calls and Discord-style voice rooms, sealed
sender metadata protection, and an offline-first encrypted local store. The
network relay is deliberately dumb: it stores opaque sealed envelopes with a
short TTL and forwards them. It cannot read content, sender identities, or
group membership.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Aegis iOS app                             │
│              SwiftUI · iOS 17+ · offline-first                   │
│              account-less · no phone numbers                     │
├───────────────┬────────────────┬───────────────┬────────────────┤
│  AegisCrypto  │ AegisTransport │  AegisStore   │     App UI     │
│  X3DH +       │ sealed         │ SQLCipher     │ SwiftUI views  │
│  Double       │ envelopes,     │ encrypted DB  │ CallKit,       │
│  Ratchet,     │ relay client,  │ + FTS5,       │ background     │
│  sealed       │ LAN/mDNS + BLE │ repository    │ fetch, local   │
│  sender,      │ discovery      │ protocols     │ notifications  │
│  group keys   │                │               │ (no APNs)      │
└───────┬───────┴────────┬───────┴───────┬───────┴────────────────┘
        │                │               │
        ▼                ▼               ▼
  key material     ┌─────────────┐  ┌──────────────┐
  never leaves   │    Relay     │  │  LAN / BLE    │
  the device     │  (dumb,       │  │  direct P2P,  │
                 │   Python,     │  │  no relay     │
                 │   self-host) │  │  at all       │
                 └─────────────┘  └──────────────┘
```

- **`Packages/AegisCrypto`** — key agreement, ratchets, sealed sender, group
  key management. (Spec: `docs/CRYPTO.md`. Owned by the crypto agent.)
- **`Packages/AegisTransport`** — sealed-envelope relay protocol, LAN/mDNS
  transport, BLE discovery, outbox drain. (Owned by the transport agent.)
- **`Packages/AegisStore`** — encrypted persistence: data models, repository
  protocols, SQLCipher integration design, in-memory implementation for tests.
  (This agent's package — see below.)
- **`relay/`** — the dumb relay server (Python, self-hostable). One-liner in
  Quickstart. (Owned by the transport agent.)
- **`Aegis/`** — the SwiftUI app target (XcodeGen `project.yml`). (Owned by
  the app agent.)

Threat model: `docs/THREAT_MODEL.md`. Feature spec: `docs/FEATURES.md`
(48 features). Delivery plan: `docs/ROADMAP.md`.

---

## Repo map

```
aegis/
├── README.md                 ← you are here
├── Package.swift             ← root SPM manifest (aggregates the 3 packages)
├── Sources/Aegis/            ← @_exported umbrella (re-exports the packages)
├── project.yml               ← XcodeGen (app agent)
├── Aegis/                    ← SwiftUI app sources (app agent)
├── Packages/
│   ├── AegisCrypto/          ← crypto (crypto agent)
│   ├── AegisTransport/       ← transport/relay client (transport agent)
│   └── AegisStore/           ← encrypted store (this spec's package)
│       ├── Package.swift
│       ├── Sources/AegisStore/
│       │   ├── Models.swift          ← Conversation, Message, Contact,
│       │   │                            GroupMembership, Attachment, CallRecord
│       │   ├── Repositories.swift    ← repository protocols the app codes against
│       │   ├── InMemoryStore.swift   ← in-memory impl (tests, previews)
│       │   └── Docs/SQLCIPHER.md     ← SQLCipher integration design
│       └── Tests/AegisStoreTests/    ← unit tests
├── relay/                    ← dumb relay server (transport agent)
├── docs/
│   ├── FEATURES.md           ← 48-feature master spec
│   ├── ROADMAP.md            ← phased delivery plan
│   ├── CRYPTO.md             ← cryptographic design (crypto agent)
│   └── THREAT_MODEL.md       ← adversary model (crypto agent)
└── .github/workflows/ci.yml  ← macOS CI: xcodebuild + swift test + relay test
```

---

## Quickstart

**Prerequisites:** macOS with Xcode 16+, [XcodeGen](https://github.com/yonaskolb/XcodeGen)
(`brew install xcodegen`). Swift cannot compile on Linux — CI uses GitHub's
macOS runners (see Honest Limitations).

```bash
# 1. Generate the Xcode project and open it
xcodegen generate
open Aegis.xcodeproj

# 2. Run the dumb relay locally (self-hostable, zero config)
python3 relay/relay.py --port 8443 --self-test   # self-test first
python3 relay/relay.py --port 8443               # then serve

# 3. In Xcode: select the Aegis scheme, an iOS 17+ simulator or device, ⌘R.
#    Point the app at your relay (Settings → Relay → http://<host>:8443),
#    or use LAN-only mode with no relay at all.

# 4. Run the package tests (no Xcode project needed)
swift test --package-path Packages/AegisStore
```

---

## HONEST LIMITATIONS

Read these before evaluating or deploying Aegis. They are architectural
facts, not temporary gaps.

**(a) No APNs push — by design, not by budget.** iOS push goes through Apple
Push Notification Service (APNs), which requires a paid Apple Developer
Program membership ($99/year) and — more importantly — registers a push
token that tells Apple exactly which device to wake for whom. Aegis
deliberately registers no push token: Apple learns nothing about your
conversations. Delivery is real-time when the app is open or peers are
nearby (WebSocket relay, LAN Multipeer); when closed, the relay's 7-day
store-and-forward queue plus iOS Background App Refresh deliver on the
next OS wake, surfaced as local notifications decrypted on-device. Calls
use the sealed knock-and-rendezvous flow. Closed-app latency is
OS-scheduled and shown honestly in the connectivity UI — nothing is lost,
only delayed.

**(b) App Store / TestFlight distribution also needs the paid account.**
Without it, your options are: Xcode sideloading to your own devices (free,
but provisioning expires every 7 days and must be re-signed), or ad-hoc
distribution. CI builds, simulator runs, and all tests need no paid account.

**(c) No cryptographic audit has been performed.** The protocol design
(`docs/CRYPTO.md`) follows well-studied constructions (X3DH, Double Ratchet,
sealed sender), but *no independent audit* has reviewed this codebase. Do
not stake lives, liberty, or nine-figure deals on unaudited crypto. An audit
is the single highest-value pre-1.0 investment.

**(d) Swift cannot compile on the Linux build machine.** This repository's
Swift packages and app can only build where Apple's toolchain exists.
GitHub Actions CI runs everything on `macos-14` runners
(`.github/workflows/ci.yml`); local Linux development is limited to the
Python relay and documentation.

**(e) Endpoint security is the boundary.** E2EE protects data in transit and
at rest (SQLCipher), but a compromised or unlocked device, a coerced user,
or a photograph of the screen defeats every messenger ever built — including
this one. Features like screenshot alerts (A35) and the duress PIN (A34) are
deterrents and tripwires, documented as such, not prevention.

**(f) Metadata minimization is not metadata elimination.** Sealed sender and
ghost mode raise the cost of traffic analysis substantially, but a global
passive adversary observing the entire network can still do timing/volume
correlation. Aegis does not claim to be a mixnet or to defeat nation-state
traffic analysis.
