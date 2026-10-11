# Messaging Richness — wire, store, and UI contract

Covers: quoted replies, threads, reactions (+ custom emoji), polls,
edits, deletes, disappearing timers, stars, pins. Implements FEATURES.md
A8–A12 and A15.

## Wire events (`WirePayload.Kind`)

All payloads are JSON inside the Double-Ratchet / sender-key AEAD channel.
New kinds in this workstream:

| Kind | Purpose | Key fields |
|---|---|---|
| `text` | Extended: now carries `quote` (frozen `QuoteSnapshot`), `threadRootID`, `disappearAfterRead` | `messageID`, `body`, `replyToID`, `quote`, `threadRootID`, `expiresIn`, `disappearAfterRead` |
| `poll` | Poll creation; renders as a message carrying a `PollMessage` | `messageID`, `pollQuestion`, `pollOptions`, `pollAllowsMultipleChoice`, `pollAnonymous`, `pollClosesAt`, `pollEligibleVoterCount`, `expiresIn`, `disappearAfterRead` |
| `ballot` | A vote. `targetMessageID` = the poll message | `ballotChoices: [Int]` |
| `pin` / `unpin` | Shared pins. `targetMessageID` = the pinned message | `pinExpiresAt` |
| `reaction`, `edit`, `delete` | Unchanged kinds, now **signed** (see below) | — |

Envelope kinds (`EnvelopeKind`) gained `poll`, `ballot`, `pin` (relay TTL:
default 7d, same as messages).

## Signed events

`reaction`, `edit`, `delete`, `ballot`, `pin`, `unpin` carry an Ed25519
`signature` over `signableBytes()` — a domain-separated canonical encoding
(`AegisMsgEventSig_v1|version|kind|…`) so a signature can never be replayed
as a different event kind. The AEAD channel authenticates the session; the
identity signature additionally binds the event to the long-term identity
key, so events stay attributable across session resets.

- Signing: `CryptoService.signWithIdentity(_:)` → `CryptoEngine`
  (the seed never leaves the engine actor). Mocks/previews throw
  `CryptoServiceError.noIdentity`.
- Verification (inbound, `AppState.verifyEventSignature`): against the
  AEAD-authenticated sender identity, falling back to the roster/contact
  identity key for the group sender-key path. **Unsigned or badly signed
  gated events are dropped.**
- Authorization on top of the signature: edits and deletes are applied
  only when the signer is the message's author; pins only when the pinner
  may pin (anyone in 1:1, moderators+ in groups/channels).

## Store (AegisStore, schema v4)

New columns on `message` (all covered by the v3→v4 migration):
`quote_snapshot_json`, `edit_history_json` (default `'[]'`),
`is_starred` (default 0, local-only), `pin_json`. New column on
`conversation`: `disappearing_after_read` (default 0). New indexes:
`(conversation_id, thread_root)`, `(conversation_id, is_starred)`.
`PRAGMA secure_delete = ON` was already set — expunged rows are zeroed.

New `MessageRepository` methods: `listReplies` (oldest-first),
`threadSummaries` (single GROUP BY → root → reply count + last activity),
`starredMessages` (newest-first, excludes tombstones),
`disappearedMessages(now:)` (lets the adapter destroy out-of-band secrets
— Keychain wrapped keys, cached files — before expunge).

## Behavior notes

- **Quotes**: frozen `QuoteSnapshot` (sender, excerpt, media flags,
  original expiry) + live `replyToID` pointer. The composer warns when
  quoting a disappearing message; snapshots inherit the original's timer.
- **Threads**: replies carry `threadRootID`; the thread view has its own
  read state (per-thread last-read timestamps in UserDefaults, local-only).
  Thread replies render inline in the main timeline too.
- **Polls**: tally is computed client-side from signed ballots; invalid
  ballots (double votes, closed polls, out-of-range) are ignored.
  Anonymous polls keep the voter set but no choice mapping; anonymous
  votes can't be changed. `closesAt` is enforced on send and receipt.
- **Edits**: configurable window via Settings → Messaging (default 48h,
  0 = disabled); local version history kept per message, never re-shared.
- **Deletes**: `store.deleteMessage` → package tombstone (drops attachment
  rows) + adapter wipes Keychain wrapped keys and cached files first.
- **Disappearing**: per-chat timer (10s…7d) starting on send or on read
  (`disappearingAfterRead`). After-read expiry for our own messages starts
  on the incoming read receipt; for inbound, on `markAsRead`.
- **Stars**: local-only flag, never sent. **Pins**: shared signed events,
  admin-gated, optional expiry; pinning a disappearing message is blocked.
- **Custom emoji**: packs are local-only JSON (`EmojiPackStore`), images
  normalized to ≤128px PNG, rendered as images only. Reaction keys are
  `pack:<packID>:<emojiID>`; unknown packs render a placeholder glyph.
