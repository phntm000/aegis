# AegisStore — SQLCipher Integration Design

**Status:** IMPLEMENTED in the `AegisStore` SwiftPM package
(`SQLCipherAegisStore`, `Packages/AegisStore/Sources/AegisStore/`).
The adapter is compiled and tested as part of the package — `swift test
--package-path Packages/AegisStore` — so there is no Xcode/SPM integration
step and no third-party dependency. What follows is the normative design;
the "Implementation status" section at the end records exactly which parts
are built and which remain hardening work. Deviations from the original
GRDB-based plan carry a written rationale (§1).

## 1. Dependency choice

- **Vendored SQLCipher amalgamation** as the `CSQLCipher` SwiftPM C target
  (`Sources/CSQLCipher/sqlite3.c` + `include/sqlite3.h`), compiled with
  `SQLITE_HAS_CODEC`, `SQLCIPHER_CRYPTO_CC` (CommonCrypto — no extra
  dependency on Apple platforms), and `SQLITE_ENABLE_FTS5`.
- A thin Swift wrapper (`SQLCipherConnection`) owns the single sqlite3
  handle; `SQLCipherAegisStore` (an actor) implements `AegisDatabase` and
  the six repository protocols on top of it.
- Rationale for deviating from the original GRDB plan: putting the adapter
  in the SwiftPM package makes it buildable and testable in CI with
  `swift test` (the app target has no test target), removes the
  Xcode-package-dependency setup step, and avoids a third-party dependency
  in the security-critical storage path. The unsafe surface (raw sqlite3
  calls) is contained in one audited file (`SQLCipherConnection.swift`):
  all statements are prepared with bound parameters, never string
  interpolation of values.
- Alternative considered and rejected: GRDB.swift via Xcode SPM — heavier
  integration, untestable in this CI (no app test target), third-party
  dependency for the encrypted store.

## 2. Key management

### 2.1 Key hierarchy (implemented, Phase 1)

```
SecRandomCopyBytes → DB key (256-bit random, generated once at first launch)
        │  stored directly in Keychain
        ▼
kSecClassGenericPassword, accessibleAfterFirstUnlockThisDeviceOnly,
synchronizable = false (never leaves the device, never enters backups)
        │
        ▼
PRAGMA key = "x'<hex of DB key>'"   (SQLCipher)
```

- **Implemented:** `DatabaseKeyManager` — 32 bytes from `SecRandomCopyBytes`
  at first launch, stored in the Keychain as above, loaded on every open,
  zeroed from memory immediately after `PRAGMA key`.
- **Hardening target (not yet implemented):** the KEK layer from the
  original design — wrapping the DB key under a Secure-Enclave biometric
  key and/or an Argon2id passphrase KDF, duress-PIN decoy database (§2.3),
  and explicit database re-key (§2.4). The Phase 1 property that matters —
  the database file is AES-256 encrypted under a device-bound random key
  that never lives in the filesystem — holds without it.
- **In-memory hygiene:** unwrap → hex → `PRAGMA key` → immediately zero
  the buffers. The unwrapped key never lives in a property.

### 2.2 Open / unlock flow (implemented)

1. Load (or generate + store) the DB key via `DatabaseKeyManager`. **Any
   failure → throw `.encryptionUnavailable`, and STOP.** There is no
   plaintext fallback, no "continue without encryption."
2. `sqlite3_open` → `PRAGMA key = "x'...'"` → verify `PRAGMA cipher_version`
   returns a SQLCipher build string (guards against silently linking
   non-encrypted SQLite) → probe-read `sqlite_master` (a wrong key surfaces
   here as "file is not a database" → `.encryptionUnavailable`).
3. `PRAGMA busy_timeout`, `journal_mode = WAL`, `foreign_keys = ON`
   (off by default in SQLite — there is a cascade test asserting this),
   `secure_delete = ON`.
4. Run pending migrations (§3). New databases get the full v1 schema.

### 2.3 Duress PIN / decoy vault

- The decoy is a **second, independent database file** (`aegis-decoy.db`)
  with its own independently generated DB key, wrapped under a KEK derived
  from the duress PIN only.
- Entering the duress PIN at the lock screen opens the decoy database and
  presents it as the app. The real database file is never opened, never
  touched (verify: file mtime unchanged — covered by a test).
- The decoy database must contain plausible content (contacts, chats).
  The app offers optional "decoy upkeep" that synthesizes realistic-looking
  local activity on a schedule.
- **Honest limitation (also in FEATURES.md A34):** a forensic image of the
  device may reveal two database files. The decoy defends against casual
  inspection and coercion, not a lab.

### 2.4 Database re-key

Provide Settings → Security → "Change database key": generate a new DB key,
`PRAGMA rekey`, re-wrap under the current KEK(s). Used after suspected
compromise (pairs with the re-verification ceremony, FEATURES.md A40).

## 3. Schema & migrations

- **Version table:** `schema_migrations(version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL)`. `PRAGMA user_version` mirrors the version.
- **Migrations are forward-only.** Each migration runs inside a single
  transaction; on failure the transaction rolls back and open throws
  `.migrationFailed`. There are no destructive down-migrations.
- **Adding a column:** `ALTER TABLE … ADD COLUMN` with a sane default.
- **Backfills** run inside the migration transaction; large backfills must
  be chunked with progress callbacks so first-launch migration doesn't ANR.
- **v1 schema** (normative table list — columns mirror `Models.swift` 1:1):
  - `conversation`, `message`, `contact`, `group_membership`,
    `attachment`, `call_record`, `schema_migrations`
  - Indexes: `message(conversation_id, created_at DESC)`,
    `message(disappear_at)` (for the expunge sweep),
    `attachment(message_id)`, `group_membership(conversation_id)`,
    `call_record(conversation_id, started_at DESC)`.
- **Foreign keys:** `message.conversation_id → conversation(id) ON DELETE
  CASCADE`, `attachment.message_id → message(id) ON DELETE CASCADE`,
  `group_membership.conversation_id → conversation(id) ON DELETE CASCADE`,
  `call_record.conversation_id → conversation(id) ON DELETE CASCADE`.
  Enforced with `PRAGMA foreign_keys = ON` (off by default in SQLite —
  forgetting this is the classic bug; there is a test asserting cascade
  delete works).
- **Secure delete:** `PRAGMA secure_delete = ON` so deleted content isn't
  left in freelist pages. (Defense in depth; the threat model notes that
  only full-file re-key + VACUUM gives strong guarantees — see 5.2.)

## 4. Encrypted full-text search (FTS5)

Search must be as encrypted as the messages. The FTS index therefore lives
**inside the same SQLCipher database file** — never in a sidecar.

```sql
CREATE VIRTUAL TABLE message_fts USING fts5(
    text,
    transcription,
    content='message',
    content_rowid='rowid',
    tokenize='unicode61 "remove_diacritics 2"'
);

CREATE TRIGGER message_fts_ai AFTER INSERT ON message BEGIN
    INSERT INTO message_fts(rowid, text, transcription)
    VALUES (new.rowid, new.text,
            (SELECT group_concat(transcription, ' ')
             FROM attachment WHERE message_id = new.id));
END;
CREATE TRIGGER message_fts_ad AFTER DELETE ON message BEGIN
    INSERT INTO message_fts(message_fts, rowid, text, transcription)
    VALUES ('delete', old.rowid, old.text, '');
END;
CREATE TRIGGER message_fts_au AFTER UPDATE ON message BEGIN
    INSERT INTO message_fts(message_fts, rowid, text, transcription)
    VALUES ('delete', old.rowid, old.text, '');
    INSERT INTO message_fts(rowid, text, transcription)
    VALUES (new.rowid, new.text,
            (SELECT group_concat(transcription, ' ')
             FROM attachment WHERE message_id = new.id));
END;
```

- Queries use `message_fts MATCH ?` with bound parameters (never string
  interpolation — FTS5 query syntax injection is a real bug class).
- Tombstoned and expired messages are excluded at query time
  (`JOIN message ... WHERE is_tombstone = 0 AND (disappear_at IS NULL ...)`),
  AND physically removed from the index by the triggers on delete/expunge.
- **Privacy note:** the FTS index tokenizes message text — it is exactly as
  sensitive as the messages. Because it lives inside the encrypted file, its
  at-rest protection is identical. Anyone who can unlock the DB can read both;
  no additional exposure is introduced. Document this in code review so nobody
  "optimizes" the index into a plaintext sidecar later.
- Keep the FTS table out of backups' plaintext manifests (there are none —
  backups are whole-file ciphertext, FEATURES.md A46).

## 5. Operations

### 5.1 Disappearing-message sweep

`expungeDisappeared(now:)` runs:
- on every unlock,
- on a background processing task (BGProcessingTask, ~hourly),
- after every sync batch.

Implementation: one write transaction selecting expired IDs, deleting their
attachments (chunks + rows), deleting the messages (triggers clean FTS),
then `PRAGMA wal_checkpoint(TRUNCATE)` opportunistically. Returns the count.
The caller (not the store) destroys Keychain data keys for the attachments.

### 5.2 Backup & export

- **Whole-DB backup (A46):** `VACUUM INTO 'backup.db'` then re-key the copy
  with the backup key (`PRAGMA key` → `PRAGMA rekey`), or
  `sqlcipher_export`. Upload **only the ciphertext file**. The storage
  endpoint never sees a key.
- **Encrypted chat export (A16):** export is assembled from decrypted rows
  in memory, encrypted with the user-supplied passphrase (Argon2id →
  AES-256-GCM), and written directly to the share destination. The app must
  never write an intermediate plaintext file — stream encrypt.

### 5.3 Concurrency

- Single sqlite3 handle owned by the `SQLCipherAegisStore` actor. Actor
  isolation serializes all readers and writers — the Swift-native equivalent
  of the single `DatabaseQueue` in the original design. WAL is enabled for
  crash safety.
- `transaction(_:)` → `BEGIN IMMEDIATE` / `COMMIT` (`ROLLBACK` on error);
  nested calls use `SAVEPOINT`s. Note the documented semantic, shared with
  the in-memory implementation: atomicity holds for the work closure, but a
  non-transactional call from another task may interleave while the closure
  suspends. Callers needing isolation should put all related writes inside
  one `transaction(_:)`.

### 5.4 Corruption & recovery

- On `SQLITE_CORRUPT` / failed `PRAGMA key` verification: do NOT auto-delete
  the database. Surface "database unreadable" with options: retry, restore
  from encrypted backup (A46), or (explicit, double-confirmed) start fresh.
  Silent auto-wipe on corruption is how data-loss bugs become data-loss
  features.

## 6. Test contract (package test target)

`Packages/AegisStore/Tests/AegisStoreTests/SQLCipherStoreTests.swift` covers,
against a temp-file SQLCipher database:
1. ✅ Open with correct key succeeds; `PRAGMA cipher_version` returns a
   SQLCipher build string (guards against silently linking non-encrypted
   SQLite — the single most dangerous misconfiguration in this design).
2. ✅ Wrong key throws `.encryptionUnavailable` (and the file still opens
   with the right key afterwards).
3. ✅ Data survives close/reopen — the Phase 1 persistence requirement.
4. ✅ All six repository protocols: full CRUD + the error cases in
   `Repositories.swift` (conflict, notFound, invalidArgument).
5. ✅ Cascade deletes actually cascade (foreign keys ON).
6. ✅ FTS search finds message text and voice-note transcriptions; excludes
   tombstones and expired messages.
7. ✅ `expungeDisappeared` removes rows AND their FTS entries.
8. ✅ Snapshot/restore round-trip; newer snapshot versions rejected.
9. ✅ Transaction rollback on error; nested transactions flatten via
   savepoints.
10. ⏳ Migration v1→v2 (synthetic): not applicable until a v2 schema exists;
    migration idempotency is covered by the reopen tests.
11. ⏳ Duress PIN / decoy database: not implemented (see §2.1 hardening target).

## 7. Implementation status (as built)

| Area | State |
|---|---|
| Vendored SQLCipher amalgamation (`CSQLCipher` target) | ✅ Done |
| `SQLCipherConnection` (open/key/verify/migrate/exec/query) | ✅ Done |
| `DatabaseKeyManager` (Keychain-held 256-bit key) | ✅ Done |
| v1 schema + FTS5 + triggers + indexes (§3, §4) | ✅ Done |
| All six repository protocols | ✅ Done |
| `transaction(_:)` with savepoint nesting | ✅ Done |
| Snapshot/restore | ✅ Done |
| Factory wiring (`LiveServiceFactory` → SQLCipher store) | ✅ Done |
| Secure-Enclave/biometric KEK wrapping | ⏳ Hardening |
| Passphrase KDF unlock path | ⏳ Hardening |
| Duress PIN / decoy database | ⏳ Hardening |
| Explicit database re-key (`PRAGMA rekey`) | ⏳ Hardening |
| Whole-DB backup (`VACUUM INTO` + re-key) | ⏳ Hardening |

Nested model values (reactions, polls, ID arrays, consent maps) are stored
as JSON text columns — a deliberate trade documented in `StoreSchema.swift`.
Schema migrations are forward-only, each in a single transaction; on
failure the transaction rolls back and open throws `.migrationFailed`.
