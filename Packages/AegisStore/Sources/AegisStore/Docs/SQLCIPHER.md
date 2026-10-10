# AegisStore — SQLCipher Integration Design

**Status:** Normative design for the production persistence adapter.
The in-memory implementation (`InMemoryStore.swift`) is the behavioral
reference; this document specifies how the SQLCipher-backed adapter must
be built in the Xcode app target. Follow it exactly — deviations need a
written rationale and review.

## 1. Dependency choice

- **GRDB.swift** via Swift Package Manager
  (`https://github.com/groue/GRDB.swift`), with the SQLCipher
  configuration enabled (`SQLITE_HAS_CODEC`).
- Rationale: GRDB gives us `DatabaseQueue` (single-writer serialization),
  migrations, FTS5 support, and value observation — without hand-rolled
  sqlite3 C calls. SQLCipher provides the encryption; we never touch raw
  sqlite3.
- Alternative considered and rejected: raw `sqlite3` + SQLCipher amalgamation
  — too much unsafe surface for key handling and migrations.

**Xcode integration steps:**
1. In Xcode: File → Add Package Dependencies → GRDB.swift URL.
2. Enable the SQLCipher build configuration per GRDB's SQLCipher
   documentation (custom `SQLCipher` product / build flags — follow the
   GRDB.swift SQLCipher guide for the Xcode version in use; verify with a
   test that `PRAGMA cipher_version;` returns a SQLCipher version string).
3. Create `SQLCipherAegisStore` (final class) in the app target, conforming
   to `AegisStore` and the six repository protocols (see
   `Repositories.swift: SQLCipherStoreDescriptor`).
4. Serialize ALL database access through one `DatabaseQueue`. No second
   queue, no direct sqlite3 handles, no WAL-mode reader threads. (WAL is
   still enabled for crash safety, but readers go through the queue.)

## 2. Key management

### 2.1 Key hierarchy

```
User secret (passphrase OR Secure Enclave biometric)
        │  KDF / unwrap
        ▼
KEK (256-bit, memory-only, never persisted)
        │  AES-256-GCM wrap
        ▼
DB key (256-bit random, generated once at onboarding)
        │  stored WRAPPED in Keychain
        ▼
PRAGMA key = "x'<hex of unwrapped DB key>'"   (SQLCipher)
```

- **DB key generation:** 32 bytes from `SecRandomCopyBytes` at first launch.
  Generated once, never rotated except on explicit "re-key database" action.
- **KEK derivation, passphrase path:** Argon2id (memory 64 MiB, iterations 3,
  parallelism 4, output 32 bytes), salt 16 bytes stored alongside the wrapped
  key in Keychain. (Use `swift-crypto`'s Argon2 when available; otherwise
  CryptoKit PBKDF2-SHA256 with 600,000 iterations as fallback — document which
  is in use.)
- **KEK derivation, Secure Enclave path (preferred):** generate a P-256 key
  in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`,
  `kSecAttrAccessControl` with `.biometryAny`, `accessibleAfterFirstUnlockThisDeviceOnly`).
  Wrap the DB key with ECIES-style hybrid encryption to that key
  (ephemeral X25519 → HKDF → AES-GCM). Unlock requires a successful
  `LAContext.evaluatePolicy` biometric prompt; on biometric failure, fall
  back to the passphrase path (both wrappings are stored; either unwraps).
- **Keychain storage:** wrapped DB key + salt + algorithm identifiers in
  `kSecClassGenericPassword`, `accessibleAfterFirstUnlockThisDeviceOnly`,
  `kSecAttrSynchronizable = false` (never iCloud-sync key material).
- **In-memory hygiene:** unwrap → hex → `PRAGMA key` → immediately zero the
  buffers (`memset_s`). Keep the unwrapped key only in the GRDB configuration
  closure's scope; never in a property.

### 2.2 Open / unlock flow

1. App requests unlock (biometric prompt or passphrase entry).
2. Unwrap DB key via the chosen path. **Any failure → throw
   `.encryptionUnavailable`, show "could not unlock", and STOP.**
   There is no plaintext fallback, no "continue without encryption."
3. `DatabaseQueue(path:)` → `PRAGMA key = "x'...'"` → `PRAGMA cipher_page_size = 4096`
   → verify with `PRAGMA cipher_version;` and a read of `schema_migrations`.
4. Run pending migrations (Section 3), then enable foreign keys
   (`PRAGMA foreign_keys = ON`).

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

- Single `DatabaseQueue`. Readers and writers serialize; with WAL, reads
  don't block writes at the SQLite level, but all access still funnels
  through the queue for key-safety and migration-safety.
- `transaction(_:)` → `dbQueue.write { … }`; nested calls use savepoints
  (`dbQueue.writeWithoutTransaction` is forbidden in app code — lint for it).

### 5.4 Corruption & recovery

- On `SQLITE_CORRUPT` / failed `PRAGMA key` verification: do NOT auto-delete
  the database. Surface "database unreadable" with options: retry, restore
  from encrypted backup (A46), or (explicit, double-confirmed) start fresh.
  Silent auto-wipe on corruption is how data-loss bugs become data-loss
  features.

## 6. Test contract (app target)

Before the SQLCipher adapter ships, the app test target must cover, against
a temp-file SQLCipher database:
1. Open with correct key succeeds; wrong key throws `.encryptionUnavailable`
   (and the file is not modified).
2. All six repository protocols: full CRUD + the error cases in
   `Repositories.swift` (conflict, notFound, invalidArgument).
3. Cascade deletes actually cascade (foreign keys ON).
4. FTS search finds message text and voice-note transcriptions; excludes
   tombstones and expired messages.
5. `expungeDisappeared` removes rows AND their FTS entries.
6. Migration v1→v2 (a synthetic test migration) preserves data.
7. Duress PIN opens the decoy DB; real DB mtime unchanged.
8. `PRAGMA cipher_version;` returns a SQLCipher build (guards against
   silently linking non-encrypted SQLite — the single most dangerous
   misconfiguration in this design).
