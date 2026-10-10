// AegisStore — StoreSchema
//
// Normative v1 schema for the SQLCipher database. Columns mirror
// Models.swift 1:1; nested model values (reactions, polls, ID arrays,
// consent maps) are stored as JSON text columns. This is a deliberate
// trade: it keeps the model <-> row mapping total and version-tolerant
// without an ORM, and every JSON column is covered by round-trip tests.
//
// FTS5: the full-text index lives INSIDE the encrypted database file
// (never a sidecar) — its at-rest protection is identical to the messages
// themselves. Triggers keep it in sync, including voice-note
// transcriptions from the attachment table.

enum StoreSchema {
    /// Current schema version. Must match SQLCipherStoreDescriptor.schemaVersion.
    static let version = 2

    static let v1 = """
        CREATE TABLE IF NOT EXISTS schema_migrations(
          version INTEGER PRIMARY KEY,
          applied_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS conversation(
          id TEXT PRIMARY KEY,
          kind TEXT NOT NULL,
          network_policy TEXT NOT NULL,
          title TEXT,
          key_epoch INTEGER NOT NULL DEFAULT 0,
          disappearing_timer_seconds INTEGER,
          is_archived INTEGER NOT NULL DEFAULT 0,
          is_muted INTEGER NOT NULL DEFAULT 0,
          is_pinned INTEGER NOT NULL DEFAULT 0,
          read_receipts INTEGER NOT NULL DEFAULT 1,
          typing_indicators INTEGER NOT NULL DEFAULT 1,
          link_previews INTEGER NOT NULL DEFAULT 1,
          last_read_message_id TEXT,
          unread_count INTEGER NOT NULL DEFAULT 0,
          last_message_id TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS message(
          id TEXT PRIMARY KEY,
          conversation_id TEXT NOT NULL
            REFERENCES conversation(id) ON DELETE CASCADE,
          sender_id TEXT,
          is_sealed_sender INTEGER NOT NULL DEFAULT 1,
          direction TEXT NOT NULL,
          kind TEXT NOT NULL,
          text TEXT,
          reply_to TEXT,
          thread_root TEXT,
          edit_version INTEGER NOT NULL DEFAULT 0,
          edited_at REAL,
          is_tombstone INTEGER NOT NULL DEFAULT 0,
          tombstoned_at REAL,
          disappear_at REAL,
          scheduled_for REAL,
          delivery_state TEXT NOT NULL,
          sent_at REAL,
          delivered_at REAL,
          read_at REAL,
          secrecy_epoch INTEGER NOT NULL DEFAULT 0,
          reactions_json TEXT NOT NULL DEFAULT '[]',
          poll_json TEXT,
          attachment_ids_json TEXT NOT NULL DEFAULT '[]',
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS contact(
          id TEXT PRIMARY KEY,
          display_name TEXT NOT NULL,
          identity_key_fingerprint TEXT NOT NULL,
          verification_state TEXT NOT NULL,
          verified_at REAL,
          is_blocked INTEGER NOT NULL DEFAULT 0,
          is_favorite INTEGER NOT NULL DEFAULT 0,
          notes TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_membership(
          conversation_id TEXT NOT NULL
            REFERENCES conversation(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL,
          role TEXT NOT NULL,
          joined_at REAL NOT NULL,
          added_by TEXT,
          joined_at_epoch INTEGER NOT NULL DEFAULT 0,
          updated_at REAL NOT NULL,
          PRIMARY KEY (conversation_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS attachment(
          id TEXT PRIMARY KEY,
          message_id TEXT NOT NULL
            REFERENCES message(id) ON DELETE CASCADE,
          conversation_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          file_name TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          byte_count INTEGER NOT NULL,
          chunk_size INTEGER NOT NULL,
          chunk_count INTEGER NOT NULL,
          bytes_transferred INTEGER NOT NULL DEFAULT 0,
          transfer_state TEXT NOT NULL,
          remote_locator TEXT,
          local_relative_path TEXT,
          keychain_key_id TEXT NOT NULL,
          plaintext_sha256 BLOB,
          transcription TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS call_record(
          id TEXT PRIMARY KEY,
          conversation_id TEXT NOT NULL
            REFERENCES conversation(id) ON DELETE CASCADE,
          kind TEXT NOT NULL,
          direction TEXT NOT NULL,
          participants_json TEXT NOT NULL DEFAULT '[]',
          was_answered INTEGER NOT NULL DEFAULT 0,
          started_at REAL NOT NULL,
          ended_at REAL,
          recording_consent_json TEXT NOT NULL DEFAULT '{}',
          local_recording_path TEXT,
          created_at REAL NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
          text,
          transcription,
          content='message',
          content_rowid='rowid',
          tokenize='unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS message_fts_ai AFTER INSERT ON message BEGIN
          INSERT INTO message_fts(rowid, text, transcription)
          VALUES (new.rowid, new.text,
                  (SELECT group_concat(transcription, ' ')
                   FROM attachment WHERE message_id = new.id));
        END;

        CREATE TRIGGER IF NOT EXISTS message_fts_ad AFTER DELETE ON message BEGIN
          INSERT INTO message_fts(message_fts, rowid, text, transcription)
          VALUES ('delete', old.rowid, old.text, '');
        END;

        CREATE TRIGGER IF NOT EXISTS message_fts_au AFTER UPDATE ON message BEGIN
          INSERT INTO message_fts(message_fts, rowid, text, transcription)
          VALUES ('delete', old.rowid, old.text, '');
          INSERT INTO message_fts(rowid, text, transcription)
          VALUES (new.rowid, new.text,
                  (SELECT group_concat(transcription, ' ')
                   FROM attachment WHERE message_id = new.id));
        END;

        -- Keep the FTS index in sync when voice-note transcriptions change.
        -- Touching the parent message row re-fires message_fts_au, which
        -- rebuilds the entry with the current transcription subquery.
        CREATE TRIGGER IF NOT EXISTS attachment_fts_ai AFTER INSERT ON attachment BEGIN
          UPDATE message SET updated_at = updated_at WHERE id = new.message_id;
        END;

        CREATE TRIGGER IF NOT EXISTS attachment_fts_au AFTER UPDATE OF transcription ON attachment BEGIN
          UPDATE message SET updated_at = updated_at WHERE id = new.message_id;
        END;

        CREATE TRIGGER IF NOT EXISTS attachment_fts_ad AFTER DELETE ON attachment BEGIN
          UPDATE message SET updated_at = updated_at WHERE id = old.message_id;
        END;

        CREATE INDEX IF NOT EXISTS idx_message_conv_created
          ON message(conversation_id, created_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_message_disappear
          ON message(disappear_at);
        CREATE INDEX IF NOT EXISTS idx_attachment_message
          ON attachment(message_id);
        CREATE INDEX IF NOT EXISTS idx_membership_conv
          ON group_membership(conversation_id);
        CREATE INDEX IF NOT EXISTS idx_call_conv_started
          ON call_record(conversation_id, started_at DESC);
        """

    /// v2 delta: durable Double Ratchet session snapshots, keyed by peer
    /// fingerprint hex. Applied to existing v1 databases by the migration
    /// chain in SQLCipherConnection.migrate(); fresh databases get v1+v2.
    /// The snapshot BLOB is opaque to the store (versioned by AegisCrypto).
    static let v2 = """
        CREATE TABLE IF NOT EXISTS ratchet_session(
          fingerprint TEXT PRIMARY KEY,
          snapshot BLOB NOT NULL,
          updated_at REAL NOT NULL
        );
        """
}
