// AegisStore — SQLCipherConnection
//
// A thin, non-Sendable wrapper around a single sqlite3 handle. All use is
// confined to `SQLCipherAegisStore`'s actor isolation, which is the only
// serialization this connection needs (one handle, one logical thread of
// execution — exactly the model SQLCipher documents as safe).
//
// Responsibilities:
// - open / apply `PRAGMA key` / verify the key is correct (fail closed)
// - run schema migrations
// - prepared-statement exec/query with bound parameters (never string
//   interpolation of values)
// - translate SQLite result codes into AegisStoreError

import Foundation
import CSQLCipher

/// A bound SQL value.
enum SQLValue: Sendable {
    case null
    case int(Int64)
    case real(Double)
    case text(String)
    case blob(Data)
}

/// A decoded row: column name -> value.
typealias SQLRow = [String: SQLValue]

final class SQLCipherConnection {
    private var db: OpaquePointer?

    /// Opens (creating if needed) the database at `path` and unlocks it
    /// with `key`. Throws `.encryptionUnavailable` when the key is wrong or
    /// the file is not a SQLCipher database. Never creates plaintext.
    init(path: String, key: [UInt8]) throws {
        var handle: OpaquePointer?
        let openFlags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let rc = path.withCString { cPath in
            sqlite3_open_v2(cPath, &handle, openFlags, nil)
        }
        guard rc == SQLITE_OK, let handle else {
            if let handle { sqlite3_close(handle) }
            throw AegisStoreError.ioError(
                "sqlite3_open failed: \(SQLCipherConnection.message(for: handle))")
        }
        self.db = handle
        do {
            try applyKey(key)
            try verifyCipherBuild()
            try verifyKey()
            try configure()
            try migrate()
        } catch {
            sqlite3_close(handle)
            self.db = nil
            throw error
        }
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    // MARK: - Key

    private func applyKey(_ key: [UInt8]) throws {
        // SQLCipher takes the raw key as a hex literal: x'...'.
        var mutable = key
        defer { DatabaseKeyManager.zero(&mutable) }
        let hex = mutable.map { String(format: "%02x", $0) }.joined()
        // Zero the hex string's backing as well on scope exit is not
        // possible for String; the window is minimal and documented.
        try execRaw("PRAGMA key = \"x'\(hex)'\";")
    }

    /// Guards against silently linking non-encrypted SQLite: the single
    /// most dangerous misconfiguration in this design (SQLCIPHER.md §6.8).
    private func verifyCipherBuild() throws {
        let rows = try queryRaw("PRAGMA cipher_version;")
        let version = rows.first?.values.first.flatMap { value -> String? in
            if case .text(let s) = value { return s }
            return nil
        }
        guard let version, !version.isEmpty else {
            throw AegisStoreError.encryptionUnavailable(
                "PRAGMA cipher_version returned nothing: not a SQLCipher build")
        }
    }

    /// Proves the key is correct by reading. With a wrong key SQLCipher
    /// reports "file is not a database" on first read — that is the signal.
    private func verifyKey() throws {
        do {
            _ = try queryRaw("SELECT count(*) FROM sqlite_master;")
        } catch let error as AegisStoreError {
            if case .encryptionUnavailable = error { throw error }
            throw AegisStoreError.encryptionUnavailable(
                "database key rejected or file unreadable: \(error)")
        }
    }

    private func configure() throws {
        // Crash safety + hygiene. foreign_keys is per-connection and OFF by
        // default in SQLite — forgetting it silently breaks cascades.
        try execRaw("PRAGMA busy_timeout = 5000;")
        try execRaw("PRAGMA journal_mode = WAL;")
        try execRaw("PRAGMA foreign_keys = ON;")
        try execRaw("PRAGMA secure_delete = ON;")
    }

    // MARK: - Exec / query

    /// Runs a statement with bound parameters. No result rows expected.
    func exec(_ sql: String, _ args: [SQLValue] = []) throws {
        var stmt: OpaquePointer?
        defer { if let stmt { sqlite3_finalize(stmt) } }
        try prepare(sql, args: args, stmt: &stmt)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else {
            throw classifiedError(sql: sql)
        }
    }

    /// Runs a query with bound parameters and returns all rows.
    func query(_ sql: String, _ args: [SQLValue] = []) throws -> [SQLRow] {
        var stmt: OpaquePointer?
        defer { if let stmt { sqlite3_finalize(stmt) } }
        try prepare(sql, args: args, stmt: &stmt)
        var rows: [SQLRow] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                rows.append(readRow(stmt!))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw classifiedError(sql: sql)
            }
        }
        return rows
    }

    func changes() -> Int {
        guard let db else { return 0 }
        return Int(sqlite3_changes(db))
    }

    // MARK: - Private

    /// Executes a raw SQL script, running EVERY statement it contains.
    ///
    /// Unlike ``exec(_:_:)`` (which prepares a single statement via
    /// `sqlite3_prepare_v2` and silently drops the rest), this uses
    /// `sqlite3_exec` so multi-statement schema scripts — including the
    /// FTS5 triggers in ``StoreSchema/v1``, whose `BEGIN…END` bodies contain
    /// inner semicolons — run in full. No bound parameters are supported.
    private func execRaw(_ sql: String) throws {
        guard let db else {
            throw AegisStoreError.ioError("database handle is closed")
        }
        let rc = sql.withCString { cSQL in
            sqlite3_exec(db, cSQL, nil, nil, nil)
        }
        guard rc == SQLITE_OK else {
            throw classifiedError(sql: sql)
        }
    }

    private func queryRaw(_ sql: String) throws -> [SQLRow] {
        try query(sql)
    }

    private func prepare(
        _ sql: String,
        args: [SQLValue],
        stmt: inout OpaquePointer?
    ) throws {
        guard let db else {
            throw AegisStoreError.ioError("database handle is closed")
        }
        let rc = sql.withCString { cSQL in
            sqlite3_prepare_v2(db, cSQL, -1, &stmt, nil)
        }
        guard rc == SQLITE_OK, stmt != nil else {
            throw classifiedError(sql: sql)
        }
        for (index, arg) in args.enumerated() {
            try bind(stmt!, index: Int32(index + 1), value: arg)
        }
    }

    private func bind(_ stmt: OpaquePointer, index: Int32, value: SQLValue) throws {
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        let rc: Int32
        switch value {
        case .null:
            rc = sqlite3_bind_null(stmt, index)
        case .int(let v):
            rc = sqlite3_bind_int64(stmt, index, v)
        case .real(let v):
            rc = sqlite3_bind_double(stmt, index, v)
        case .text(let v):
            rc = v.withCString { ptr in
                sqlite3_bind_text(stmt, index, ptr, -1, transient)
            }
        case .blob(let v):
            rc = v.withUnsafeBytes { buffer in
                sqlite3_bind_blob(
                    stmt, index, buffer.baseAddress, Int32(v.count), transient)
            }
        }
        guard rc == SQLITE_OK else {
            throw AegisStoreError.ioError("bind failed: \(Self.message(for: db))")
        }
    }

    private func readRow(_ stmt: OpaquePointer) -> SQLRow {
        var row: SQLRow = [:]
        let count = sqlite3_column_count(stmt)
        for i in 0..<count {
            let name = String(cString: sqlite3_column_name(stmt, i))
            let value: SQLValue
            switch sqlite3_column_type(stmt, i) {
            case SQLITE_INTEGER:
                value = .int(sqlite3_column_int64(stmt, i))
            case SQLITE_FLOAT:
                value = .real(sqlite3_column_double(stmt, i))
            case SQLITE_TEXT:
                value = .text(String(cString: sqlite3_column_text(stmt, i)))
            case SQLITE_BLOB:
                let bytes = sqlite3_column_blob(stmt, i)
                let count = Int(sqlite3_column_bytes(stmt, i))
                if let bytes, count > 0 {
                    value = .blob(Data(bytes: bytes, count: count))
                } else {
                    value = .blob(Data())
                }
            default:
                value = .null
            }
            row[name] = value
        }
        return row
    }

    private func classifiedError(sql: String) -> AegisStoreError {
        guard let db else { return AegisStoreError.ioError("no handle: \(sql)") }
        let code = sqlite3_errcode(db)
        let message = Self.message(for: db)
        // Primary result code only (mask off extended bits).
        switch code & 0xFF {
        case SQLITE_CONSTRAINT:
            return .conflict("constraint violated: \(message)")
        case SQLITE_NOTADB:
            return .encryptionUnavailable(
                "wrong key or not a SQLCipher database: \(message)")
        case SQLITE_CORRUPT:
            return .ioError("database corrupt: \(message)")
        default:
            return .ioError("sqlite error \(code): \(message) [\(sql)]")
        }
    }

    private static func message(for db: OpaquePointer?) -> String {
        guard let db, let cMsg = sqlite3_errmsg(db) else { return "unknown" }
        return String(cString: cMsg)
    }

    // MARK: - Schema & migrations

    private func currentVersion() throws -> Int {
        let rows = try queryRaw("PRAGMA user_version;")
        if case .int(let v) = rows.first?.values.first { return Int(v) }
        return 0
    }

    private func setVersion(_ v: Int) throws {
        try execRaw("PRAGMA user_version = \(v);")
    }

    private func migrate() throws {
        let version = try currentVersion()
        if version < 1 {
            try exec("BEGIN IMMEDIATE;")
            do {
                try execRaw(StoreSchema.v1)
                try execRaw(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (1, \(Date().timeIntervalSince1970));"
                )
                try setVersion(1)
                try exec("COMMIT;")
            } catch {
                try? exec("ROLLBACK;")
                throw AegisStoreError.migrationFailed("v1 migration failed: \(error)")
            }
        }
        // Future migrations chain here: if version < 2 { ... }
        if version < 2 {
            try exec("BEGIN IMMEDIATE;")
            do {
                try execRaw(StoreSchema.v2)
                try execRaw(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (2, \(Date().timeIntervalSince1970));"
                )
                try setVersion(2)
                try exec("COMMIT;")
            } catch {
                try? exec("ROLLBACK;")
                throw AegisStoreError.migrationFailed("v2 migration failed: \(error)")
            }
        }
        if version < 3 {
            try exec("BEGIN IMMEDIATE;")
            do {
                try execRaw(StoreSchema.v3)
                try execRaw(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (3, \(Date().timeIntervalSince1970));"
                )
                try setVersion(3)
                try exec("COMMIT;")
            } catch {
                try? exec("ROLLBACK;")
                throw AegisStoreError.migrationFailed("v3 migration failed: \(error)")
            }
        }
    }
}

// MARK: - Value conveniences

extension SQLValue {
    var string: String? {
        if case .text(let s) = self { return s }
        return nil
    }
    var int: Int64? {
        if case .int(let v) = self { return v }
        return nil
    }
    var real: Double? {
        if case .real(let v) = self { return v }
        return nil
    }
    var data: Data? {
        if case .blob(let d) = self { return d }
        return nil
    }
    var isNull: Bool {
        if case .null = self { return true }
        return false
    }
}

func sqlBool(_ b: Bool) -> SQLValue { .int(b ? 1 : 0) }

func sqlDate(_ date: Date?) -> SQLValue {
    guard let date else { return .null }
    return .real(date.timeIntervalSince1970)
}

extension SQLRow {
    func string(_ column: String) -> String? { self[column]?.string }
    func int(_ column: String) -> Int64? { self[column]?.int }
    func real(_ column: String) -> Double? { self[column]?.real }
    func data(_ column: String) -> Data? { self[column]?.data }
    func bool(_ column: String) -> Bool { (self[column]?.int ?? 0) != 0 }
    func date(_ column: String) -> Date? {
        guard let t = self[column]?.real else { return nil }
        return Date(timeIntervalSince1970: t)
    }
    /// Required non-null text column; throws `.ioError` on schema violation.
    func reqString(_ column: String) throws -> String {
        guard let s = string(column) else {
            throw AegisStoreError.ioError("missing column \(column)")
        }
        return s
    }
    func reqDate(_ column: String) throws -> Date {
        guard let d = date(column) else {
            throw AegisStoreError.ioError("missing column \(column)")
        }
        return d
    }
}
