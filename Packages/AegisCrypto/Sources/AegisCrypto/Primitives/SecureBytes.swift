// SecureBytes — a heap buffer for secret key material that is wiped on
// release.
//
// Honest limits, stated up front:
//  - Swift has no `mlock`/`madvise` equivalent and ARC may leave copies of
//    bytes in freed heap pages. This is strictly better than leaving key
//    bytes in a `Data` that is never wiped, but it is NOT a guarantee that
//    no copy survives in memory.
//  - `toData()` copies are not wiped; keep their lifetimes as short as
//    possible and prefer the `withUnsafeBytes` accessors.
//  - Long-lived identity keys should additionally be persisted via the
//    Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly) by the store
//    layer; this type only governs in-memory hygiene.
//
// TODO(security-audit): evaluate guard pages / mlock'd regions for
// long-lived keys, and audit every `toData()` call site for lifetime.

import Foundation

public final class SecureBytes {
    private let base: UnsafeMutablePointer<UInt8>
    public let count: Int

    public init(count: Int) {
        precondition(count >= 0, "SecureBytes count must be non-negative")
        self.count = count
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        pointer.initialize(repeating: 0, count: count)
        self.base = pointer
    }

    public convenience init(_ data: Data) {
        self.init(count: data.count)
        data.withUnsafeBytes { raw in
            guard data.count > 0,
                  let src = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
            else { return }
            base.update(from: src, count: data.count)
        }
    }

    deinit {
        // Best-effort wipe. A sufficiently motivated memory forensics
        // attacker may still find copies; see the file header.
        for i in 0 ..< count {
            base[i] = 0
        }
        base.deallocate()
    }

    /// Scoped read access to the bytes.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// Scoped read-write access to the bytes.
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: base, count: count))
    }

    /// Overwrites the buffer with zeros immediately. Idempotent.
    public func zero() {
        for i in 0 ..< count {
            base[i] = 0
        }
    }

    /// Copies the bytes into a fresh `Data`. The copy is NOT wiped — keep
    /// its lifetime short and zero it if it lands in another `SecureBytes`.
    public func toData() -> Data {
        Data(bytes: base, count: count)
    }
}
