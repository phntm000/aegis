// BLAKE2b (RFC 7693), pure Swift, variable-length output.
//
// Needed as the compression core of Argon2id (RFC 9106 builds everything —
// the H0 pre-hash, the H' variable-length hash, and thereby the whole
// memory-hard function — on top of BLAKE2b). One-shot API only; Argon2
// never needs streaming.

import Foundation

enum Blake2b {
    // MARK: - Constants

    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    // MARK: - Public API

    /// One-shot BLAKE2b with output length `digestSize` (1…64 bytes).
    static func hash(digestSize: Int, data: Data) -> Data {
        precondition(digestSize >= 1 && digestSize <= 64, "BLAKE2b digest size out of range")
        var h = iv
        // Parameter block: digest_length = nn, key_length = 0, fanout = 1, depth = 1.
        h[0] ^= 0x01010000 ^ UInt64(digestSize)

        var t: UInt64 = 0 // bytes compressed so far
        var offset = data.startIndex
        // All but the last block go through unflagged…
        while data.distance(from: offset, to: data.endIndex) > 128 {
            let block = data[offset ..< data.index(offset, offsetBy: 128)]
            t &+= 128
            h = compress(h: h, block: block, bytesCompressed: t, isLast: false)
            offset = data.index(offset, offsetBy: 128)
        }
        // …the last block (possibly empty) is flagged.
        let last = data[offset...]
        t &+= UInt64(last.count)
        h = compress(h: h, block: last, bytesCompressed: t, isLast: true)

        var out = Data()
        out.reserveCapacity(64)
        for word in h {
            var little = word.littleEndian
            withUnsafeBytes(of: &little) { out.append(contentsOf: $0) }
        }
        return out.prefix(digestSize)
    }

    // MARK: - Compression

    private static func compress(h: [UInt64], block: Data.SubSequence, bytesCompressed t: UInt64, isLast: Bool) -> [UInt64] {
        var m = [UInt64](repeating: 0, count: 16)
        var bi = block.startIndex
        for i in 0 ..< 16 {
            var word: UInt64 = 0
            for j in 0 ..< 8 {
                if bi < block.endIndex {
                    word |= UInt64(block[bi]) << (8 * j)
                    bi = block.index(after: bi)
                }
            }
            m[i] = word
        }

        var v = h + iv
        v[12] ^= t
        // t fits in 64 bits for any real input; high word stays zero.
        if isLast {
            v[14] ^= UInt64.max
        }

        for r in 0 ..< 12 {
            let s = sigma[r]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        var hOut = h
        for i in 0 ..< 8 {
            hOut[i] ^= v[i] ^ v[i + 8]
        }
        return hOut
    }

    private static func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotateRight(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d]
        v[b] = rotateRight(v[b] ^ v[c], 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotateRight(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotateRight(v[b] ^ v[c], 63)
    }

    private static func rotateRight(_ x: UInt64, _ n: Int) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }
}
