// Argon2id (RFC 9106) — pure-Swift memory-hard password hashing.
//
// Used to derive the key-encryption key for identity backups from a user
// passphrase. Why Argon2id and not PBKDF2: PBKDF2 is only CPU-hard, so an
// attacker with GPUs/ASICs/FPGAs gets a massive cost advantage trying
// passphrases offline against a stolen backup file. Argon2id is
// *memory*-hard: every guess requires a large RAM working set, which
// dedicated hardware cannot cheaply parallelize. See docs/CRYPTO.md.
//
// This is a direct port of the reference algorithm, validated against the
// RFC 9106 §5.3 test vector (see `Argon2Tests.testRFC9106Vector`) via a
// pure-Python implementation that was itself cross-checked against the RFC
// text and `argon2-cffi` byte-for-byte.
//
// Performance: lanes are filled sequentially (no threading yet), so expect
// on the order of seconds for the default 64 MiB parameters on a phone —
// fine for an infrequent backup unlock, and documented as a tuning knob.
// TODO(security-audit): parallelize lane filling (p=4) and re-tune defaults;
// verify constant-time behavior of the data-dependent addressing phase is
// not a practical side channel on iOS (Argon2id's hybrid addressing is the
// standard mitigation; cache-timing attacks against the data-dependent
// half remain a theoretical concern on shared hardware).

import CryptoKit
import Foundation

/// Argon2id password-based key derivation (RFC 9106, version 0x13).
public struct Argon2id: PassphraseKDF {
    public static let version: UInt32 = 0x13

    public let memoryKiB: Int
    public let iterations: Int
    public let parallelism: Int

    /// Default parameters: RFC 9106's memory-constrained recommendation
    /// (m = 64 MiB, t = 3) with parallelism 1, since this implementation
    /// fills lanes sequentially.
    public static let `default` = Argon2id(memoryKiB: 65_536, iterations: 3, parallelism: 1)

    public init(memoryKiB: Int, iterations: Int, parallelism: Int) {
        precondition(memoryKiB >= 8 * parallelism, "Argon2 memory too small for parallelism")
        precondition(iterations >= 1, "Argon2 iterations must be >= 1")
        precondition(parallelism >= 1, "Argon2 parallelism must be >= 1")
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
    }

    // MARK: PassphraseKDF

    public var identifier: String { "argon2id" }

    public var parametersDescription: String {
        "m=\(memoryKiB),t=\(iterations),p=\(parallelism),v=19"
    }

    public func serializedParameters() -> Data {
        var encoder = WireEncoder()
        encoder.u32(UInt32(memoryKiB))
        encoder.u32(UInt32(iterations))
        encoder.u8(UInt8(parallelism))
        return encoder.data
    }

    public static func parameters(serialized data: Data) throws -> Argon2id {
        var decoder = WireDecoder(data)
        let m = Int(try decoder.u32())
        let t = Int(try decoder.u32())
        let p = Int(try decoder.u8())
        try decoder.expectEnd()
        return Argon2id(memoryKiB: m, iterations: t, parallelism: p)
    }

    public func deriveKey(password: SecureBytes, salt: Data, outputLength: Int) throws -> SymmetricKey {
        guard outputLength > 0, outputLength <= 1 << 20 else {
            throw AegisCryptoError.kdfFailed("invalid output length")
        }
        guard salt.count >= 8 else {
            throw AegisCryptoError.kdfFailed("salt too short")
        }
        let tag = try Self.hash(
            password: password.toData(),
            salt: salt,
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism,
            tagLength: outputLength
        )
        return SymmetricKey(data: tag)
    }

    // MARK: - Core (exposed for tests)

    /// Raw Argon2id. Matches RFC 9106 exactly, including the `secret` and
    /// `associatedData` inputs (unused by key backup, exercised by tests).
    static func hash(
        password: Data,
        salt: Data,
        secret: Data = Data(),
        associatedData: Data = Data(),
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        tagLength: Int
    ) throws -> Data {
        let lanes = parallelism
        // m' — total blocks, rounded down to a multiple of 4*lanes.
        let mPrime = 4 * lanes * (memoryKiB / (4 * lanes))
        let laneLength = mPrime / lanes
        let segmentLength = laneLength / 4
        let type: UInt32 = 2 // Argon2id

        let h0 = initialHash(
            parallelism: lanes, tagLength: tagLength, memoryKiB: memoryKiB,
            iterations: iterations, version: version, type: type,
            password: password, salt: salt, secret: secret, associatedData: associatedData
        )

        // Flat memory: lanes × laneLength blocks × 128 words.
        var memory = [UInt64](repeating: 0, count: lanes * laneLength * 128)
        func blockBase(_ lane: Int, _ block: Int) -> Int { (lane * laneLength + block) * 128 }
        func readBlock(_ lane: Int, _ block: Int) -> [UInt64] {
            let base = blockBase(lane, block)
            return Array(memory[base ..< base + 128])
        }
        func writeBlock(_ lane: Int, _ block: Int, _ words: [UInt64]) {
            let base = blockBase(lane, block)
            memory.replaceSubrange(base ..< base + 128, with: words)
        }

        // Initial blocks B[i][0], B[i][1].
        for lane in 0 ..< lanes {
            writeBlock(lane, 0, wordsFromBytes(hPrime(outputLength: 1024, input: h0 + u32le(0) + u32le(UInt32(lane)))))
            writeBlock(lane, 1, wordsFromBytes(hPrime(outputLength: 1024, input: h0 + u32le(1) + u32le(UInt32(lane)))))
        }

        let zeroBlock = [UInt64](repeating: 0, count: 128)

        for pass in 0 ..< iterations {
            for slice in 0 ..< 4 {
                for lane in 0 ..< lanes {
                    let dataIndependent = (pass == 0 && slice < 2)
                    let start = (pass == 0 && slice == 0) ? 2 : 0

                    var inputBlock: [UInt64] = zeroBlock
                    var addressBlock: [UInt64] = zeroBlock
                    var addressValid = false
                    if dataIndependent {
                        inputBlock = [UInt64](repeating: 0, count: 128)
                        inputBlock[0] = UInt64(pass)
                        inputBlock[1] = UInt64(lane)
                        inputBlock[2] = UInt64(slice)
                        inputBlock[3] = UInt64(mPrime)
                        inputBlock[4] = UInt64(iterations)
                        inputBlock[5] = UInt64(type)
                        inputBlock[6] = 0 // counter, incremented by nextAddresses
                        if pass == 0 && slice == 0 {
                            // Pre-generate: covers positions k = 2..127.
                            addressBlock = nextAddresses(inputBlock: &inputBlock, zero: zeroBlock)
                            addressValid = true
                        }
                    }

                    for k in start ..< segmentLength {
                        let j = slice * segmentLength + k
                        let pseudo: UInt64
                        if dataIndependent {
                            if k % 128 == 0 && (k != 0 || !(pass == 0 && slice == 0)) {
                                addressBlock = nextAddresses(inputBlock: &inputBlock, zero: zeroBlock)
                                addressValid = true
                            }
                            guard addressValid else {
                                throw AegisCryptoError.kdfFailed("address block unavailable")
                            }
                            pseudo = addressBlock[k % 128]
                        } else {
                            pseudo = readBlock(lane, (j - 1 + laneLength) % laneLength)[0]
                        }

                        let j1 = UInt32(truncatingIfNeeded: pseudo)
                        let j2 = UInt32(truncatingIfNeeded: pseudo >> 32)
                        var refLane = Int(j2) % lanes
                        if pass == 0 && slice == 0 {
                            refLane = lane // cannot reference other lanes yet
                        }
                        let refIndex = indexAlpha(
                            pass: pass, slice: slice, index: k,
                            laneLength: laneLength, segmentLength: segmentLength,
                            j1: j1, sameLane: refLane == lane
                        )

                        let prevBlock = readBlock(lane, (j - 1 + laneLength) % laneLength)
                        let refBlock = readBlock(refLane, refIndex)
                        var newBlock = compressionG(prevBlock, refBlock)
                        if pass > 0 {
                            let old = readBlock(lane, j)
                            newBlock = xorWords(newBlock, old)
                        }
                        writeBlock(lane, j, newBlock)
                    }
                }
            }
        }

        // Final block: XOR of the last column.
        var final = [UInt64](repeating: 0, count: 128)
        for lane in 0 ..< lanes {
            final = xorWords(final, readBlock(lane, laneLength - 1))
        }
        return hPrime(outputLength: tagLength, input: bytesFromWords(final))
    }

    // MARK: - Building blocks

    /// H0 pre-hash: BLAKE2b-64 over the parameter block (RFC 9106 §3.2).
    static func initialHash(
        parallelism: Int, tagLength: Int, memoryKiB: Int, iterations: Int,
        version: UInt32, type: UInt32,
        password: Data, salt: Data, secret: Data, associatedData: Data
    ) -> Data {
        var input = Data()
        for v in [UInt32(parallelism), UInt32(tagLength), UInt32(memoryKiB), UInt32(iterations), version, type] {
            input.append(u32le(v))
        }
        for s in [password, salt, secret, associatedData] {
            input.append(u32le(UInt32(s.count)))
            input.append(s)
        }
        return Blake2b.hash(digestSize: 64, data: input)
    }

    /// Variable-length hash H' (RFC 9106 §3.3).
    static func hPrime(outputLength: Int, input: Data) -> Data {
        if outputLength <= 64 {
            return Blake2b.hash(digestSize: outputLength, data: u32le(UInt32(outputLength)) + input)
        }
        let r = (outputLength + 31) / 32 - 2
        var out = Data()
        var v = Data()
        for i in 0 ..< r {
            v = (i == 0)
                ? Blake2b.hash(digestSize: 64, data: u32le(UInt32(outputLength)) + input)
                : Blake2b.hash(digestSize: 64, data: v)
            out.append(v.prefix(32))
        }
        out.append(Blake2b.hash(digestSize: outputLength - 32 * r, data: v))
        return out
    }

    /// The compression function G: R = X^Y, Z = P(R), output = Z^R, where P
    /// applies the BlaMka permutation to 8 consecutive-word groups then 8
    /// strided groups (RFC 9106 §3.5).
    static func compressionG(_ x: [UInt64], _ y: [UInt64]) -> [UInt64] {
        precondition(x.count == 128 && y.count == 128)
        let r = xorWords(x, y)
        var z = r
        for i in 0 ..< 8 {
            pRound(&z, indices: Array(16 * i ..< 16 * i + 16))
        }
        for i in 0 ..< 8 {
            var idx: [Int] = []
            idx.reserveCapacity(16)
            for k in stride(from: 0, through: 112, by: 16) {
                idx.append(2 * i + k)
                idx.append(2 * i + k + 1)
            }
            pRound(&z, indices: idx)
        }
        return xorWords(z, r)
    }

    /// One application of the permutation P to 16 words (RFC 9106 Fig. 18).
    static func pRound(_ v: inout [UInt64], indices: [Int]) {
        let i = indices
        gb(&v, i[0], i[4], i[8], i[12])
        gb(&v, i[1], i[5], i[9], i[13])
        gb(&v, i[2], i[6], i[10], i[14])
        gb(&v, i[3], i[7], i[11], i[15])
        gb(&v, i[0], i[5], i[10], i[15])
        gb(&v, i[1], i[6], i[11], i[12])
        gb(&v, i[2], i[7], i[8], i[13])
        gb(&v, i[3], i[4], i[9], i[14])
    }

    /// The GB round function (RFC 9106 Fig. 19): BLAKE2b's G with addition
    /// replaced by BlaMka.
    static func gb(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        var A = v[a], B = v[b], C = v[c], D = v[d]
        A = fBlaMka(A, B)
        D = rotateRight(D ^ A, 32)
        C = fBlaMka(C, D)
        B = rotateRight(B ^ C, 24)
        A = fBlaMka(A, B)
        D = rotateRight(D ^ A, 16)
        C = fBlaMka(C, D)
        B = rotateRight(B ^ C, 63)
        v[a] = A; v[b] = B; v[c] = C; v[d] = D
    }

    /// BlaMka: x + y + 2·low32(x)·low32(y) mod 2^64.
    static func fBlaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
        x &+ y &+ (2 &* UInt64(UInt32(truncatingIfNeeded: x)) &* UInt64(UInt32(truncatingIfNeeded: y)))
    }

    static func rotateRight(_ x: UInt64, _ n: Int) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }

    /// Generates one address block: G(zero, G(zero, input)), incrementing
    /// the input's counter first (RFC 9106 §3.4.1.3).
    static func nextAddresses(inputBlock: inout [UInt64], zero: [UInt64]) -> [UInt64] {
        inputBlock[6] &+= 1
        let a1 = compressionG(zero, inputBlock)
        return compressionG(zero, a1)
    }

    /// Maps J1 to a reference-block column (RFC 9106 §3.4.2).
    static func indexAlpha(
        pass: Int, slice: Int, index: Int,
        laneLength: Int, segmentLength: Int,
        j1: UInt32, sameLane: Bool
    ) -> Int {
        let refArea: Int
        if pass == 0 {
            if slice == 0 {
                refArea = index - 1
            } else if sameLane {
                refArea = slice * segmentLength + index - 1
            } else {
                refArea = slice * segmentLength + (index == 0 ? -1 : 0)
            }
        } else {
            if sameLane {
                refArea = laneLength - segmentLength + index - 1
            } else {
                refArea = laneLength - segmentLength + (index == 0 ? -1 : 0)
            }
        }
        // Non-uniform mapping that favors recent blocks:
        //   x = (J1² mod 2^64) >> 32; y = (refArea·x) >> 32
        //   rel = refArea - 1 - y
        let x = (UInt64(j1) &* UInt64(j1)) >> 32
        let y = (UInt64(refArea) &* x) >> 32
        let rel = refArea - 1 - Int(y)
        let start: Int = (pass != 0) ? (slice == 3 ? 0 : (slice + 1) * segmentLength) : 0
        return (start + rel) % laneLength
    }

    // MARK: - Small helpers

    static func xorWords(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        precondition(a.count == b.count)
        return zip(a, b).map { $0 ^ $1 }
    }

    static func wordsFromBytes(_ data: Data) -> [UInt64] {
        precondition(data.count == 1024, "block must be 1024 bytes")
        var words = [UInt64](repeating: 0, count: 128)
        var idx = data.startIndex
        for w in 0 ..< 128 {
            var word: UInt64 = 0
            for b in 0 ..< 8 {
                word |= UInt64(data[idx]) << (8 * b)
                idx = data.index(after: idx)
            }
            words[w] = word
        }
        return words
    }

    static func bytesFromWords(_ words: [UInt64]) -> Data {
        precondition(words.count == 128)
        var data = Data()
        data.reserveCapacity(1024)
        for word in words {
            var le = word.littleEndian
            withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
        }
        return data
    }

    static func u32le(_ v: UInt32) -> Data {
        var le = v.littleEndian
        return withUnsafeBytes(of: &le) { Data($0) }
    }
}
