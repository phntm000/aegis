// Verification — safety numbers and QR ceremonies.
//
// Encryption without authentication is decoration: a relay that can swap
// prekey bundles can man-in-the-middle every session. Aegis has no central
// directory to consult, so verification is out-of-band and explicit:
//
//  - `SafetyNumber`: a 30-byte value derived from both parties'
//    fingerprints, displayed as 75 digits in 15 groups of 5. Two people
//    read the numbers to each other (or compare on screen) — if they match,
//    no one is in the middle.
//  - `VerificationQR`: a QR payload encoding a contact's public identity.
//    Scanning it verifies the fingerprint binding without typing.
//
// `VerificationState` is the UI-facing trust state per contact / per
// group. The crypto layer computes; the store layer persists; the UI
// surfaces. A fingerprint change on a `verified` contact MUST produce a
// loud, blocking warning — that is the whole point.

import CryptoKit
import Foundation

/// The UI-facing trust state of a contact (or group) identity.
public enum VerificationState: String, Equatable, Codable {
    /// Never verified out-of-band. Show a subtle, non-blocking indicator.
    case unverified
    /// Safety number or QR verified against the current fingerprint.
    case verified
    /// The fingerprint changed after verification. Treat as a potential
    /// MITM: block sending until the user re-verifies or explicitly
    /// accepts the new fingerprint.
    case changed
}

public enum SafetyNumber {
    /// Number of SHA-512 iterations. Matches Signal's work factor so the
    /// safety number cannot be brute-forced cheaply if fingerprints leak.
    public static let hashIterations = 5_200

    /// Computes the 30-byte safety number for a pair of fingerprints.
    /// Order-independent: both parties compute the same value.
    public static func compute(localFingerprint: Data, remoteFingerprint: Data) -> Data {
        precondition(localFingerprint.count == 32 && remoteFingerprint.count == 32)
        let (first, second): (Data, Data) =
            localFingerprint.lexicographicallyPrecedes(remoteFingerprint)
            ? (localFingerprint, remoteFingerprint)
            : (remoteFingerprint, localFingerprint)
        var input = Data("AegisSafetyNumber_v1".utf8)
        input.append(first)
        input.append(second)
        var digest = Data(SHA512.hash(data: input))
        for _ in 0 ..< hashIterations {
            digest = Data(SHA256.hash(data: digest))
        }
        return Data(digest.prefix(30))
    }

    /// Renders the 30-byte safety number as 75 decimal digits in 15 groups
    /// of 5, e.g. `"12345 67890 …"`. Each group is one big-endian UInt16
    /// formatted as 5 digits (values range 00000–65535).
    public static func displayString(_ safetyNumber: Data) -> String {
        precondition(safetyNumber.count == 30, "safety number must be 30 bytes")
        var groups: [String] = []
        groups.reserveCapacity(15)
        var index = safetyNumber.startIndex
        for _ in 0 ..< 15 {
            let value = UInt16(safetyNumber[index]) << 8 | UInt16(safetyNumber[safetyNumber.index(after: index)])
            groups.append(String(format: "%05d", value))
            index = safetyNumber.index(index, offsetBy: 2)
        }
        return groups.joined(separator: " ")
    }
}

/// QR-code verification payload: `version u8 || signingPub(32) ||`
/// `agreementPub(32) || fingerprint(32)` (97 bytes), base64url-encoded for
/// the QR encoder. Contains only public keys — photographing someone's QR
/// over their shoulder yields zero secret material.
public enum VerificationQR {
    public static func payload(for identity: Identity) -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(identity.signingKey.publicKey)
        encoder.bytes(identity.agreementKey.publicKey)
        encoder.bytes(identity.fingerprint)
        return encoder.data
    }

    /// Parses a scanned payload and checks the fingerprint binding.
    /// - Returns: the claimed public identity. The caller compares
    ///   `.fingerprint` against the stored contact fingerprint.
    /// - Throws: `invalidWireFormat` (malformed) or `invalidSignature`
    ///   (fingerprint does not match the keys — the QR is forged).
    public static func parse(_ data: Data) throws -> IdentityPublic {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let identity = try IdentityPublic(
            signingPublicKey: decoder.bytes(count: 32),
            agreementPublicKey: decoder.bytes(count: 32)
        )
        let claimedFingerprint = try decoder.bytes(count: 32)
        try decoder.expectEnd()
        guard constantTimeEqual(claimedFingerprint, identity.fingerprint) else {
            throw AegisCryptoError.invalidSignature
        }
        return identity
    }
}
