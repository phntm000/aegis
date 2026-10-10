import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class BackupTests: XCTestCase {
    // MARK: - Argon2id (RFC 9106 §5.3)

    func testArgon2idRFC9106Vector() throws {
        // password = 32×0x01, salt = 16×0x02, secret = 8×0x03,
        // ad = 12×0x04, m = 32 KiB, t = 3, p = 4, taglen = 32.
        let tag = try Argon2id.hash(
            password: Data(repeating: 0x01, count: 32),
            salt: Data(repeating: 0x02, count: 16),
            secret: Data(repeating: 0x03, count: 8),
            associatedData: Data(repeating: 0x04, count: 12),
            memoryKiB: 32,
            iterations: 3,
            parallelism: 4,
            tagLength: 32
        )
        XCTAssertEqual(
            tag,
            hexData("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        )
    }

    func testArgon2idIsDeterministicAndSaltSensitive() throws {
        let params = (memoryKiB: 8, iterations: 1, parallelism: 1)
        let a = try Argon2id.hash(password: Data("pw".utf8), salt: Data(repeating: 1, count: 16), memoryKiB: params.memoryKiB, iterations: params.iterations, parallelism: params.parallelism, tagLength: 32)
        let b = try Argon2id.hash(password: Data("pw".utf8), salt: Data(repeating: 1, count: 16), memoryKiB: params.memoryKiB, iterations: params.iterations, parallelism: params.parallelism, tagLength: 32)
        let c = try Argon2id.hash(password: Data("pw".utf8), salt: Data(repeating: 2, count: 16), memoryKiB: params.memoryKiB, iterations: params.iterations, parallelism: params.parallelism, tagLength: 32)
        let d = try Argon2id.hash(password: Data("pw2".utf8), salt: Data(repeating: 1, count: 16), memoryKiB: params.memoryKiB, iterations: params.iterations, parallelism: params.parallelism, tagLength: 32)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        XCTAssertNotEqual(a, d)
    }

    // MARK: - Export / import

    private func testKDF() -> Argon2id {
        Argon2id(memoryKiB: 8, iterations: 1, parallelism: 1)
    }

    func testExportImportRoundTrip() throws {
        let identity = try Identity(provider: testProvider)
        let spk = try SignedPreKey.generate(id: 7, identity: identity, provider: testProvider)
        let password = SecureBytes(Data("correct horse battery staple".utf8))
        defer { password.zero() }

        let exported = try KeyBackup.export(
            identity: identity, signedPreKey: spk,
            password: password, kdf: testKDF(), provider: testProvider
        )
        let contents = try KeyBackup.import(exported, password: password, provider: testProvider)

        XCTAssertEqual(contents.identity.fingerprint, identity.fingerprint)
        XCTAssertEqual(contents.identity.signingKey.publicKey, identity.signingKey.publicKey)
        XCTAssertEqual(contents.identity.agreementKey.publicKey, identity.agreementKey.publicKey)
        XCTAssertEqual(contents.signedPreKey.id, 7)
        XCTAssertTrue(contents.signedPreKey.verify(identityPublicKey: identity.signingKey.publicKey, provider: testProvider))
        // The restored identity can actually sign.
        let sig = try contents.identity.signingKey.sign(Data("test".utf8), provider: testProvider)
        XCTAssertTrue(Ed25519KeyPair.verify(signature: sig, for: Data("test".utf8), publicKey: identity.signingKey.publicKey, provider: testProvider))
    }

    func testImportWrongPasswordFails() throws {
        let identity = try Identity(provider: testProvider)
        let spk = try SignedPreKey.generate(id: 1, identity: identity, provider: testProvider)
        let exported = try KeyBackup.export(
            identity: identity, signedPreKey: spk,
            password: SecureBytes(Data("right".utf8)), kdf: testKDF(), provider: testProvider
        )
        // Wrong password is indistinguishable from a corrupted file.
        XCTAssertThrowsError(
            try KeyBackup.import(exported, password: SecureBytes(Data("wrong".utf8)), provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testTamperedBackupFails() throws {
        let identity = try Identity(provider: testProvider)
        let spk = try SignedPreKey.generate(id: 1, identity: identity, provider: testProvider)
        let password = SecureBytes(Data("pw".utf8))
        var exported = try KeyBackup.export(
            identity: identity, signedPreKey: spk,
            password: password, kdf: testKDF(), provider: testProvider
        )
        exported[exported.count - 1] ^= 0x01 // flip a tag byte
        XCTAssertThrowsError(try KeyBackup.import(exported, password: password, provider: testProvider)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testDecoyExportProducesWorkingDistinctIdentity() throws {
        let password = SecureBytes(Data("duress".utf8))
        let decoyExport = try KeyBackup.exportDecoy(password: password, kdf: testKDF(), provider: testProvider)
        let contents = try KeyBackup.import(decoyExport, password: password, provider: testProvider)
        // A valid, working identity — just not the user's real one.
        XCTAssertEqual(contents.identity.fingerprint.count, 32)
        let sig = try contents.identity.signingKey.sign(Data("x".utf8), provider: testProvider)
        XCTAssertTrue(Ed25519KeyPair.verify(signature: sig, for: Data("x".utf8), publicKey: contents.identity.signingKey.publicKey, provider: testProvider))
    }
}
