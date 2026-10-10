import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class PrimitiveTests: XCTestCase {
    // MARK: - HKDF (RFC 5869, Test Case 1)

    func testHKDFRFC5869TestCase1() {
        let ikm = Data(repeating: 0x0B, count: 22)
        let salt = hexData("000102030405060708090a0b0c")
        let info = hexData("f0f1f2f3f4f5f6f7f8f9")
        let expected = hexData("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        let okm = HKDF.expand(
            pseudoRandomKey: HKDF.extract(salt: salt, inputKeyMaterial: ikm),
            info: info,
            outputByteCount: 42
        )
        XCTAssertEqual(okm, expected)
    }

    // MARK: - BLAKE2b

    func testBlake2bEmptyStringVectors() {
        XCTAssertEqual(
            Blake2b.hash(digestSize: 64, data: Data()),
            hexData("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
        )
        XCTAssertEqual(
            Blake2b.hash(digestSize: 32, data: Data()),
            hexData("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
        )
    }

    // MARK: - AES-256-GCM

    func testAESGCMAllZeroVector() throws {
        // AES-256, key = 32 zero bytes, nonce = 12 zero bytes, empty
        // plaintext and AAD. (The oft-quoted 58e2fcce… tag is AES-128's;
        // verified against an independent implementation.)
        let key = SymmetricKey(data: Data(repeating: 0, count: 32))
        let sealed = try AEAD.seal(
            plaintext: Data(),
            key: key,
            associatedData: Data(),
            nonce: Data(repeating: 0, count: 12),
            provider: testProvider
        )
        XCTAssertEqual(sealed.ciphertext, Data())
        XCTAssertEqual(sealed.tag, hexData("530f8afbc74536b9a963b4f1c4cb738b"))
    }

    func testAESGCMRoundTrip() throws {
        let key = SymmetricKey(data: try Random.bytes(count: 32))
        let plaintext = Data("the quick brown fox".utf8)
        let aad = Data("header".utf8)
        let sealed = try AEAD.seal(plaintext: plaintext, key: key, associatedData: aad, provider: testProvider)
        XCTAssertEqual(try AEAD.open(sealed, key: key, associatedData: aad, provider: testProvider), plaintext)
    }

    func testAESGCMTamperedCiphertextFails() throws {
        let key = SymmetricKey(data: try Random.bytes(count: 32))
        var sealed = try AEAD.seal(plaintext: Data("secret".utf8), key: key, associatedData: Data(), provider: testProvider)
        sealed = SealedMessage(
            nonce: sealed.nonce,
            ciphertext: Data(sealed.ciphertext.map { $0 ^ 0x01 }),
            tag: sealed.tag
        )
        XCTAssertThrowsError(try AEAD.open(sealed, key: key, associatedData: Data(), provider: testProvider)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testAESGCMWrongAssociatedDataFails() throws {
        let key = SymmetricKey(data: try Random.bytes(count: 32))
        let sealed = try AEAD.seal(
            plaintext: Data("secret".utf8), key: key,
            associatedData: Data("right".utf8), provider: testProvider
        )
        XCTAssertThrowsError(
            try AEAD.open(sealed, key: key, associatedData: Data("wrong".utf8), provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    // MARK: - X25519 (RFC 7748 §6.1)

    func testX25519RFC7748Vector() throws {
        let secret = hexData("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let expectedPublic = hexData("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        XCTAssertEqual(try X25519KeyPair.publicKey(forPrivateKey: secret, provider: testProvider), expectedPublic)
    }

    func testX25519DHCommutativity() throws {
        let a = try X25519KeyPair.generate(provider: testProvider)
        let b = try X25519KeyPair.generate(provider: testProvider)
        let ab = try testProvider.x25519DH(privateKey: a.privateKey.toData(), peerPublicKey: b.publicKey)
        let ba = try testProvider.x25519DH(privateKey: b.privateKey.toData(), peerPublicKey: a.publicKey)
        let ka = ab.derivedKey(salt: Data(), info: Data("test".utf8), outputByteCount: 32)
        let kb = ba.derivedKey(salt: Data(), info: Data("test".utf8), outputByteCount: 32)
        XCTAssertEqual(HKDF.hmac(key: ka, message: Data("x".utf8)), HKDF.hmac(key: kb, message: Data("x".utf8)))
    }

    // MARK: - Ed25519 (RFC 8032 TEST 1)

    func testEd25519RFC8032Vector() throws {
        let seed = hexData("9d61b19deffd5a60ba844af492ec2cc4449c5d0b6a7d2d53d8ac4a29c170d445")
        let expectedPublic = hexData("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let expectedSig = hexData("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        let publicKey = try testProvider.ed25519PublicKey(fromSeed: seed)
        XCTAssertEqual(publicKey, expectedPublic)
        let sig = try testProvider.ed25519Sign(seed: seed, message: Data())
        XCTAssertEqual(sig, expectedSig)
        XCTAssertTrue(testProvider.ed25519Verify(publicKey: publicKey, signature: sig, message: Data()))
    }

    func testEd25519TamperedMessageFails() throws {
        let pair = try Ed25519KeyPair.generate(provider: testProvider)
        let sig = try pair.sign(Data("hello".utf8), provider: testProvider)
        XCTAssertFalse(Ed25519KeyPair.verify(signature: sig, for: Data("hallo".utf8), publicKey: pair.publicKey, provider: testProvider))
        XCTAssertFalse(Ed25519KeyPair.verify(signature: Data(repeating: 0, count: 64), for: Data("hello".utf8), publicKey: pair.publicKey, provider: testProvider))
    }

    // MARK: - Constant-time compare

    func testConstantTimeEqual() {
        XCTAssertTrue(constantTimeEqual(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(constantTimeEqual(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(constantTimeEqual(Data([1, 2, 3]), Data([1, 2])))
        XCTAssertTrue(constantTimeEqual(Data(), Data()))
    }

    // MARK: - Wire codec

    func testWireRoundTrip() throws {
        var encoder = WireEncoder()
        encoder.u8(0xAB)
        encoder.u16(0xCDEF)
        encoder.u32(0x12345678)
        encoder.u64(0x1122334455667788)
        encoder.prefixed(Data([9, 8, 7]))
        var decoder = WireDecoder(encoder.data)
        XCTAssertEqual(try decoder.u8(), 0xAB)
        XCTAssertEqual(try decoder.u16(), 0xCDEF)
        XCTAssertEqual(try decoder.u32(), 0x12345678)
        XCTAssertEqual(try decoder.u64(), 0x1122334455667788)
        XCTAssertEqual(try decoder.prefixed(), Data([9, 8, 7]))
        XCTAssertNoThrow(try decoder.expectEnd())
    }

    func testWireTruncationThrows() {
        var decoder = WireDecoder(Data([0x01, 0x02]))
        XCTAssertThrowsError(try decoder.u32()) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidWireFormat)
        }
        var trailing = WireDecoder(Data([0x01, 0x02]))
        _ = try? trailing.u8()
        XCTAssertThrowsError(try trailing.expectEnd())
    }

    // MARK: - Padding

    func testPaddingRoundTrip() throws {
        for size in [0, 1, 100, 255, 1_000, 5_000] {
            let original = try Random.bytes(count: size)
            XCTAssertEqual(try Padding.unpad(Padding.pad(original)), original)
        }
    }

    func testPaddingBucketing() {
        XCTAssertEqual(Padding.pad(Data()).count, 256)
        XCTAssertEqual(Padding.pad(Data(repeating: 7, count: 1_000)).count, 1_024)
    }

    // MARK: - SecureBytes

    func testSecureBytesZeroing() {
        let secret = SecureBytes(Data([1, 2, 3, 4]))
        secret.zero()
        let wiped = secret.withUnsafeBytes { Data($0) }
        XCTAssertEqual(wiped, Data([0, 0, 0, 0]))
    }
}
