// X3DH — Extended Triple Diffie-Hellman key agreement.
//
// Establishes a shared secret between an initiator (who holds the
// responder's published `PreKeyBundle`) and the responder, without any
// interaction. The output is the Double Ratchet's initial root key.
//
// Protocol (see docs/CRYPTO.md §5 for the equations and rationale):
//
//   DH1 = DH(IKA_agree, SPKB)      // initiator identity DH key × responder signed prekey
//   DH2 = DH(EKA,      IKB_agree)  // ephemeral × responder identity DH key
//   DH3 = DH(EKA,      SPKB)       // ephemeral × responder signed prekey
//   DH4 = DH(EKA,      OPKB)       // ephemeral × one-time prekey (if present)
//
// Two deliberate deviations from Signal's X3DH, both documented in
// CRYPTO.md:
//  1. The identity contributes its X25519 *agreement* key to the DHs, not
//     the Ed25519 signing key (CryptoKit has no XEdDSA conversion; see
//     Identity.swift). The bundle signature still binds everything to the
//     Ed25519 identity.
//  2. The KDF is a *cascade* over the DH secrets rather than
//     `KDF(DH1 || DH2 || DH3 || DH4)`, because CryptoKit's `SharedSecret`
//     never exposes raw bytes. Each stage HKDFs one DH secret with a salt
//     chained from the previous stage, so the final key still requires
//     knowledge of *all* DH secrets. The equations are specified in
//     CRYPTO.md; any `CryptoProvider` adapter implements the same cascade
//     via `DHSecret.derivedKey`.

import CryptoKit
import Foundation

public enum X3DH {
    // MARK: - Cascade KDF

    /// Combines DH secrets into a single key.
    ///
    ///   k_0 = HKDF(DH_0, salt: salt,                    info: "<p>/0")
    ///   k_i = HKDF(DH_i, salt: HMAC(k_{i-1}, "<p>/step<i>"), info: "<p>/<i>")
    ///
    /// The final `k` requires every DH secret: each stage's salt is a MAC
    /// under the previous stage's key, so skipping or substituting any DH
    /// breaks the chain. `salt` binds the two parties' fingerprints.
    static func cascadeKDF(secrets: [any DHSecret], salt: Data, infoPrefix: String) -> SymmetricKey {
        precondition(!secrets.isEmpty, "cascade KDF needs at least one DH secret")
        var chaining = secrets[0].derivedKey(
            salt: salt,
            info: Data("\(infoPrefix)/0".utf8),
            outputByteCount: 32
        )
        for (index, secret) in secrets.dropFirst().enumerated() {
            let step = index + 1
            let stepSalt = HKDF.hmac(
                key: chaining,
                message: Data("\(infoPrefix)/step\(step)".utf8)
            )
            chaining = secret.derivedKey(
                salt: stepSalt,
                info: Data("\(infoPrefix)/\(step)".utf8),
                outputByteCount: 32
            )
        }
        return chaining
    }

    /// The KDF salt: binds both identities so the handshake cannot be
    /// retargeted at a different pair of fingerprints.
    static func handshakeSalt(initiatorFingerprint: Data, responderFingerprint: Data) -> Data {
        var context = Data("AegisX3DH_v1".utf8)
        context.append(initiatorFingerprint)
        context.append(responderFingerprint)
        return Data(SHA256.hash(data: context))
    }

    // MARK: - Initiator

    public struct Initiation {
        /// The Double Ratchet's initial root key.
        public let rootKey: SymmetricKey
        /// Ephemeral public key, sent in the prekey message.
        public let ephemeralPublicKey: Data
        /// The consumed one-time prekey id, or `nil` if the bundle had none.
        /// The initiator tells the responder which OPK it used so the
        /// responder can delete the right private half.
        public let usedOneTimePreKeyID: UInt32?
    }

    /// Runs the initiator side of X3DH against a verified bundle.
    /// - Throws: `invalidSignature` if the bundle does not verify — the
    ///   handshake MUST be aborted in that case.
    public static func initiate(
        ourIdentity: Identity,
        bundle: PreKeyBundle,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Initiation {
        guard bundle.verify(provider: provider) else {
            throw AegisCryptoError.invalidSignature
        }

        let ephemeral = try X25519KeyPair.generate(provider: provider)

        var secrets: [any DHSecret] = []
        secrets.append(try provider.x25519DH(
            privateKey: ourIdentity.agreementKey.privateKey.toData(),
            peerPublicKey: bundle.signedPreKey.publicKey
        ))
        secrets.append(try provider.x25519DH(
            privateKey: ephemeral.privateKey.toData(),
            peerPublicKey: bundle.identity.agreementPublicKey
        ))
        secrets.append(try provider.x25519DH(
            privateKey: ephemeral.privateKey.toData(),
            peerPublicKey: bundle.signedPreKey.publicKey
        ))

        let usedOPKID: UInt32?
        if let opk = bundle.oneTimePreKey {
            secrets.append(try provider.x25519DH(
                privateKey: ephemeral.privateKey.toData(),
                peerPublicKey: opk.publicKey
            ))
            usedOPKID = opk.id
        } else {
            usedOPKID = nil
        }

        let salt = handshakeSalt(
            initiatorFingerprint: ourIdentity.fingerprint,
            responderFingerprint: bundle.identity.fingerprint
        )
        let rootKey = cascadeKDF(secrets: secrets, salt: salt, infoPrefix: "AegisX3DH_v1")

        return Initiation(
            rootKey: rootKey,
            ephemeralPublicKey: ephemeral.publicKey,
            usedOneTimePreKeyID: usedOPKID
        )
    }

    // MARK: - Responder

    /// Runs the responder side of X3DH.
    ///
    /// - Parameters:
    ///   - initiator: the initiator's public identity (from the prekey message).
    ///   - ephemeralPublicKey: the initiator's ephemeral public key.
    ///   - usedOneTimePreKey: the private one-time prekey the initiator
    ///     consumed, or `nil`. The caller MUST delete its private half
    ///     (via `PreKeyManager.consumeOneTimePreKey`) immediately after
    ///     this returns — reuse would destroy forward secrecy for the
    ///     first message.
    public static func respond(
        ourIdentity: Identity,
        ourSignedPreKey: SignedPreKey,
        usedOneTimePreKey: OneTimePreKey?,
        initiator: IdentityPublic,
        ephemeralPublicKey: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SymmetricKey {
        guard ephemeralPublicKey.count == 32 else {
            throw AegisCryptoError.invalidKeyData
        }

        var secrets: [any DHSecret] = []
        // DH1 = DH(SPKB_priv, IKA_agree_pub)
        secrets.append(try provider.x25519DH(
            privateKey: ourSignedPreKey.keyPair.privateKey.toData(),
            peerPublicKey: initiator.agreementPublicKey
        ))
        // DH2 = DH(IKB_agree_priv, EKA_pub)
        secrets.append(try provider.x25519DH(
            privateKey: ourIdentity.agreementKey.privateKey.toData(),
            peerPublicKey: ephemeralPublicKey
        ))
        // DH3 = DH(SPKB_priv, EKA_pub)
        secrets.append(try provider.x25519DH(
            privateKey: ourSignedPreKey.keyPair.privateKey.toData(),
            peerPublicKey: ephemeralPublicKey
        ))
        // DH4 = DH(OPKB_priv, EKA_pub)
        if let opk = usedOneTimePreKey {
            secrets.append(try provider.x25519DH(
                privateKey: opk.keyPair.privateKey.toData(),
                peerPublicKey: ephemeralPublicKey
            ))
        }

        let salt = handshakeSalt(
            initiatorFingerprint: initiator.fingerprint,
            responderFingerprint: ourIdentity.fingerprint
        )
        return cascadeKDF(secrets: secrets, salt: salt, infoPrefix: "AegisX3DH_v1")
    }
}
