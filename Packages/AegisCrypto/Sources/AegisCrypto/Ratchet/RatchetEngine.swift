// RatchetEngine — the protocol seam for the Double Ratchet.
//
// `AegisDoubleRatchet` is the pure-Swift implementation in this module. A
// future libsignal-client adapter implements this same protocol, so callers
// (sessions, groups, transport) never depend on the concrete ratchet.

import Foundation

/// An established 1:1 encrypted session: encrypts with the sending chain,
/// decrypts with the receiving chain, ratcheting forward as needed.
public protocol RatchetEngine: AnyObject {
    /// Encrypts `plaintext` under the current sending chain.
    /// - Parameter associatedData: application-level AAD (e.g. conversation
    ///   binding). Authenticated, not encrypted.
    func encrypt(plaintext: Data, associatedData: Data) throws -> RatchetMessage

    /// Decrypts, performing DH-ratchet steps and stashing skipped message
    /// keys for out-of-order delivery as needed.
    func decrypt(_ message: RatchetMessage, associatedData: Data) throws -> Data
}
