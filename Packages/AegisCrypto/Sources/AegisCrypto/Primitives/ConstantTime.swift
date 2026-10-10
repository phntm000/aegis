// Constant-time comparison helpers.
//
// Used wherever attacker-controlled bytes are compared against secrets or
// authentication tags (fingerprints are public, but comparing them in
// constant time costs nothing and avoids building a timing-oracle habit).

import Foundation

/// Compares two byte strings in time independent of their contents.
/// Length mismatch returns `false` immediately (lengths are not secret in
/// any protocol in this module).
public func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var diff: UInt8 = 0
    for (a, b) in zip(lhs, rhs) {
        diff |= a ^ b
    }
    // `diff` accumulates every differing bit; the branch below depends only
    // on the aggregate, not on *where* the difference was.
    return diff == 0
}
