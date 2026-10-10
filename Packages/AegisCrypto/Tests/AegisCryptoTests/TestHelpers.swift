// Shared test helpers for AegisCryptoTests.

import Foundation
@testable import AegisCrypto

/// Decodes a hex string into `Data`. Test vectors only — crashes on bad
/// input by design (a malformed vector is a test-authoring bug).
func hexData(_ hex: String) -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index ..< next], radix: 16) else {
            fatalError("malformed hex test vector")
        }
        data.append(byte)
        index = next
    }
    return data
}

/// A non-throwing test provider shorthand.
let testProvider: any CryptoProvider = CryptoKitProvider.shared
