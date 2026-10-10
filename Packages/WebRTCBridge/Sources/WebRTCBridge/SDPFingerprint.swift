import Foundation

/// Extracts the DTLS certificate fingerprint from SDP text.
///
/// WebRTC session descriptions carry one line like:
/// `a=fingerprint:sha-256 4A:5B:6C:…`
/// The signaling layer exchanges this fingerprint inside the E2EE call
/// offer/answer so both parties can compute the SAS (Short Authentication
/// String) over the *media* keys and read it aloud to each other.
///
/// - Returns: the canonical `SHA-256:4A:5B:…` form (matching what
///   `CallSAS` expects), or `nil` when no well-formed fingerprint line
///   is present. Pure Swift — no WebRTC dependency, fully unit-testable.
public enum SDPFingerprint {
    public static func extract(from sdp: String) -> String? {
        for rawLine in sdp.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.lowercased().hasPrefix("a=fingerprint:") else { continue }
            let rest = line.dropFirst("a=fingerprint:".count)
            let parts = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2 else { continue }
            let algorithm = canonicalAlgorithm(String(parts[0]))
            let hex = parts[1].trimmingCharacters(in: .whitespaces).uppercased()
            guard !hex.isEmpty, isHexColonList(hex) else { continue }
            return "\(algorithm):\(hex)"
        }
        return nil
    }

    private static func canonicalAlgorithm(_ raw: String) -> String {
        switch raw.lowercased().replacingOccurrences(of: "-", with: "") {
        case "sha256": return "SHA-256"
        case "sha1": return "SHA-1"
        case "sha384": return "SHA-384"
        case "sha512": return "SHA-512"
        default: return raw.uppercased()
        }
    }

    private static func isHexColonList(_ s: String) -> Bool {
        let hexDigits = CharacterSet(charactersIn: "0123456789ABCDEF:")
        guard s.rangeOfCharacter(from: hexDigits.inverted) == nil else { return false }
        return s.split(separator: ":").allSatisfy { $0.count == 2 }
    }
}
