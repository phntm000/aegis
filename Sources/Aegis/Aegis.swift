// Aegis umbrella module: re-exports the library packages so
// consumers can `import Aegis` instead of importing each package.

@_exported import AegisCrypto
@_exported import AegisTransport
@_exported import AegisStore
@_exported import AegisDeviceLink

/// Umbrella namespace for the Aegis client libraries.
public enum Aegis {
    /// Semantic version of the library umbrella. Bump on breaking changes.
    public static let version = "0.1.0"
}
