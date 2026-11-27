/// Something went wrong during a cryptographic operation.
///
/// Most commonly you'll see `invalidKeySize` when importing keys with
/// wrong-length data, or `algorithmNotAvailable` if a liboqs algorithm
/// wasn't enabled in the build.
public enum OQSError: Error, Sendable, Equatable, Hashable, CustomStringConvertible {
    /// The requested algorithm is not available in the current build.
    case algorithmNotAvailable(String)
    /// Key pair generation failed.
    case keyGenerationFailed
    /// KEM encapsulation failed.
    case encapsulationFailed
    /// KEM decapsulation failed.
    case decapsulationFailed
    /// Signature generation failed.
    case signFailed
    /// Signature verification failed.
    case verifyFailed
    /// The provided key data has the wrong size.
    case invalidKeySize(expected: Int, actual: Int)
    /// The algorithm does not take a context string.
    case contextNotSupported
    /// The context string is longer than the algorithm allows.
    case contextTooLong
    /// The algorithm has no form of the operation that takes a seed.
    ///
    /// The public seeded ML-KEM methods never throw this.
    /// It is the error for a seeded call on an algorithm that liboqs gives no seeded form.
    /// The internal seeded helpers throw it for every other KEM.
    case seedNotSupported
    /// The stateful secret key has no signature left to give.
    case keyExhausted
    /// The advanced stateful secret key could not be saved.
    case persistenceFailed

    public var description: String {
        switch self {
        case .algorithmNotAvailable(let name): "Algorithm not available: \(name)"
        case .keyGenerationFailed: "Key generation failed"
        case .encapsulationFailed: "KEM encapsulation failed"
        case .decapsulationFailed: "KEM decapsulation failed"
        case .signFailed: "Signature generation failed"
        case .verifyFailed: "Signature verification failed"
        case .invalidKeySize(let expected, let actual): "Invalid key size: expected \(expected) bytes, got \(actual)"
        case .contextNotSupported: "The algorithm does not take a context string"
        case .contextTooLong: "The context string is too long"
        case .seedNotSupported: "The algorithm has no form of the operation that takes a seed"
        case .keyExhausted: "The secret key has no signature left"
        case .persistenceFailed: "The advanced secret key was not saved"
        }
    }
}
