import Foundation

/// One registered liboqs algorithm: its name, a closure that runs the base
/// case through the algorithm's public Swift type, and a closure that reads
/// the lengths that type checks. `run` returns the named output fields in the
/// same order as the raw C reference.
struct ParityAlgorithm: Sendable {
    let name: String
    let run: @Sendable () throws -> [(String, Data)]
    let typedLengths: @Sendable () throws -> TypedLengths
    /// Uses the key, exports it, rebuilds it and uses the rebuilt key.
    let secretFlow: @Sendable () throws -> SecretFlow
}
