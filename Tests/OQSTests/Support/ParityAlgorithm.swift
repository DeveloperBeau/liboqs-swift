import Foundation

/// One registered liboqs algorithm: its name, a closure that runs the base
/// case through the algorithm's public Swift type, and a closure that reads
/// the lengths that type checks. `run` returns the named output fields in the
/// same order as the raw C reference.
struct ParityAlgorithm: Sendable {
    let name: String
    let run: @Sendable () throws -> [(String, Data)]
    let typedLengths: @Sendable () throws -> TypedLengths
    /// For a signature scheme, one fresh key pair and a signature made through
    /// the public type, with a verifier that goes through the public type. A KEM has none.
    var signed: (@Sendable () throws -> SignedSample)? = nil
}

/// A valid signature and a verifier for it, both made through a public type.
struct SignedSample: Sendable {
    let message: Data
    let publicKey: Data
    let signature: Data
    /// Runs the public type's `isValidSignature` for `signature` over `message`.
    let verify: @Sendable (_ signature: Data) throws -> Bool
}
