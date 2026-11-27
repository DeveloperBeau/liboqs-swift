import Foundation
@testable import OQS

/// The byte lengths that an algorithm's public Swift type checks, read with no key generation.
///
/// Each length is the `expected` value of the `invalidKeySize` error that the
/// type throws for input of the wrong size. A signature type does not check
/// signature lengths, so the signature length is the size the wrapper reserves
/// for a signature, which no public member reports.
struct TypedLengths: Equatable, CustomStringConvertible {
    let publicKey: Int
    let secretKey: Int
    /// The ciphertext length of a KEM, or the signature length of a signature scheme.
    let output: Int

    var description: String { "pk \(publicKey), sk \(secretKey), out \(output)" }

    struct NoLengthCheck: Error {}

    // The length an `invalidKeySize` error from `body` expects.
    static func expectedLength(_ body: () throws -> Void) throws -> Int {
        do {
            try body()
        } catch OQSError.invalidKeySize(let expected, _) {
            return expected
        }
        throw NoLengthCheck()
    }

    static func kem<K: ParityKEMPrivateKey>(_: K.Type) throws -> TypedLengths {
        let pk = try expectedLength { _ = try K.Public(rawRepresentation: Data()) }
        let sk = try expectedLength { _ = try K(rawRepresentation: Data(), publicKeyRepresentation: Data(count: pk)) }
        // A key of the right sizes, so decapsulation reaches its ciphertext check.
        let key = try K(rawRepresentation: Data(count: sk), publicKeyRepresentation: Data(count: pk))
        let ct = try expectedLength { _ = try key.decryptSharedSecret(Data()) }
        return TypedLengths(publicKey: pk, secretKey: sk, output: ct)
    }

    static func signature<K: ParityImportableSigPrivateKey>(_: K.Type, name: String) throws -> TypedLengths {
        let pk = try expectedLength { _ = try K.Public(rawRepresentation: Data()) }
        let sk = try expectedLength { _ = try K(rawRepresentation: Data(), publicKeyRepresentation: Data(count: pk)) }
        return TypedLengths(publicKey: pk, secretKey: sk, output: try sigExpectedKeyLengths(algorithm: name).signature)
    }

    static func prehash(_ fn: SLHDSA.Prehash.Function, _ ps: SLHDSA.Prehash.ParamSet) throws -> TypedLengths {
        let pk = try expectedLength { _ = try SLHDSA.Prehash.PublicKey(prehash: fn, paramSet: ps, rawRepresentation: Data()) }
        let sk = try expectedLength {
            _ = try SLHDSA.Prehash.PrivateKey(prehash: fn, paramSet: ps, rawRepresentation: Data(), publicKeyRepresentation: Data(count: pk))
        }
        let name = SLHDSA.Prehash.algorithmName(fn, ps)
        return TypedLengths(publicKey: pk, secretKey: sk, output: try sigExpectedKeyLengths(algorithm: name).signature)
    }
}
