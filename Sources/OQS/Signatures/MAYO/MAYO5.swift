import Foundation
internal import Cliboqs

/// MAYO-5 digital signatures (multivariate Oil-and-Vinegar scheme, NIST additional-signatures candidate).
///
/// MAYO is a multivariate signature scheme from the Oil-and-Vinegar family,
/// submitted to the NIST additional digital-signature standardization effort.
/// Its security rests on the hardness of solving structured systems of
/// multivariate quadratic equations, and it offers very small keys (the secret
/// key is essentially a short seed of a few dozen bytes) and compact signatures.
/// MAYO-5 is the largest parameter set, targeting the highest security tier.
///
/// - Warning: This parameter set allocates very large buffers on the stack
///   during key generation and signing. It requires a thread stack of several
///   megabytes; calling it on a small-stack thread (such as a background or
///   test-runner thread) crashes the process (an uncatchable hardware trap)
///   rather than throwing an error. Run it on the main thread or a thread
///   configured with a large stack.
///
/// ```swift
/// // Generate a signing key
/// let signer = try MAYO5.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try MAYO5.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try MAYO5.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum MAYO5: Sendable {
    static let algorithmName = "MAYO-5"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: MAYO5.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MAYO5.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        public func signature(for data: Data) throws -> Data {
            try sigSign(algorithm: MAYO5.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MAYO5.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: MAYO5.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
