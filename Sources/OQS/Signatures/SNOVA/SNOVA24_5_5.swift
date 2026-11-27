import Foundation
internal import Cliboqs

/// SNOVA-24-5-5 digital signatures (multivariate UOV-family scheme, compact keys).
///
/// SNOVA is a multivariate signature scheme built on the Unbalanced Oil and
/// Vinegar (UOV) trapdoor, augmented with a noncommutative-ring structure that
/// shrinks the public key relative to plain UOV. The name encodes its
/// parameters as `SNOVA_v_o_l`: `v` vinegar variables, `o` oil variables, and
/// a rank-`l` matrix layout.
/// This `24-5-5` set increases the matrix rank to 5, trading larger keys and
/// signatures for a higher security margin than the `24-5-4` baseline.
///
/// - Warning: Signing allocates very large on-stack buffers (rank-5 layout).
///   On a thread with a small stack (e.g. a background or test-runner thread),
///   ``PrivateKey/signature(for:)`` crashes with an uncatchable SIGBUS rather
///   than throwing. Sign on the main thread or a thread with a several-MB
///   stack. Key generation is unaffected.
///
/// ```swift
/// // Generate a signing key
/// let signer = try SNOVA24_5_5.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try SNOVA24_5_5.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try SNOVA24_5_5.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum SNOVA24_5_5: Sendable {
    static let algorithmName = "SNOVA_24_5_5"

    /// A SNOVA-24-5-5 private (signing) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SNOVA24_5_5.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA24_5_5.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        /// Signs the given message and returns the signature.
        public func signature(for data: Data) throws -> Data {
            try sigSign(algorithm: SNOVA24_5_5.algorithmName, message: data, secretKey: rawRepresentation)
        }

        /// Signs `data` together with a context string.
        ///
        /// An empty `context` gives the same signature as ``signature(for:)``.
        /// The context is at most 255 bytes. Throws ``OQSError/contextNotSupported``
        /// when the algorithm takes no context and `context` is not empty,
        /// ``OQSError/invalidKeySize(expected:actual:)`` when the secret key has the
        /// wrong length, ``OQSError/contextTooLong`` when `context` is over 255 bytes,
        /// and ``OQSError/signFailed`` when liboqs reports an error.
        public func signature(for data: Data, context: Data) throws -> Data {
            try sigSign(algorithm: SNOVA24_5_5.algorithmName, message: data, context: context, secretKey: rawRepresentation)
        }
    }

    /// A SNOVA-24-5-5 public (verification) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA24_5_5.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        /// Verifies a signature over the given message.
        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: SNOVA24_5_5.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }

        /// Verifies `signature` over `data` and a context string.
        ///
        /// An empty `context` gives the same result as ``isValidSignature(_:for:)``.
        /// Returns `false` when the signature does not match, when the algorithm takes
        /// no context and `context` is not empty, and when `context` is over 255 bytes.
        /// Throws ``OQSError/invalidKeySize(expected:actual:)`` when the public key has
        /// the wrong length.
        public func isValidSignature(_ signature: Data, for data: Data, context: Data) throws -> Bool {
            try sigVerify(algorithm: SNOVA24_5_5.algorithmName, message: data, signature: signature, context: context, publicKey: rawRepresentation)
        }
    }
}
