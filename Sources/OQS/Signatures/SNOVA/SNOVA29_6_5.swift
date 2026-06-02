import Foundation
internal import Cliboqs

/// SNOVA-29-6-5 digital signatures (multivariate UOV-family scheme, compact keys).
///
/// SNOVA is a multivariate signature scheme built on the Unbalanced Oil and
/// Vinegar (UOV) trapdoor, augmented with a noncommutative-ring structure that
/// shrinks the public key relative to plain UOV. The name encodes its
/// parameters as `SNOVA_v_o_l`: `v` vinegar variables, `o` oil variables, and
/// a rank-`l` matrix layout.
/// This `29-6-5` set uses a rank-5 layout, targeting a stronger security
/// tier than the smaller variants.
///
/// - Warning: Signing allocates very large on-stack buffers (rank-5 layout).
///   On a thread with a small stack (e.g. a background or test-runner thread),
///   ``PrivateKey/signature(for:)`` crashes with an uncatchable SIGBUS rather
///   than throwing. Sign on the main thread or a thread with a several-MB
///   stack. Key generation is unaffected.
///
/// ```swift
/// // Generate a signing key
/// let signer = try SNOVA29_6_5.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try SNOVA29_6_5.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try SNOVA29_6_5.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum SNOVA29_6_5: Sendable {
    static let algorithmName = "SNOVA_29_6_5"

    /// A SNOVA-29-6-5 private (signing) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SNOVA29_6_5.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA29_6_5.algorithmName)
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
            try sigSign(algorithm: SNOVA29_6_5.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    /// A SNOVA-29-6-5 public (verification) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA29_6_5.algorithmName)
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
            try sigVerify(algorithm: SNOVA29_6_5.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
