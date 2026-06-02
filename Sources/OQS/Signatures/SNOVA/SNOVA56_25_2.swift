import Foundation
internal import Cliboqs

/// SNOVA-56-25-2 digital signatures (multivariate UOV-family scheme, compact keys).
///
/// SNOVA is a multivariate signature scheme built on the Unbalanced Oil and
/// Vinegar (UOV) trapdoor, augmented with a noncommutative-ring structure that
/// shrinks the public key relative to plain UOV. The name encodes its
/// parameters as `SNOVA_v_o_l`: `v` vinegar variables, `o` oil variables, and
/// a rank-`l` matrix layout.
/// This `56-25-2` set uses a rank-2 layout with a large oil space, one of
/// the strongest SNOVA parameter choices.
///
/// - Warning: This parameter set allocates very large buffers on the stack
///   during key generation and signing. It requires a thread stack of several
///   megabytes; calling it on a small-stack thread crashes the process
///   (an uncatchable hardware trap) rather than throwing an error. Run it on
///   the main thread or a thread configured with a large stack.
///
/// ```swift
/// // Generate a signing key
/// let signer = try SNOVA56_25_2.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try SNOVA56_25_2.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try SNOVA56_25_2.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum SNOVA56_25_2: Sendable {
    static let algorithmName = "SNOVA_56_25_2"

    /// A SNOVA-56-25-2 private (signing) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SNOVA56_25_2.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA56_25_2.algorithmName)
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
            try sigSign(algorithm: SNOVA56_25_2.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    /// A SNOVA-56-25-2 public (verification) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA56_25_2.algorithmName)
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
            try sigVerify(algorithm: SNOVA56_25_2.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
