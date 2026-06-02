import Foundation
internal import Cliboqs

/// SNOVA-24-5-4-esk digital signatures (multivariate UOV-family scheme, compact keys).
///
/// SNOVA is a multivariate signature scheme built on the Unbalanced Oil and
/// Vinegar (UOV) trapdoor, augmented with a noncommutative-ring structure that
/// shrinks the public key relative to plain UOV. The name encodes its
/// parameters as `SNOVA_v_o_l`: `v` vinegar variables, `o` oil variables, and
/// a rank-`l` matrix layout.
/// This `24-5-4` variant stores an expanded secret key (`esk`): signing is
/// faster because the trapdoor maps are precomputed, at the cost of a larger
/// private key.
///
/// ```swift
/// // Generate a signing key
/// let signer = try SNOVA24_5_4_esk.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try SNOVA24_5_4_esk.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try SNOVA24_5_4_esk.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum SNOVA24_5_4_esk: Sendable {
    static let algorithmName = "SNOVA_24_5_4_esk"

    /// A SNOVA-24-5-4-esk private (signing) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SNOVA24_5_4_esk.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA24_5_4_esk.algorithmName)
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
            try sigSign(algorithm: SNOVA24_5_4_esk.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    /// A SNOVA-24-5-4-esk public (verification) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SNOVA24_5_4_esk.algorithmName)
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
            try sigVerify(algorithm: SNOVA24_5_4_esk.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
