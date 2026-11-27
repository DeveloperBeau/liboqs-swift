import Foundation
internal import Cliboqs

/// mqom2_cat3_gf16_short_r5 digital signatures (MQOM2, MPC-in-the-head multivariate, NIST category 3, short profile, 5 rounds).
///
/// MQOM2 ("MQ on my Mind") is a third-round candidate in NIST's Additional
/// Digital Signatures process. Security reduces to the hardness of solving
/// random multivariate quadratic systems over GF(16), proven via an
/// MPC-in-the-head zero-knowledge argument. The "short" trade-off favors smaller signatures over speed;
/// r5 uses 5 rounds (slower, smaller signatures).
///
/// - Warning: Signing uses large on-stack buffers. On a thread with a small
///   stack (e.g. a dispatch-queue or test-runner thread),
///   ``PrivateKey/signature(for:)`` can crash with an uncatchable SIGBUS
///   rather than throwing. Sign on the main thread or a thread with a
///   several-MB stack. Key generation and verification are unaffected.
///
/// ```swift
/// // Generate a signing key
/// let signer = try MQOM2Cat3GF16ShortR5.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try MQOM2Cat3GF16ShortR5.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try MQOM2Cat3GF16ShortR5.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum MQOM2Cat3GF16ShortR5: Sendable {
    static let algorithmName = "mqom2_cat3_gf16_short_r5"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: MQOM2Cat3GF16ShortR5.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MQOM2Cat3GF16ShortR5.algorithmName)
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
            try sigSign(algorithm: MQOM2Cat3GF16ShortR5.algorithmName, message: data, secretKey: rawRepresentation)
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
            try sigSign(algorithm: MQOM2Cat3GF16ShortR5.algorithmName, message: data, context: context, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MQOM2Cat3GF16ShortR5.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: MQOM2Cat3GF16ShortR5.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }

        /// Verifies `signature` over `data` and a context string.
        ///
        /// An empty `context` gives the same result as ``isValidSignature(_:for:)``.
        /// Returns `false` when the signature does not match, when the algorithm takes
        /// no context and `context` is not empty, and when `context` is over 255 bytes.
        /// Throws ``OQSError/invalidKeySize(expected:actual:)`` when the public key has
        /// the wrong length.
        public func isValidSignature(_ signature: Data, for data: Data, context: Data) throws -> Bool {
            try sigVerify(algorithm: MQOM2Cat3GF16ShortR5.algorithmName, message: data, signature: signature, context: context, publicKey: rawRepresentation)
        }
    }
}
