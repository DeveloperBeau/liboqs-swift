import Foundation
internal import Cliboqs

/// SLH-DSA-SHA2-128f digital signatures (NIST standard (FIPS 205), hash-based, 128-bit security).
///
/// FIPS 205 standard. Uses SHA2 internally, optimized for fast signing.
/// Hash-based security with no lattice or code-based assumptions.
///
/// ```swift
/// // Generate a signing key
/// let signer = try SLHDSAPureSHA2128f.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try SLHDSAPureSHA2128f.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try SLHDSAPureSHA2128f.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum SLHDSAPureSHA2128f: Sendable {
    static let algorithmName = "SLH_DSA_PURE_SHA2_128F"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: SLHDSAPureSHA2128f.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHA2128f.algorithmName)
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
            try sigSign(algorithm: SLHDSAPureSHA2128f.algorithmName, message: data, secretKey: rawRepresentation)
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
            try sigSign(algorithm: SLHDSAPureSHA2128f.algorithmName, message: data, context: context, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: SLHDSAPureSHA2128f.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: SLHDSAPureSHA2128f.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }

        /// Verifies `signature` over `data` and a context string.
        ///
        /// An empty `context` gives the same result as ``isValidSignature(_:for:)``.
        /// Returns `false` when the signature does not match, when the algorithm takes
        /// no context and `context` is not empty, and when `context` is over 255 bytes.
        /// Throws ``OQSError/invalidKeySize(expected:actual:)`` when the public key has
        /// the wrong length.
        public func isValidSignature(_ signature: Data, for data: Data, context: Data) throws -> Bool {
            try sigVerify(algorithm: SLHDSAPureSHA2128f.algorithmName, message: data, signature: signature, context: context, publicKey: rawRepresentation)
        }
    }
}
