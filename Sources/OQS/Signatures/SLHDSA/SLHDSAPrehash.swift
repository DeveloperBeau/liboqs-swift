import Foundation
internal import Cliboqs

/// SLH-DSA in pre-hash mode (FIPS 205 HashSLH-DSA).
///
/// In pre-hash mode the message is first reduced with a chosen pre-hash
/// function (for example SHA2-256 or SHAKE-128) and the resulting digest is
/// then signed by the SLH-DSA core. This matches the FIPS 205 *HashSLH-DSA*
/// construction and is useful when the message has already been hashed, or
/// when a fixed digest size is required by a protocol.
///
/// liboqs exposes 144 distinct pre-hash identifiers (12 pre-hash functions ×
/// 12 parameter sets). Rather than generating 144 wrapper types, this API is
/// parameterized: pick a ``Prehash/Function`` and a ``Prehash/ParamSet``.
///
/// Parameter sets come in two flavors:
/// - `f` (fast): faster signing at the cost of larger signatures.
/// - `s` (small): smaller signatures at the cost of slower signing.
///
/// ```swift
/// // Generate a signing key for a specific (pre-hash, parameter set) pair.
/// let signer = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .sha2_128f)
///
/// // Sign a message (the pre-hash function is applied internally).
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify.
/// let legit = try signer.publicKey.isValidSignature(sig, for: messageData)
/// ```
public enum SLHDSA: Sendable {
    /// A parameterized SLH-DSA pre-hash signature scheme.
    ///
    /// Combine a ``Function`` and a ``ParamSet`` to select one of the 144
    /// FIPS 205 HashSLH-DSA variants exposed by liboqs.
    public enum Prehash: Sendable {
        /// The pre-hash function applied to the message before signing
        /// (FIPS 205 HashSLH-DSA component).
        public enum Function: String, Sendable, CaseIterable {
            case sha2_224  = "SHA2_224"
            case sha2_256  = "SHA2_256"
            case sha2_384  = "SHA2_384"
            case sha2_512  = "SHA2_512"
            case sha2_512_224 = "SHA2_512_224"
            case sha2_512_256 = "SHA2_512_256"
            case sha3_224  = "SHA3_224"
            case sha3_256  = "SHA3_256"
            case sha3_384  = "SHA3_384"
            case sha3_512  = "SHA3_512"
            case shake_128 = "SHAKE_128"
            case shake_256 = "SHAKE_256"
        }

        /// The SLH-DSA parameter set. The trailing `f`/`s` selects the
        /// fast (larger signature) or small (slower) trade-off.
        public enum ParamSet: String, Sendable, CaseIterable {
            case sha2_128f = "SHA2_128F", sha2_128s = "SHA2_128S"
            case sha2_192f = "SHA2_192F", sha2_192s = "SHA2_192S"
            case sha2_256f = "SHA2_256F", sha2_256s = "SHA2_256S"
            case shake_128f = "SHAKE_128F", shake_128s = "SHAKE_128S"
            case shake_192f = "SHAKE_192F", shake_192s = "SHAKE_192S"
            case shake_256f = "SHAKE_256F", shake_256s = "SHAKE_256S"
        }

        static func algorithmName(_ fn: Function, _ ps: ParamSet) -> String {
            "SLH_DSA_\(fn.rawValue)_PREHASH_\(ps.rawValue)"
        }

        /// A private (signing) key for a specific SLH-DSA pre-hash variant.
        ///
        /// ```swift
        /// let signer = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .shake_192f)
        /// let sig = try signer.signature(for: messageData)
        /// ```
        ///
        /// Keys can be saved and reloaded:
        /// ```swift
        /// let saved = signer.rawRepresentation
        /// let loaded = try SLHDSA.Prehash.PrivateKey(
        ///     prehash: .sha2_256, paramSet: .shake_192f,
        ///     rawRepresentation: saved,
        ///     publicKeyRepresentation: signer.publicKey.rawRepresentation
        /// )
        /// ```
        public struct PrivateKey: Sendable {
            public let rawRepresentation: Data
            public let publicKey: PublicKey
            let algorithmName: String

            /// Generates a fresh key pair for the given pre-hash function and parameter set.
            public init(prehash: Function, paramSet: ParamSet) throws {
                let name = Prehash.algorithmName(prehash, paramSet)
                let kp = try sigGenerateKeyPair(algorithm: name)
                self.algorithmName = name
                self.rawRepresentation = kp.secretKey
                self.publicKey = PublicKey(unchecked: kp.publicKey, algorithmName: name)
            }

            /// Reconstructs a key pair from previously saved raw secret and public key bytes.
            public init(prehash: Function, paramSet: ParamSet,
                        rawRepresentation: Data, publicKeyRepresentation: Data) throws {
                let name = Prehash.algorithmName(prehash, paramSet)
                let lengths = try sigExpectedKeyLengths(algorithm: name)
                guard rawRepresentation.count == lengths.secretKey else {
                    throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
                }
                guard publicKeyRepresentation.count == lengths.publicKey else {
                    throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
                }
                self.algorithmName = name
                self.rawRepresentation = rawRepresentation
                self.publicKey = PublicKey(unchecked: publicKeyRepresentation, algorithmName: name)
            }

            /// Signs `data`, applying the configured pre-hash function before the SLH-DSA core.
            public func signature(for data: Data) throws -> Data {
                try sigSign(algorithm: algorithmName, message: data, secretKey: rawRepresentation)
            }
        }

        /// A public (verifying) key for a specific SLH-DSA pre-hash variant.
        ///
        /// ```swift
        /// let pub = try SLHDSA.Prehash.PublicKey(
        ///     prehash: .sha2_256, paramSet: .shake_192f,
        ///     rawRepresentation: savedPublicKeyData
        /// )
        /// let legit = try pub.isValidSignature(sig, for: messageData)
        /// ```
        public struct PublicKey: Sendable {
            public let rawRepresentation: Data
            let algorithmName: String

            /// Reconstructs a public key from previously saved raw bytes.
            public init(prehash: Function, paramSet: ParamSet, rawRepresentation: Data) throws {
                let name = Prehash.algorithmName(prehash, paramSet)
                let lengths = try sigExpectedKeyLengths(algorithm: name)
                guard rawRepresentation.count == lengths.publicKey else {
                    throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
                }
                self.algorithmName = name
                self.rawRepresentation = rawRepresentation
            }

            init(unchecked rawRepresentation: Data, algorithmName: String) {
                self.rawRepresentation = rawRepresentation
                self.algorithmName = algorithmName
            }

            /// Verifies that `signature` is a valid SLH-DSA pre-hash signature over `data`.
            public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
                try sigVerify(algorithm: algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
            }
        }
    }
}
