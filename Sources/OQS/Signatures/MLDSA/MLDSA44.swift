import Foundation
internal import Cliboqs

/// ML-DSA-44 digital signatures (NIST standard (FIPS 204), lattice-based, NIST level 2 security).
///
/// FIPS 204 standard, the standardized form of CRYSTALS-Dilithium. A lattice
/// signature scheme whose security rests on the Module-LWE and Module-SIS
/// problems. ML-DSA-44 is the smallest of the three parameter sets, targeting
/// NIST security level 2.
///
/// ```swift
/// // Generate a signing key
/// let signer = try MLDSA44.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try MLDSA44.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try MLDSA44.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum MLDSA44: Sendable {
    static let algorithmName = "ML-DSA-44"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: MLDSA44.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MLDSA44.algorithmName)
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
            try sigSign(algorithm: MLDSA44.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MLDSA44.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: MLDSA44.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
