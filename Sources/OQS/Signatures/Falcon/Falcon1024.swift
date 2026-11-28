import Foundation
internal import Cliboqs

/// Falcon-1024 digital signatures (lattice-based, compact signatures, 256-bit security).
///
/// Higher security Falcon variant. Signatures are still compact compared to
/// hash-based schemes.
///
/// ```swift
/// // Generate a signing key
/// let signer = try Falcon1024.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try Falcon1024.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try Falcon1024.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum Falcon1024: Sendable {
    static let algorithmName = "Falcon-1024"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: SecretBytes
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: Falcon1024.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: Falcon1024.algorithmName)
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
            try sigSign(algorithm: Falcon1024.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: Falcon1024.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: Falcon1024.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
