import Foundation
internal import Cliboqs

/// Falcon-Padded-512 digital signatures (constant-size signatures, padded variant, 128-bit security).
///
/// Same security as Falcon-512, but signatures are padded to a fixed size.
/// Handy when you need predictable signature lengths in a wire protocol.
///
/// ```swift
/// // Generate a signing key
/// let signer = try FalconPadded512.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try FalconPadded512.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try FalconPadded512.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum FalconPadded512: Sendable {
    static let algorithmName = "Falcon-padded-512"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: SecretBytes
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: FalconPadded512.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: FalconPadded512.algorithmName)
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
            try sigSign(algorithm: FalconPadded512.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: FalconPadded512.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: FalconPadded512.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
