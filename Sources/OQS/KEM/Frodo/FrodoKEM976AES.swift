import Foundation
internal import Cliboqs

/// FrodoKEM-976-AES key encapsulation (NIST Round 3 alternate, ~192-bit security, AES-based PRF).
public enum FrodoKEM976AES: Sendable {
    static let algorithmName = "FrodoKEM-976-AES"

    /// A FrodoKEM-976-AES private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: FrodoKEM976AES.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: FrodoKEM976AES.algorithmName)
            guard rawRepresentation.count == lengths.secretKey else {
                throw OQSError.invalidKeySize(expected: lengths.secretKey, actual: rawRepresentation.count)
            }
            guard publicKeyRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: publicKeyRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
            self.publicKey = PublicKey(unchecked: publicKeyRepresentation)
        }

        /// Decrypts a shared secret from the given ciphertext.
        public func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret {
            let ss = try kemDecapsulate(algorithm: FrodoKEM976AES.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A FrodoKEM-976-AES public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: FrodoKEM976AES.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        /// Generates a new shared secret using this public key.
        public func generateSharedSecret() throws -> SharedSecretResult {
            let result = try kemEncapsulate(algorithm: FrodoKEM976AES.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
