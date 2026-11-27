import Foundation
internal import Cliboqs

/// ML-KEM-1024 key encapsulation (NIST standard, 256-bit security).
///
/// Maximum strength ML-KEM. Larger keys than ML-KEM-768, but you get the
/// highest security level if that's what your threat model calls for.
///
/// ```swift
/// // Alice generates a key pair
/// let alice = try MLKEM1024.PrivateKey()
///
/// // Bob gets Alice's public key and creates a shared secret
/// let pub = try MLKEM1024.PublicKey(rawRepresentation: alicePublicKeyData)
/// let result = try pub.generateSharedSecret()
/// // Bob has result.sharedSecret. Send result.ciphertext to Alice
///
/// // Alice decrypts it
/// let secret = try alice.decryptSharedSecret(result.ciphertext)
/// // secret == result.sharedSecret
///
/// // Use the 32-byte secret as an AES or ChaCha20 key
/// let key = SymmetricKey(data: secret.rawRepresentation)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = alice.rawRepresentation
/// let loaded = try MLKEM1024.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: alice.publicKey.rawRepresentation
/// )
/// ```
public enum MLKEM1024: Sendable {
    static let algorithmName = "ML-KEM-1024"

    /// A MLKEM1024 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM1024.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Generates the key pair that the given seed determines.
        ///
        /// The same seed always gives the same key pair. The seed must be exactly
        /// 64 bytes. It is secret, because anyone who has it can rebuild the private key,
        /// so wipe your copy once you no longer need it.
        ///
        /// - Parameter seed: The 64 secret seed bytes.
        /// - Throws: ``OQSError/invalidKeySize(expected:actual:)`` if the seed is not 64 bytes,
        ///   or ``OQSError/keyGenerationFailed`` if liboqs reports an error.
        public init(seed: Data) throws {
            let kp = try kemGenerateKeyPair(algorithm: MLKEM1024.algorithmName, seed: seed)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM1024.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: MLKEM1024.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A MLKEM1024 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: MLKEM1024.algorithmName)
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
            let result = try kemEncapsulate(algorithm: MLKEM1024.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }

        /// Generates the shared secret and ciphertext that the given seed determines.
        ///
        /// The same public key and seed always give the same result. The seed must be
        /// exactly 32 bytes. It is secret, because anyone who has it and the public key
        /// can rebuild the shared secret, so wipe your copy once you no longer need it.
        ///
        /// - Parameter seed: The 32 secret seed bytes.
        /// - Throws: ``OQSError/invalidKeySize(expected:actual:)`` if the seed is not 32 bytes,
        ///   or ``OQSError/encapsulationFailed`` if liboqs reports an error.
        public func generateSharedSecret(seed: Data) throws -> SharedSecretResult {
            let result = try kemEncapsulate(algorithm: MLKEM1024.algorithmName, publicKey: rawRepresentation, seed: seed)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
