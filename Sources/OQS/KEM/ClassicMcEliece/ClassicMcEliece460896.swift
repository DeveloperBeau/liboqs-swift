import Foundation
internal import Cliboqs

/// Classic McEliece 460896 key encapsulation (conservative choice, studied for 50+ years, but with very large keys).
///
/// Larger parameter set with higher security. Same trade-off as all Classic
/// McEliece variants: very large public keys, but rock-solid security assumptions.
///
/// ```swift
/// // Alice generates a key pair
/// let alice = try ClassicMcEliece460896.PrivateKey()
///
/// // Bob gets Alice's public key and creates a shared secret
/// let pub = try ClassicMcEliece460896.PublicKey(rawRepresentation: alicePublicKeyData)
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
/// let loaded = try ClassicMcEliece460896.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: alice.publicKey.rawRepresentation
/// )
/// ```
public enum ClassicMcEliece460896: Sendable {
    static let algorithmName = "Classic-McEliece-460896"

    /// A ClassicMcEliece460896 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The secret key bytes, held in storage that is wiped when the key is released.
        public let rawRepresentation: SecretBytes
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: ClassicMcEliece460896.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece460896.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: ClassicMcEliece460896.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A ClassicMcEliece460896 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: ClassicMcEliece460896.algorithmName)
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
            let result = try kemEncapsulate(algorithm: ClassicMcEliece460896.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
