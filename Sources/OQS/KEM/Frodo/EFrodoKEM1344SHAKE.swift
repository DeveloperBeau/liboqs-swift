import Foundation
internal import Cliboqs

/// eFrodoKEM-1344-SHAKE key encapsulation (NIST Round 3 alternate, ~256-bit security, SHAKE-based PRF).
///
/// Conservative LWE-based KEM at NIST level 5 (~256-bit security). FrodoKEM trades
/// larger keys and ciphertexts than ML-KEM for more conservative security assumptions,
/// relying on plain (unstructured) learning-with-errors. This variant uses SHAKE128 to
/// generate the public matrix A, avoiding any dependency on AES hardware.
///
/// Ephemeral FrodoKEM: the algorithm named FrodoKEM before liboqs 0.16.0,
/// recommended when each keypair encapsulates only a small number of shared
/// secrets. For long-lived keys use the salted ``FrodoKEM1344SHAKE``.
///
/// ```swift
/// // Alice generates a key pair
/// let alice = try EFrodoKEM1344SHAKE.PrivateKey()
///
/// // Bob gets Alice's public key and creates a shared secret
/// let pub = try EFrodoKEM1344SHAKE.PublicKey(rawRepresentation: alicePublicKeyData)
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
/// let loaded = try EFrodoKEM1344SHAKE.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: alice.publicKey.rawRepresentation
/// )
/// ```
public enum EFrodoKEM1344SHAKE: Sendable {
    static let algorithmName = "eFrodoKEM-1344-SHAKE"

    /// An eFrodoKEM-1344-SHAKE private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The secret key bytes, held in storage that is wiped when the key is released.
        public let rawRepresentation: SecretBytes
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: EFrodoKEM1344SHAKE.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: EFrodoKEM1344SHAKE.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: EFrodoKEM1344SHAKE.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// An eFrodoKEM-1344-SHAKE public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: EFrodoKEM1344SHAKE.algorithmName)
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
            let result = try kemEncapsulate(algorithm: EFrodoKEM1344SHAKE.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
