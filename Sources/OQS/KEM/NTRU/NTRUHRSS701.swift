import Foundation
internal import Cliboqs

/// NTRU-HRSS-701 key encapsulation (structured-lattice KEM).
///
/// NTRU is a structured-lattice KEM and a NIST Round 3 finalist. This is the
/// HRSS (Hülsing–Rijneveld–Schanck–Schwabe) parameter family with ring degree
/// N = 701. Unlike the fixed-weight HPS variants, HRSS samples its secrets
/// without a fixed Hamming weight. This is the smaller/entry-level NTRU-HRSS
/// parameter set, with more compact keys than NTRU-HRSS-1373.
///
/// ```swift
/// // Alice generates a key pair
/// let alice = try NTRUHRSS701.PrivateKey()
///
/// // Bob gets Alice's public key and creates a shared secret
/// let pub = try NTRUHRSS701.PublicKey(rawRepresentation: alicePublicKeyData)
/// let result = try pub.generateSharedSecret()
/// // Bob has result.sharedSecret. Send result.ciphertext to Alice
///
/// // Alice decrypts it
/// let secret = try alice.decryptSharedSecret(result.ciphertext)
/// // secret == result.sharedSecret
///
/// // Use the shared secret as an AES or ChaCha20 key
/// let key = SymmetricKey(data: secret.rawRepresentation)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = alice.rawRepresentation
/// let loaded = try NTRUHRSS701.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: alice.publicKey.rawRepresentation
/// )
/// ```
public enum NTRUHRSS701: Sendable {
    static let algorithmName = "NTRU-HRSS-701"

    /// A NTRUHRSS701 private (decapsulation) key.
    public struct PrivateKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data
        /// The corresponding public key.
        public let publicKey: PublicKey

        /// Generates a new random key pair.
        public init() throws {
            let kp = try kemGenerateKeyPair(algorithm: NTRUHRSS701.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        /// Imports a private key from raw bytes.
        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: NTRUHRSS701.algorithmName)
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
            let ss = try kemDecapsulate(algorithm: NTRUHRSS701.algorithmName, ciphertext: ciphertext, secretKey: rawRepresentation)
            return SharedSecret(rawRepresentation: ss)
        }
    }

    /// A NTRUHRSS701 public (encapsulation) key.
    public struct PublicKey: Sendable {
        /// The raw key bytes.
        public let rawRepresentation: Data

        /// Imports a public key from raw bytes.
        public init(rawRepresentation: Data) throws {
            let lengths = try kemExpectedKeyLengths(algorithm: NTRUHRSS701.algorithmName)
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
            let result = try kemEncapsulate(algorithm: NTRUHRSS701.algorithmName, publicKey: rawRepresentation)
            return SharedSecretResult(
                sharedSecret: SharedSecret(rawRepresentation: result.sharedSecret),
                ciphertext: result.ciphertext
            )
        }
    }
}
