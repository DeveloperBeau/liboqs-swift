import Foundation
internal import Cliboqs

/// mqom2_cat1_gf16_fast_r5 digital signatures (MQOM2, MPC-in-the-head multivariate, NIST category 1, fast profile, 5 rounds).
///
/// MQOM2 ("MQ on my Mind") is a third-round candidate in NIST's Additional
/// Digital Signatures process. Security reduces to the hardness of solving
/// random multivariate quadratic systems over GF(16), proven via an
/// MPC-in-the-head zero-knowledge argument. The "fast" trade-off favors signing/verification speed over signature size;
/// r5 uses 5 rounds (slower, smaller signatures).
///
/// - Warning: Signing uses large on-stack buffers. On a thread with a small
///   stack (e.g. a dispatch-queue or test-runner thread),
///   ``PrivateKey/signature(for:)`` can crash with an uncatchable SIGBUS
///   rather than throwing. Sign on the main thread or a thread with a
///   several-MB stack. Key generation and verification are unaffected.
///
/// ```swift
/// // Generate a signing key
/// let signer = try MQOM2Cat1GF16FastR5.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try MQOM2Cat1GF16FastR5.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try MQOM2Cat1GF16FastR5.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum MQOM2Cat1GF16FastR5: Sendable {
    static let algorithmName = "mqom2_cat1_gf16_fast_r5"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: SecretBytes
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: MQOM2Cat1GF16FastR5.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MQOM2Cat1GF16FastR5.algorithmName)
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
            try sigSign(algorithm: MQOM2Cat1GF16FastR5.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: MQOM2Cat1GF16FastR5.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: MQOM2Cat1GF16FastR5.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
