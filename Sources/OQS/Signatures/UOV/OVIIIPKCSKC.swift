import Foundation
internal import Cliboqs

/// OV-III-pkc-skc digital signatures (Unbalanced Oil-and-Vinegar multivariate scheme, NIST additional-signatures candidate).
///
/// UOV is the classic Unbalanced Oil-and-Vinegar multivariate signature scheme,
/// submitted to the NIST additional digital-signature standardization effort.
/// Its security rests on the hardness of solving structured systems of
/// multivariate quadratic equations. UOV trades very large public keys for very
/// small signatures (96–260 bytes) and fast verification. OV-III-pkc-skc is the level-3 parameter set with both a compressed public key and a compressed secret key (`-pkc-skc`): the secret key is a 32-byte seed and the public key is expanded on use, minimizing storage.
///
/// ```swift
/// // Generate a signing key
/// let signer = try OVIIIPKCSKC.PrivateKey()
///
/// // Sign something
/// let sig = try signer.signature(for: messageData)
///
/// // Anyone with the public key can verify
/// let pub = try OVIIIPKCSKC.PublicKey(rawRepresentation: signerPublicKeyData)
/// let legit = try pub.isValidSignature(sig, for: messageData)
/// ```
///
/// Keys can be saved and loaded:
/// ```swift
/// let saved = signer.rawRepresentation
/// let loaded = try OVIIIPKCSKC.PrivateKey(
///     rawRepresentation: saved,
///     publicKeyRepresentation: signer.publicKey.rawRepresentation
/// )
/// ```
public enum OVIIIPKCSKC: Sendable {
    static let algorithmName = "OV-III-pkc-skc"

    public struct PrivateKey: Sendable {
        public let rawRepresentation: Data
        public let publicKey: PublicKey

        public init() throws {
            let kp = try sigGenerateKeyPair(algorithm: OVIIIPKCSKC.algorithmName)
            self.rawRepresentation = kp.secretKey
            self.publicKey = PublicKey(unchecked: kp.publicKey)
        }

        public init(rawRepresentation: Data, publicKeyRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: OVIIIPKCSKC.algorithmName)
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
            try sigSign(algorithm: OVIIIPKCSKC.algorithmName, message: data, secretKey: rawRepresentation)
        }
    }

    public struct PublicKey: Sendable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let lengths = try sigExpectedKeyLengths(algorithm: OVIIIPKCSKC.algorithmName)
            guard rawRepresentation.count == lengths.publicKey else {
                throw OQSError.invalidKeySize(expected: lengths.publicKey, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }

        init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }

        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try sigVerify(algorithm: OVIIIPKCSKC.algorithmName, message: data, signature: signature, publicKey: rawRepresentation)
        }
    }
}
