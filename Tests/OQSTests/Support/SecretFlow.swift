import Foundation
@testable import OQS

/// What a caller sees when a key is used, exported, rebuilt and used again.
struct SecretFlow: Sendable {
    /// What a flipped ciphertext byte did to decapsulation.
    enum Tampered: Sendable, Equatable { case threw, differs, same }

    /// KEM: both sides hold equal shared secrets. Signature: the signature verifies.
    var original: Bool
    /// KEM: a key rebuilt from the exported bytes opens to the same secret. Signature: it signs and the signature verifies.
    var rebuilt: Bool
    /// The shared secret length of a KEM, 0 for a signature.
    var secretLength: Int
    /// KEM only: the result of decapsulating a tampered ciphertext.
    var tampered: Tampered?
    /// The error an import of a key one byte short gives.
    var wrongLengthError: OQSError?
    /// True if the text of that error holds the leading key bytes as hex.
    var errorShowsKey: Bool
}

extension SecretFlow {
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    static func kem<K: ParityKEMPrivateKey>(_ make: () throws -> K) throws -> SecretFlow {
        let key = try make()
        let sealed = try key.publicKey.generateSharedSecret()
        let opened = try key.decryptSharedSecret(sealed.ciphertext)

        let exported = key.rawRepresentation.makeData()
        let rebuilt = try K(rawRepresentation: SecretBytes(copying: exported), publicKeyRepresentation: key.publicKey.rawRepresentation)
        let reopened = try rebuilt.decryptSharedSecret(sealed.ciphertext)

        var bad = sealed.ciphertext
        bad[bad.startIndex] ^= 0x01
        let tampered: Tampered
        do {
            tampered = try key.decryptSharedSecret(bad) == sealed.sharedSecret ? .same : .differs
        } catch {
            tampered = .threw
        }

        let (wrong, shows) = wrongLength(exported: exported) {
            _ = try K(rawRepresentation: SecretBytes(copying: $0), publicKeyRepresentation: key.publicKey.rawRepresentation)
        }
        return SecretFlow(
            original: opened == sealed.sharedSecret, rebuilt: reopened == sealed.sharedSecret,
            secretLength: sealed.sharedSecret.rawRepresentation.count,
            tampered: tampered, wrongLengthError: wrong, errorShowsKey: shows)
    }

    static func signature<K: ParitySigPrivateKey>(
        _ make: () throws -> K, rebuild: (SecretBytes, Data) throws -> K
    ) throws -> SecretFlow {
        let message = Data("secret flow message".utf8)
        let key = try make()
        let signature = try key.signature(for: message)
        let original = try key.publicKey.isValidSignature(signature, for: message)

        let exported = key.rawRepresentation.makeData()
        let publicKey = key.publicKey.rawRepresentation
        let rebuilt = try rebuild(SecretBytes(copying: exported), publicKey)
        let again = try rebuilt.signature(for: message)
        let worksAgain = try key.publicKey.isValidSignature(again, for: message)

        let (wrong, shows) = wrongLength(exported: exported) { _ = try rebuild(SecretBytes(copying: $0), publicKey) }
        return SecretFlow(
            original: original, rebuilt: worksAgain, secretLength: 0,
            tampered: nil, wrongLengthError: wrong, errorShowsKey: shows)
    }

    /// Tries `body` with the exported key cut by one byte and reports the error and whether its text shows key bytes.
    private static func wrongLength(exported: Data, _ body: (Data) throws -> Void) -> (OQSError?, Bool) {
        do {
            try body(exported.dropLast())
            return (nil, false)
        } catch let error as OQSError {
            return (error, "\(error)".contains(hex(exported.prefix(8))) || "\(error)".contains(exported.prefix(8).base64EncodedString()))
        } catch {
            return (nil, false)
        }
    }
}
