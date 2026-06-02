import Testing
import Foundation
@testable import OQS

@Suite struct KEMTests {

    // MARK: - Round-trip

    @Test("ML-KEM-512 round-trip")
    func roundTrip512() throws {
        let privateKey = try MLKEM512.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("ML-KEM-768 round-trip")
    func roundTrip768() throws {
        let privateKey = try MLKEM768.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("ML-KEM-1024 round-trip")
    func roundTrip1024() throws {
        let privateKey = try MLKEM1024.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("HQC-128 round-trip")
    func roundTripHQC128() throws {
        let privateKey = try HQC128.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("HQC-192 round-trip")
    func roundTripHQC192() throws {
        let privateKey = try HQC192.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("HQC-256 round-trip")
    func roundTripHQC256() throws {
        let privateKey = try HQC256.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("Classic McEliece 348864 round-trip")
    func roundTripMcEliece() throws {
        let privateKey = try ClassicMcEliece348864.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-640-AES round-trip")
    func roundTripFrodo640AES() throws {
        let sk = try FrodoKEM640AES.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-640-SHAKE round-trip")
    func roundTripFrodo640SHAKE() throws {
        let sk = try FrodoKEM640SHAKE.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-976-AES round-trip")
    func roundTripFrodo976AES() throws {
        let sk = try FrodoKEM976AES.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-976-SHAKE round-trip")
    func roundTripFrodo976SHAKE() throws {
        let sk = try FrodoKEM976SHAKE.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-1344-AES round-trip")
    func roundTripFrodo1344AES() throws {
        let sk = try FrodoKEM1344AES.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("FrodoKEM-1344-SHAKE round-trip")
    func roundTripFrodo1344SHAKE() throws {
        let sk = try FrodoKEM1344SHAKE.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let secret = try sk.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    // MARK: - Key pair uniqueness

    @Test("Key pairs are unique")
    func keyPairUniqueness() throws {
        let a = try MLKEM768.PrivateKey()
        let b = try MLKEM768.PrivateKey()
        #expect(a.publicKey.rawRepresentation != b.publicKey.rawRepresentation)
        #expect(a.rawRepresentation != b.rawRepresentation)
    }

    // MARK: - Multiple encapsulations produce different ciphertexts

    @Test("Multiple shared secret generations differ")
    func multipleGenerations() throws {
        let privateKey = try MLKEM768.PrivateKey()
        let first = try privateKey.publicKey.generateSharedSecret()
        let second = try privateKey.publicKey.generateSharedSecret()
        #expect(first.ciphertext != second.ciphertext)
        #expect(first.sharedSecret.rawRepresentation != second.sharedSecret.rawRepresentation)
    }

    // MARK: - Wrong secret key

    @Test("Decrypt with wrong secret key produces different secret")
    func wrongSecretKey() throws {
        let keyA = try MLKEM768.PrivateKey()
        let keyB = try MLKEM768.PrivateKey()
        let sealed = try keyA.publicKey.generateSharedSecret()

        // liboqs may return a different secret or throw depending on the algorithm
        do {
            let decrypted = try keyB.decryptSharedSecret(sealed.ciphertext)
            #expect(decrypted.rawRepresentation != sealed.sharedSecret.rawRepresentation)
        } catch {
            // acceptable: some algorithms throw on decryption failure
        }
    }

    // MARK: - Key import round-trip

    @Test("Private key import round-trip")
    func privateKeyImport() throws {
        let original = try MLKEM768.PrivateKey()
        let imported = try MLKEM768.PrivateKey(
            rawRepresentation: original.rawRepresentation,
            publicKeyRepresentation: original.publicKey.rawRepresentation
        )
        #expect(imported.rawRepresentation == original.rawRepresentation)
        #expect(imported.publicKey.rawRepresentation == original.publicKey.rawRepresentation)

        // Imported key should still work for decryption
        let sealed = try original.publicKey.generateSharedSecret()
        let secret = try imported.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    @Test("Public key import round-trip")
    func publicKeyImport() throws {
        let privateKey = try MLKEM768.PrivateKey()
        let imported = try MLKEM768.PublicKey(rawRepresentation: privateKey.publicKey.rawRepresentation)
        #expect(imported.rawRepresentation == privateKey.publicKey.rawRepresentation)

        // Imported public key should work for generating shared secrets
        let sealed = try imported.generateSharedSecret()
        let secret = try privateKey.decryptSharedSecret(sealed.ciphertext)
        #expect(secret.rawRepresentation == sealed.sharedSecret.rawRepresentation)
    }

    // MARK: - Invalid key sizes

    @Test("Public key import rejects wrong size")
    func publicKeyImportInvalidSize() throws {
        #expect(throws: OQSError.self) {
            try MLKEM768.PublicKey(rawRepresentation: Data([0x00]))
        }
    }

    @Test("Private key import rejects wrong size")
    func privateKeyImportInvalidSize() throws {
        let key = try MLKEM768.PrivateKey()
        #expect(throws: OQSError.self) {
            try MLKEM768.PrivateKey(
                rawRepresentation: Data([0x00]),
                publicKeyRepresentation: key.publicKey.rawRepresentation
            )
        }
    }

    @Test("Private key import rejects wrong public key size")
    func privateKeyImportInvalidPublicKeySize() throws {
        let key = try MLKEM768.PrivateKey()
        #expect(throws: OQSError.self) {
            try MLKEM768.PrivateKey(
                rawRepresentation: key.rawRepresentation,
                publicKeyRepresentation: Data([0x00])
            )
        }
    }

    // MARK: - Empty inputs

    @Test("Public key import rejects empty data")
    func publicKeyImportEmpty() throws {
        #expect(throws: OQSError.self) {
            try MLKEM768.PublicKey(rawRepresentation: Data())
        }
    }

    @Test("Private key import rejects empty secret key")
    func privateKeyImportEmptySecret() throws {
        #expect(throws: OQSError.self) {
            try MLKEM768.PrivateKey(
                rawRepresentation: Data(),
                publicKeyRepresentation: Data()
            )
        }
    }

    // MARK: - Cross-algorithm mismatch

    @Test("Cross-algorithm public key is rejected on import")
    func crossAlgorithmMismatch() throws {
        let key512 = try MLKEM512.PrivateKey()
        // ML-KEM-512 public key size != ML-KEM-768 expected size
        #expect(throws: OQSError.self) {
            try MLKEM768.PublicKey(rawRepresentation: key512.publicKey.rawRepresentation)
        }
    }

    // MARK: - Truncated ciphertext

    @Test("Truncated ciphertext is rejected")
    func truncatedCiphertext() throws {
        let privateKey = try MLKEM768.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let truncated = sealed.ciphertext.prefix(sealed.ciphertext.count - 1)
        #expect(throws: OQSError.self) {
            try privateKey.decryptSharedSecret(truncated)
        }
    }

    // MARK: - Extended ciphertext

    @Test("Extended ciphertext is rejected")
    func extendedCiphertext() throws {
        let privateKey = try MLKEM768.PrivateKey()
        let sealed = try privateKey.publicKey.generateSharedSecret()
        let extended = sealed.ciphertext + Data([0x00])
        #expect(throws: OQSError.self) {
            try privateKey.decryptSharedSecret(extended)
        }
    }
}
