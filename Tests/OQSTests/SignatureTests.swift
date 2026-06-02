import Testing
import Foundation
@testable import OQS

private let testMessage = Data("Post-quantum cryptography is fun.".utf8)

@Suite struct SignatureTests {

    // MARK: - Round-trip

    @Test("Falcon-512 sign/verify")
    func roundTripFalcon512() throws {
        let signingKey = try Falcon512.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("Falcon-1024 sign/verify")
    func roundTripFalcon1024() throws {
        let signingKey = try Falcon1024.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("FalconPadded-512 sign/verify")
    func roundTripFalconPadded512() throws {
        let signingKey = try FalconPadded512.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("FalconPadded-1024 sign/verify")
    func roundTripFalconPadded1024() throws {
        let signingKey = try FalconPadded1024.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("CROSS-RSDP-128-Fast sign/verify")
    func roundTripCROSS() throws {
        let signingKey = try CrossRSDP128Fast.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("SPHINCS+-SHA2-128f-simple sign/verify")
    func roundTripSPHINCS() throws {
        let signingKey = try SPHINCSSHA2128fSimple.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("SLH-DSA-Pure-SHA2-128f sign/verify")
    func roundTripSLHDSA() throws {
        let signingKey = try SLHDSAPureSHA2128f.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("ML-DSA-44 sign/verify")
    func roundTripMLDSA44() throws {
        let key = try MLDSA44.PrivateKey()
        let sig = try key.signature(for: testMessage)
        #expect(try key.publicKey.isValidSignature(sig, for: testMessage))
    }

    @Test("ML-DSA-65 sign/verify")
    func roundTripMLDSA65() throws {
        let key = try MLDSA65.PrivateKey()
        let sig = try key.signature(for: testMessage)
        #expect(try key.publicKey.isValidSignature(sig, for: testMessage))
    }

    @Test("ML-DSA-87 sign/verify")
    func roundTripMLDSA87() throws {
        let key = try MLDSA87.PrivateKey()
        let sig = try key.signature(for: testMessage)
        #expect(try key.publicKey.isValidSignature(sig, for: testMessage))
    }

    @Test("SNOVA_24_5_4 sign/verify")
    func roundTripSNOVA2454() throws {
        let key = try SNOVA24_5_4.PrivateKey()
        let sig = try key.signature(for: testMessage)
        #expect(try key.publicKey.isValidSignature(sig, for: testMessage))
    }

    // MARK: - Empty message

    @Test("Sign and verify empty message")
    func emptyMessage() throws {
        let signingKey = try Falcon512.PrivateKey()
        let sig = try signingKey.signature(for: Data())
        let valid = try signingKey.publicKey.isValidSignature(sig, for: Data())
        #expect(valid)
    }

    // MARK: - Key uniqueness

    @Test("Key pairs are unique")
    func keyPairUniqueness() throws {
        let a = try Falcon512.PrivateKey()
        let b = try Falcon512.PrivateKey()
        #expect(a.publicKey.rawRepresentation != b.publicKey.rawRepresentation)
        #expect(a.rawRepresentation != b.rawRepresentation)
    }

    // MARK: - Failure: wrong message

    @Test("Verify rejects wrong message")
    func wrongMessage() throws {
        let signingKey = try Falcon512.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let wrong = Data("Wrong message.".utf8)
        let valid = try signingKey.publicKey.isValidSignature(sig, for: wrong)
        #expect(!valid)
    }

    // MARK: - Failure: wrong public key

    @Test("Verify rejects wrong public key")
    func wrongPublicKey() throws {
        let keyA = try Falcon512.PrivateKey()
        let keyB = try Falcon512.PrivateKey()
        let sig = try keyA.signature(for: testMessage)
        let valid = try keyB.publicKey.isValidSignature(sig, for: testMessage)
        #expect(!valid)
    }

    // MARK: - Failure: corrupted signature

    @Test("Verify rejects corrupted signature")
    func corruptedSignature() throws {
        let signingKey = try Falcon512.PrivateKey()
        var sig = try signingKey.signature(for: testMessage)
        sig[sig.count / 2] ^= 0xFF
        let valid = try signingKey.publicKey.isValidSignature(sig, for: testMessage)
        #expect(!valid)
    }

    // MARK: - Failure: truncated signature

    @Test("Verify rejects truncated signature")
    func truncatedSignature() throws {
        let signingKey = try Falcon512.PrivateKey()
        let sig = try signingKey.signature(for: testMessage)
        let truncated = sig.prefix(sig.count / 2)
        let valid = try signingKey.publicKey.isValidSignature(truncated, for: testMessage)
        #expect(!valid)
    }

    // MARK: - Key import round-trip

    @Test("Private key import round-trip")
    func privateKeyImport() throws {
        let original = try Falcon512.PrivateKey()
        let imported = try Falcon512.PrivateKey(
            rawRepresentation: original.rawRepresentation,
            publicKeyRepresentation: original.publicKey.rawRepresentation
        )
        #expect(imported.rawRepresentation == original.rawRepresentation)

        let sig = try imported.signature(for: testMessage)
        let valid = try original.publicKey.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    @Test("Public key import round-trip")
    func publicKeyImport() throws {
        let signingKey = try Falcon512.PrivateKey()
        let imported = try Falcon512.PublicKey(rawRepresentation: signingKey.publicKey.rawRepresentation)

        let sig = try signingKey.signature(for: testMessage)
        let valid = try imported.isValidSignature(sig, for: testMessage)
        #expect(valid)
    }

    // MARK: - Invalid key sizes

    @Test("Public key import rejects wrong size")
    func publicKeyImportInvalidSize() throws {
        #expect(throws: OQSError.self) {
            try Falcon512.PublicKey(rawRepresentation: Data([0x00]))
        }
    }

    @Test("Private key import rejects wrong size")
    func privateKeyImportInvalidSize() throws {
        let key = try Falcon512.PrivateKey()
        #expect(throws: OQSError.self) {
            try Falcon512.PrivateKey(
                rawRepresentation: Data([0x00]),
                publicKeyRepresentation: key.publicKey.rawRepresentation
            )
        }
    }

    // MARK: - Cross-algorithm mismatch

    @Test("Cross-algorithm public key is rejected on import")
    func crossAlgorithmMismatch() throws {
        let key512 = try Falcon512.PrivateKey()
        // Falcon-512 public key size != Falcon-1024 expected size
        #expect(throws: OQSError.self) {
            try Falcon1024.PublicKey(rawRepresentation: key512.publicKey.rawRepresentation)
        }
    }

    // MARK: - Multiple signatures differ

    @Test("Multiple signatures of same message differ")
    func multipleSignaturesDiffer() throws {
        let signingKey = try Falcon512.PrivateKey()
        let sig1 = try signingKey.signature(for: testMessage)
        let sig2 = try signingKey.signature(for: testMessage)
        #expect(sig1 != sig2)
        // Both should still verify
        #expect(try signingKey.publicKey.isValidSignature(sig1, for: testMessage))
        #expect(try signingKey.publicKey.isValidSignature(sig2, for: testMessage))
    }

    // MARK: - SLH-DSA prehash

    @Test("SLH-DSA prehash SHA2-224 / SHA2-128f round-trip")
    func roundTripSLHDSAPrehash() throws {
        let key = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_224, paramSet: .sha2_128f)
        let sig = try key.signature(for: testMessage)
        #expect(try key.publicKey.isValidSignature(sig, for: testMessage))
    }

    @Test("SLH-DSA prehash fast param sets keygen")
    func prehashFastKeygen() throws {
        let fast: [SLHDSA.Prehash.ParamSet] = [.sha2_128f, .sha2_192f, .sha2_256f,
                                               .shake_128f, .shake_192f, .shake_256f]
        for ps in fast {
            _ = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: ps)
        }
    }

    @Test("SLH-DSA prehash key import round-trip")
    func prehashKeyImport() throws {
        let key = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .sha2_128f)
        let imported = try SLHDSA.Prehash.PrivateKey(
            prehash: .sha2_256, paramSet: .sha2_128f,
            rawRepresentation: key.rawRepresentation,
            publicKeyRepresentation: key.publicKey.rawRepresentation
        )
        #expect(imported.rawRepresentation == key.rawRepresentation)
        let sig = try imported.signature(for: testMessage)
        #expect(try imported.publicKey.isValidSignature(sig, for: testMessage))
    }

    @Test("SLH-DSA prehash key import rejects wrong size")
    func prehashKeyImportInvalidSize() {
        #expect(throws: OQSError.self) {
            try SLHDSA.Prehash.PrivateKey(
                prehash: .sha2_256, paramSet: .sha2_128f,
                rawRepresentation: Data([0x00]),
                publicKeyRepresentation: Data([0x00])
            )
        }
    }
}
