import Testing
import Foundation
@testable import OQS

/// A quick check of the key flow on one KEM and one signature type, so the
/// mutation run can target it. SecretFlowTests covers every type.
@Suite struct SecretKeyFlowTests {
    @Test("ML-KEM-768: a key rebuilt from its exported bytes opens the same secret, and a tampered ciphertext gives a different one")
    func mlkemKeyFlow() throws {
        let flow = try SecretFlow.kem { try MLKEM768.PrivateKey() }
        #expect(flow.original)
        #expect(flow.rebuilt)
        #expect(flow.secretLength == 32)
        #expect(flow.tampered == .differs)
    }

    @Test("ML-DSA-44: the signature verifies and a key rebuilt from its exported bytes signs signatures that verify")
    func mldsaKeyFlow() throws {
        let flow = try SecretFlow.signature({ try MLDSA44.PrivateKey() },
                                            rebuild: { try MLDSA44.PrivateKey(rawRepresentation: $0, publicKeyRepresentation: $1) })
        #expect(flow.original)
        #expect(flow.rebuilt)
    }

    @Test("A private key of the wrong length is rejected with the expected and actual lengths, and the error does not show the key")
    func wrongLengthImport() throws {
        let kem = try SecretFlow.kem { try MLKEM768.PrivateKey() }
        #expect(kem.wrongLengthError == .invalidKeySize(expected: 2400, actual: 2399))
        #expect(!kem.errorShowsKey)
        let sig = try SecretFlow.signature({ try MLDSA44.PrivateKey() },
                                           rebuild: { try MLDSA44.PrivateKey(rawRepresentation: $0, publicKeyRepresentation: $1) })
        #expect(sig.wrongLengthError == .invalidKeySize(expected: 2560, actual: 2559))
        #expect(!sig.errorShowsKey)
    }

    @Test("A private key of the right length but other bytes is a different key that does not open the original secret")
    func otherKeyOpensOtherSecret() throws {
        let key = try MLKEM768.PrivateKey()
        let sealed = try key.publicKey.generateSharedSecret()
        var bytes = key.rawRepresentation.makeData()
        bytes[0] ^= 0xFF
        let other = try MLKEM768.PrivateKey(rawRepresentation: SecretBytes(copying: bytes), publicKeyRepresentation: key.publicKey.rawRepresentation)
        #expect(try other.decryptSharedSecret(sealed.ciphertext) != sealed.sharedSecret)
        #expect(try key.decryptSharedSecret(sealed.ciphertext) == sealed.sharedSecret)
    }
}
