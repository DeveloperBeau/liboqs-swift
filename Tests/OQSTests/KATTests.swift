import Testing
import Foundation
@testable import OQS

@Suite(.serialized) struct KATTests {
    @Test("ML-KEM-512 KAT digest matches committed hash")
    func mlkem512KAT() throws {
        KAT.seedDeterministicRNG()
        defer { KAT.restoreSystemRNG() }

        let sk = try MLKEM512.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let blob = sk.publicKey.rawRepresentation + sk.rawRepresentation
            + sealed.ciphertext + sealed.sharedSecret.rawRepresentation
        let digest = KAT.sha3_256Hex(blob)

        let expected = try KATHashes.shared.hash(for: "ML-KEM-512")
        #expect(digest == expected)
    }

    @Test("FrodoKEM-640-AES KAT digest matches committed hash")
    func frodo640aesKAT() throws {
        KAT.seedDeterministicRNG()
        defer { KAT.restoreSystemRNG() }
        let sk = try FrodoKEM640AES.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let blob = sk.publicKey.rawRepresentation + sk.rawRepresentation
            + sealed.ciphertext + sealed.sharedSecret.rawRepresentation
        #expect(KAT.sha3_256Hex(blob) == (try KATHashes.shared.hash(for: "FrodoKEM-640-AES")))
    }

    @Test("NTRU-HPS-2048-509 KAT digest matches committed hash")
    func ntruhps2048509KAT() throws {
        KAT.seedDeterministicRNG()
        defer { KAT.restoreSystemRNG() }
        let sk = try NTRUHPS2048509.PrivateKey()
        let sealed = try sk.publicKey.generateSharedSecret()
        let blob = sk.publicKey.rawRepresentation + sk.rawRepresentation
            + sealed.ciphertext + sealed.sharedSecret.rawRepresentation
        #expect(KAT.sha3_256Hex(blob) == (try KATHashes.shared.hash(for: "NTRU-HPS-2048-509")))
    }
}
