import Foundation
internal import Cliboqs

func kemGenerateKeyPair(algorithm: String) throws -> (publicKey: Data, secretKey: Data) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let pkLen = Int(kem.pointee.length_public_key)
    let skLen = Int(kem.pointee.length_secret_key)
    var publicKey = Data(count: pkLen)
    var secretKey = Data(count: skLen)

    let rc = publicKey.withUnsafeMutableBytes { pk in
        secretKey.withUnsafeMutableBytes { sk in
            oqs_kem_keypair_safe(kem, pk, sk)
        }
    }
    guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

    return (publicKey: publicKey, secretKey: secretKey)
}

func kemEncapsulate(algorithm: String, publicKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let expectedPK = Int(kem.pointee.length_public_key)
    guard publicKey.count == expectedPK else {
        throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
    }

    let ctLen = Int(kem.pointee.length_ciphertext)
    let ssLen = Int(kem.pointee.length_shared_secret)
    var ciphertext = Data(count: ctLen)
    var sharedSecret = Data(count: ssLen)

    let rc = publicKey.withUnsafeBytes { pk in
        ciphertext.withUnsafeMutableBytes { ct in
            sharedSecret.withUnsafeMutableBytes { ss in
                oqs_kem_encaps_safe(kem, ct, ss, pk)
            }
        }
    }
    guard rc == OQS_SUCCESS else { throw OQSError.encapsulationFailed }

    return (ciphertext: ciphertext, sharedSecret: sharedSecret)
}

func kemDecapsulate(algorithm: String, ciphertext: Data, secretKey: Data) throws -> Data {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let expectedSK = Int(kem.pointee.length_secret_key)
    guard secretKey.count == expectedSK else {
        throw OQSError.invalidKeySize(expected: expectedSK, actual: secretKey.count)
    }
    let expectedCT = Int(kem.pointee.length_ciphertext)
    guard ciphertext.count == expectedCT else {
        throw OQSError.invalidKeySize(expected: expectedCT, actual: ciphertext.count)
    }

    let ssLen = Int(kem.pointee.length_shared_secret)
    var sharedSecret = Data(count: ssLen)

    let rc = ciphertext.withUnsafeBytes { ct in
        secretKey.withUnsafeBytes { sk in
            sharedSecret.withUnsafeMutableBytes { ss in
                oqs_kem_decaps_safe(kem, ss, ct, sk)
            }
        }
    }
    guard rc == OQS_SUCCESS else { throw OQSError.decapsulationFailed }

    return sharedSecret
}

func kemExpectedKeyLengths(algorithm: String) throws -> (publicKey: Int, secretKey: Int, ciphertext: Int, sharedSecret: Int) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    return (
        publicKey: Int(kem.pointee.length_public_key),
        secretKey: Int(kem.pointee.length_secret_key),
        ciphertext: Int(kem.pointee.length_ciphertext),
        sharedSecret: Int(kem.pointee.length_shared_secret)
    )
}
