import Foundation
internal import Cliboqs

func kemGenerateKeyPair(algorithm: String) throws -> (publicKey: Data, secretKey: SecretBytes) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let pkLen = Int(kem.pointee.length_public_key)
    let skLen = Int(kem.pointee.length_secret_key)
    var publicKey = Data(count: pkLen)
    let secretKey = try SecretBytes(memory: LiboqsSecretMemory(), count: skLen) { sk in
        #if OQS_SAFE_INTEROP
        let rc = publicKey.withUnsafeMutableBytes { pk in
            oqs_kem_keypair_safe(kem, pk, sk)
        }
        #else
        let rc = publicKey.withUnsafeMutableBytes { pk in
            OQS_KEM_keypair(kem,
                pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
        }
        #endif
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }
    }

    return (publicKey: publicKey, secretKey: secretKey)
}

func kemEncapsulate(algorithm: String, publicKey: Data) throws -> (ciphertext: Data, sharedSecret: SecretBytes) {
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
    let sharedSecret = try SecretBytes(memory: LiboqsSecretMemory(), count: ssLen) { ss in
        #if OQS_SAFE_INTEROP
        let rc = publicKey.withUnsafeBytes { pk in
            ciphertext.withUnsafeMutableBytes { ct in
                oqs_kem_encaps_safe(kem, ct, ss, pk)
            }
        }
        #else
        let rc = publicKey.withUnsafeBytes { pk in
            ciphertext.withUnsafeMutableBytes { ct in
                OQS_KEM_encaps(kem,
                    ct.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ss.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    pk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        #endif
        guard rc == OQS_SUCCESS else { throw OQSError.encapsulationFailed }
    }

    return (ciphertext: ciphertext, sharedSecret: sharedSecret)
}

/// Generates a key pair from `seed` with `OQS_KEM_keypair_derand`.
///
/// The algorithm must have a keypair seed, and `seed` must be exactly that long.
/// The caller owns `seed` and is responsible for wiping it.
func kemGenerateKeyPair(algorithm: String, seed: Data) throws -> (publicKey: Data, secretKey: SecretBytes) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let seedLen = Int(kem.pointee.length_keypair_seed)
    guard seedLen != 0 else { throw OQSError.seedNotSupported }
    guard seed.count == seedLen else {
        throw OQSError.invalidKeySize(expected: seedLen, actual: seed.count)
    }

    let pkLen = Int(kem.pointee.length_public_key)
    let skLen = Int(kem.pointee.length_secret_key)
    var publicKey = Data(count: pkLen)
    let secretKey = try SecretBytes(memory: LiboqsSecretMemory(), count: skLen) { sk in
        #if OQS_SAFE_INTEROP
        let rc = publicKey.withUnsafeMutableBytes { pk in
            seed.withUnsafeBytes { seedBytes in
                oqs_kem_keypair_derand_safe(kem, pk, sk, seedBytes)
            }
        }
        #else
        let rc = publicKey.withUnsafeMutableBytes { pk in
            seed.withUnsafeBytes { seedBytes in
                OQS_KEM_keypair_derand(kem,
                    pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    seedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        #endif
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }
    }

    return (publicKey: publicKey, secretKey: secretKey)
}

/// Encapsulates to `publicKey` with `seed` through `OQS_KEM_encaps_derand`.
///
/// The algorithm must have an encapsulation seed. The seed length is checked
/// before the public key length. The caller owns `seed` and is responsible for wiping it.
func kemEncapsulate(algorithm: String, publicKey: Data, seed: Data) throws -> (ciphertext: Data, sharedSecret: SecretBytes) {
    ensureInitialized()

    guard let kem = OQS_KEM_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_KEM_free(kem) }

    let seedLen = Int(kem.pointee.length_encaps_seed)
    guard seedLen != 0 else { throw OQSError.seedNotSupported }
    guard seed.count == seedLen else {
        throw OQSError.invalidKeySize(expected: seedLen, actual: seed.count)
    }
    let expectedPK = Int(kem.pointee.length_public_key)
    guard publicKey.count == expectedPK else {
        throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
    }

    let ctLen = Int(kem.pointee.length_ciphertext)
    let ssLen = Int(kem.pointee.length_shared_secret)
    var ciphertext = Data(count: ctLen)
    let sharedSecret = try SecretBytes(memory: LiboqsSecretMemory(), count: ssLen) { ss in
        #if OQS_SAFE_INTEROP
        let rc = publicKey.withUnsafeBytes { pk in
            ciphertext.withUnsafeMutableBytes { ct in
                seed.withUnsafeBytes { seedBytes in
                    oqs_kem_encaps_derand_safe(kem, ct, ss, pk, seedBytes)
                }
            }
        }
        #else
        let rc = publicKey.withUnsafeBytes { pk in
            ciphertext.withUnsafeMutableBytes { ct in
                seed.withUnsafeBytes { seedBytes in
                    OQS_KEM_encaps_derand(kem,
                        ct.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ss.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        seedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        #endif
        guard rc == OQS_SUCCESS else { throw OQSError.encapsulationFailed }
    }

    return (ciphertext: ciphertext, sharedSecret: sharedSecret)
}

func kemDecapsulate(algorithm: String, ciphertext: Data, secretKey: SecretBytes) throws -> SecretBytes {
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
    return try SecretBytes(memory: LiboqsSecretMemory(), count: ssLen) { ss in
        #if OQS_SAFE_INTEROP
        let rc = ciphertext.withUnsafeBytes { ct in
            secretKey.withUnsafeBytes { sk in
                oqs_kem_decaps_safe(kem, ss, ct, sk)
            }
        }
        #else
        let rc = ciphertext.withUnsafeBytes { ct in
            secretKey.withUnsafeBytes { sk in
                OQS_KEM_decaps(kem,
                    ss.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ct.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        #endif
        guard rc == OQS_SUCCESS else { throw OQSError.decapsulationFailed }
    }
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
