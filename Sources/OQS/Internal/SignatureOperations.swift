import Foundation
internal import Cliboqs

func sigGenerateKeyPair(algorithm: String) throws -> (publicKey: Data, secretKey: Data) {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    let pkLen = Int(sig.pointee.length_public_key)
    let skLen = Int(sig.pointee.length_secret_key)
    var publicKey = Data(count: pkLen)
    var secretKey = Data(count: skLen)

    #if OQS_SAFE_INTEROP
    let rc = publicKey.withUnsafeMutableBytes { pk in
        secretKey.withUnsafeMutableBytes { sk in
            oqs_sig_keypair_safe(sig, pk, sk)
        }
    }
    #else
    let rc = publicKey.withUnsafeMutableBytes { pk in
        secretKey.withUnsafeMutableBytes { sk in
            OQS_SIG_keypair(sig,
                pk.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
        }
    }
    #endif
    guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

    return (publicKey: publicKey, secretKey: secretKey)
}

func sigSign(algorithm: String, message: Data, secretKey: Data) throws -> Data {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    let expectedSK = Int(sig.pointee.length_secret_key)
    guard secretKey.count == expectedSK else {
        throw OQSError.invalidKeySize(expected: expectedSK, actual: secretKey.count)
    }

    let maxSigLen = Int(sig.pointee.length_signature)
    var signature = Data(count: maxSigLen)
    var actualSigLen = 0

    #if OQS_SAFE_INTEROP
    let rc = message.withUnsafeBytes { msg in
        secretKey.withUnsafeBytes { sk in
            signature.withUnsafeMutableBytes { sigBuf in
                oqs_sig_sign_safe(sig, sigBuf, &actualSigLen, msg, sk)
            }
        }
    }
    #else
    let rc = message.withUnsafeBytes { msg in
        secretKey.withUnsafeBytes { sk in
            signature.withUnsafeMutableBytes { sigBuf in
                OQS_SIG_sign(sig,
                    sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &actualSigLen,
                    msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    message.count,
                    sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
    }
    #endif
    guard rc == OQS_SUCCESS else { throw OQSError.signFailed }

    signature.removeSubrange(actualSigLen...)
    return signature
}

func sigVerify(algorithm: String, message: Data, signature: Data, publicKey: Data) throws -> Bool {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    let expectedPK = Int(sig.pointee.length_public_key)
    guard publicKey.count == expectedPK else {
        throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
    }

    #if OQS_SAFE_INTEROP
    let rc = message.withUnsafeBytes { msg in
        signature.withUnsafeBytes { sigBuf in
            publicKey.withUnsafeBytes { pk in
                oqs_sig_verify_safe(sig, msg, sigBuf, pk)
            }
        }
    }
    #else
    let rc = message.withUnsafeBytes { msg in
        signature.withUnsafeBytes { sigBuf in
            publicKey.withUnsafeBytes { pk in
                OQS_SIG_verify(sig,
                    msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    message.count,
                    sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signature.count,
                    pk.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
    }
    #endif

    return rc == OQS_SUCCESS
}

/// The longest context string, in bytes, that liboqs accepts.
let sigMaxContextLength = 255

/// Whether the algorithm takes a non-empty context string, read from the liboqs object.
func sigSupportsContext(algorithm: String) throws -> Bool {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    return sig.pointee.sig_with_ctx_support
}

func sigSign(algorithm: String, message: Data, context: Data, secretKey: Data) throws -> Data {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    // Same order as the Rust port: support, key size, context length.
    if !context.isEmpty && !sig.pointee.sig_with_ctx_support {
        throw OQSError.contextNotSupported
    }
    let expectedSK = Int(sig.pointee.length_secret_key)
    guard secretKey.count == expectedSK else {
        throw OQSError.invalidKeySize(expected: expectedSK, actual: secretKey.count)
    }
    guard context.count <= sigMaxContextLength else {
        throw OQSError.contextTooLong
    }

    let maxSigLen = Int(sig.pointee.length_signature)
    var signature = Data(count: maxSigLen)
    var actualSigLen = 0

    // An empty Data can still have a base address, but liboqs wants NULL and length 0.
    #if OQS_SAFE_INTEROP
    let rc = message.withUnsafeBytes { msg in
        context.withUnsafeBytes { ctx in
            secretKey.withUnsafeBytes { sk in
                signature.withUnsafeMutableBytes { sigBuf in
                    oqs_sig_sign_with_ctx_str_safe(sig, sigBuf, &actualSigLen, msg, context.isEmpty ? nil : ctx, sk)
                }
            }
        }
    }
    #else
    let rc = message.withUnsafeBytes { msg in
        context.withUnsafeBytes { ctx in
            secretKey.withUnsafeBytes { sk in
                signature.withUnsafeMutableBytes { sigBuf in
                    OQS_SIG_sign_with_ctx_str(sig,
                        sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &actualSigLen,
                        msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count,
                        context.isEmpty ? nil : ctx.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        context.count,
                        sk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
    }
    #endif
    guard rc == OQS_SUCCESS else { throw OQSError.signFailed }

    signature.removeSubrange(actualSigLen...)
    return signature
}

func sigVerify(algorithm: String, message: Data, signature: Data, context: Data, publicKey: Data) throws -> Bool {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    let expectedPK = Int(sig.pointee.length_public_key)
    guard publicKey.count == expectedPK else {
        throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
    }

    // An empty Data can still have a base address, but liboqs wants NULL and length 0.
    #if OQS_SAFE_INTEROP
    let rc = message.withUnsafeBytes { msg in
        signature.withUnsafeBytes { sigBuf in
            context.withUnsafeBytes { ctx in
                publicKey.withUnsafeBytes { pk in
                    oqs_sig_verify_with_ctx_str_safe(sig, msg, sigBuf, context.isEmpty ? nil : ctx, pk)
                }
            }
        }
    }
    #else
    let rc = message.withUnsafeBytes { msg in
        signature.withUnsafeBytes { sigBuf in
            context.withUnsafeBytes { ctx in
                publicKey.withUnsafeBytes { pk in
                    OQS_SIG_verify_with_ctx_str(sig,
                        msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count,
                        sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        signature.count,
                        context.isEmpty ? nil : ctx.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        context.count,
                        pk.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
    }
    #endif

    return rc == OQS_SUCCESS
}

func sigExpectedKeyLengths(algorithm: String) throws -> (publicKey: Int, secretKey: Int, signature: Int) {
    ensureInitialized()

    guard let sig = OQS_SIG_new(algorithm) else {
        throw OQSError.algorithmNotAvailable(algorithm)
    }
    defer { OQS_SIG_free(sig) }

    return (
        publicKey: Int(sig.pointee.length_public_key),
        secretKey: Int(sig.pointee.length_secret_key),
        signature: Int(sig.pointee.length_signature)
    )
}
