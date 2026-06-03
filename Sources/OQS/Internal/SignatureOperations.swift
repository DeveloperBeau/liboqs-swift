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

    let rc = publicKey.withUnsafeMutableBytes { pk in
        secretKey.withUnsafeMutableBytes { sk in
            oqs_sig_keypair_safe(sig, pk, sk)
        }
    }
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

    let rc = message.withUnsafeBytes { msg in
        secretKey.withUnsafeBytes { sk in
            signature.withUnsafeMutableBytes { sigBuf in
                oqs_sig_sign_safe(sig, sigBuf, &actualSigLen, msg, sk)
            }
        }
    }
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

    let rc = message.withUnsafeBytes { msg in
        signature.withUnsafeBytes { sigBuf in
            publicKey.withUnsafeBytes { pk in
                oqs_sig_verify_safe(sig, msg, sigBuf, pk)
            }
        }
    }

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
