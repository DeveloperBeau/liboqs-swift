import Foundation
internal import Cliboqs

/// Owns the mutable C state for one stateful-hash signing key (`OQS_SIG_STFL` +
/// `OQS_SIG_STFL_SECRET_KEY`).
///
/// This is the shared engine behind ``XMSS``, ``XMSSMT`` and ``LMS`` private keys.
/// It is a reference type because the secret key is a mutable C object whose
/// one-time-key index advances on every sign; copying the pointer would let two
/// owners race the same index (a key-reuse catastrophe). It is intentionally NOT
/// `Sendable` and must not cross isolation boundaries.
final class StatefulSigningKey {
    private let algorithm: String
    private let sig: UnsafeMutablePointer<OQS_SIG_STFL>
    private let sk: UnsafeMutablePointer<OQS_SIG_STFL_SECRET_KEY>

    /// The DER-free public key bytes, captured at generation or restore time.
    let publicKey: Data

    /// Fresh key generation.
    init(generating algorithm: String) throws {
        ensureInitialized()
        self.algorithm = algorithm
        guard let sig = OQS_SIG_STFL_new(algorithm) else {
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        guard let sk = OQS_SIG_STFL_SECRET_KEY_new(algorithm) else {
            OQS_SIG_STFL_free(sig)
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        self.sig = sig
        self.sk = sk

        let pkLen = Int(sig.pointee.length_public_key)
        var pk = Data(count: pkLen)
        #if OQS_SAFE_INTEROP
        let rc = pk.withUnsafeMutableBytes { p in
            oqs_sig_stfl_keypair_safe(sig, p, sk)
        }
        #else
        let rc = pk.withUnsafeMutableBytes { p in
            OQS_SIG_STFL_keypair(sig, p.baseAddress?.assumingMemoryBound(to: UInt8.self), sk)
        }
        #endif
        guard rc == OQS_SUCCESS else {
            OQS_SIG_STFL_SECRET_KEY_free(sk)
            OQS_SIG_STFL_free(sig)
            throw OQSError.keyGenerationFailed
        }
        self.publicKey = pk
    }

    /// Restore from a self-contained `pk || liboqs_sk` blob produced by
    /// ``serializedSecretKey`` or the store callback.
    init(algorithm: String, serialized: Data) throws {
        ensureInitialized()
        self.algorithm = algorithm
        guard let sig = OQS_SIG_STFL_new(algorithm) else {
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        guard let sk = OQS_SIG_STFL_SECRET_KEY_new(algorithm) else {
            OQS_SIG_STFL_free(sig)
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        self.sig = sig
        self.sk = sk

        let pkLen = Int(sig.pointee.length_public_key)
        guard serialized.count > pkLen else {
            OQS_SIG_STFL_SECRET_KEY_free(sk)
            OQS_SIG_STFL_free(sig)
            throw OQSError.invalidKeySize(expected: pkLen + 1, actual: serialized.count)
        }
        let pk = serialized.prefix(pkLen)
        let skBytes = Data(serialized.suffix(from: serialized.startIndex + pkLen))
        let rc = skBytes.withUnsafeBytes { b in
            OQS_SIG_STFL_SECRET_KEY_deserialize(
                sk,
                b.baseAddress?.assumingMemoryBound(to: UInt8.self),
                b.count,
                nil)
        }
        guard rc == OQS_SUCCESS else {
            OQS_SIG_STFL_SECRET_KEY_free(sk)
            OQS_SIG_STFL_free(sig)
            throw OQSError.invalidKeySize(expected: pkLen, actual: serialized.count)
        }
        self.publicKey = Data(pk)
    }

    deinit {
        OQS_SIG_STFL_free(sig)
        OQS_SIG_STFL_SECRET_KEY_free(sk)
    }

    /// The self-contained `pk || liboqs_sk` blob for the key's current state.
    var serialized: Data {
        get throws {
            var bufPtr: UnsafeMutablePointer<UInt8>? = nil
            var bufLen = 0
            let rc = OQS_SIG_STFL_SECRET_KEY_serialize(&bufPtr, &bufLen, sk)
            guard rc == OQS_SUCCESS, let bufPtr else {
                throw OQSError.keyGenerationFailed
            }
            defer { OQS_MEM_secure_free(bufPtr, bufLen) }
            return publicKey + Data(bytes: bufPtr, count: bufLen)
        }
    }

    /// How many signatures the key can still make, as liboqs counts it.
    ///
    /// Throws ``OQSError/invalidKeySize(expected:actual:)`` when liboqs cannot
    /// read the key, see ``unreadableKey``. After the last LMS signature liboqs
    /// can no longer read the key. After the last XMSS signature the count wraps
    /// to `UInt64.max`.
    var remainingSignatures: UInt64 {
        get throws {
            var remain: UInt64 = 0
            guard OQS_SIG_STFL_sigs_remaining(sig, &remain, sk) == OQS_SUCCESS else {
                throw unreadableKey
            }
            return remain
        }
    }

    /// How many signatures the key can make over its life, as liboqs counts it.
    ///
    /// This is `2^h - 1` for a tree of height `h`. It does not change as the key
    /// is used. It throws the same error as ``remainingSignatures``.
    var totalSignatures: UInt64 {
        get throws {
            var total: UInt64 = 0
            guard OQS_SIG_STFL_sigs_total(sig, &total, sk) == OQS_SUCCESS else {
                throw unreadableKey
            }
            return total
        }
    }

    /// The error for a count liboqs could not read from the key.
    ///
    /// No length failed, so this reports the secret-key length liboqs expects
    /// and zero readable bytes.
    private var unreadableKey: OQSError {
        .invalidKeySize(expected: Int(sig.pointee.length_secret_key), actual: 0)
    }

    /// Decides what a liboqs sign call produced, in the order the ports share.
    ///
    /// A failed persist is ``OQSError/persistenceFailed``. Any other error status
    /// is ``OQSError/signFailed``, even when liboqs wrote a length, because XMSS
    /// writes the length before it stores the state. A success with no length is
    /// ``OQSError/keyExhausted``, because liboqs leaves the length alone when LMS
    /// has no signature left. Otherwise the produced length is returned.
    static func producedLength(status: OQS_STATUS, length: Int, persistFailed: Bool) throws -> Int {
        if persistFailed { throw OQSError.persistenceFailed }
        guard status == OQS_SUCCESS else { throw OQSError.signFailed }
        guard length > 0 else { throw OQSError.keyExhausted }
        return length
    }

    /// Sign `message`, persisting the advanced key state via `store` before the
    /// signature is returned.
    ///
    /// The signature is returned IF AND ONLY IF `store` completed without
    /// throwing. If `store` throws, ``OQSError/persistenceFailed`` is thrown and
    /// the signature is discarded. See ``producedLength(status:length:persistFailed:)``
    /// for the other errors.
    ///
    /// As in liboqs, one key makes ``totalSignatures`` + 1 signatures, and the
    /// last is made when ``remainingSignatures`` already reads 0. An LMS key then
    /// throws ``OQSError/keyExhausted``. An XMSS key throws ``OQSError/signFailed``.
    func signature(for message: Data, persistingTo store: (Data) throws -> Void) throws -> Data {
        // The box does not outlive this call (withExtendedLifetime below), so
        // it's safe to bridge the non-escaping closure across the FFI boundary.
        try withoutActuallyEscaping(store) { escapingStore in
            try _signature(for: message, store: escapingStore)
        }
    }

    private func _signature(for message: Data, store: @escaping (Data) throws -> Void) throws -> Data {
        let box = STFLStoreBox(publicKey: publicKey, store)
        let ctx = Unmanaged.passUnretained(box).toOpaque()
        // Context MUST be non-NULL: LMS silently drops a NULL-context callback.
        OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, stflStoreTrampoline, ctx)

        let maxSigLen = Int(sig.pointee.length_signature)
        var signature = Data(count: maxSigLen)
        var actualLen = 0

        #if OQS_SAFE_INTEROP
        let rc = withExtendedLifetime(box) {
            message.withUnsafeBytes { msg in
                signature.withUnsafeMutableBytes { sigBuf in
                    oqs_sig_stfl_sign_safe(sig, sigBuf, &actualLen, msg, sk)
                }
            }
        }
        #else
        let rc = withExtendedLifetime(box) {
            message.withUnsafeBytes { msg in
                signature.withUnsafeMutableBytes { sigBuf in
                    OQS_SIG_STFL_sign(
                        sig,
                        sigBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        &actualLen,
                        msg.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        message.count,
                        sk)
                }
            }
        }
        #endif

        let length = try Self.producedLength(
            status: rc, length: actualLen, persistFailed: box.caughtError != nil)
        signature.removeSubrange(length...)
        return signature
    }
}

/// Stateless verification + length lookup for stateful-hash schemes.
enum StatefulSignatureVerifier {
    static func expectedPublicKeyLength(algorithm: String) throws -> Int {
        ensureInitialized()
        guard let sig = OQS_SIG_STFL_new(algorithm) else {
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        defer { OQS_SIG_STFL_free(sig) }
        return Int(sig.pointee.length_public_key)
    }

    static func verify(algorithm: String, message: Data, signature: Data, publicKey: Data) throws -> Bool {
        ensureInitialized()
        guard let sig = OQS_SIG_STFL_new(algorithm) else {
            throw OQSError.algorithmNotAvailable(algorithm)
        }
        defer { OQS_SIG_STFL_free(sig) }

        let expectedPK = Int(sig.pointee.length_public_key)
        guard publicKey.count == expectedPK else {
            throw OQSError.invalidKeySize(expected: expectedPK, actual: publicKey.count)
        }

        #if OQS_SAFE_INTEROP
        let rc = message.withUnsafeBytes { msg in
            signature.withUnsafeBytes { sigBuf in
                publicKey.withUnsafeBytes { pk in
                    oqs_sig_stfl_verify_safe(sig, msg, sigBuf, pk)
                }
            }
        }
        #else
        let rc = message.withUnsafeBytes { msg in
            signature.withUnsafeBytes { sigBuf in
                publicKey.withUnsafeBytes { pk in
                    OQS_SIG_STFL_verify(
                        sig,
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
}
