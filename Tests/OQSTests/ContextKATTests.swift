import Testing
import Foundation
@testable import OQS
internal import Cliboqs

// The liboqs NIST-KAT DRBG is process-global, so this suite follows the
// KATTests rules: it is serialized, its name ends in KATTests so the bulk run
// skips it, and every test restores the system RNG.

private let message = Data("the quick brown fox".utf8)
private let shortContext = Data("ctx".utf8)
private let longestContext = Data(repeating: 0x41, count: 255)

/// Raw liboqs output under the KAT seed, with no Swift wrapper in between.
private struct RawSig {
    let name: String
    let publicKey: Data
    let secretKey: Data

    /// Seeds the DRBG, then generates a key pair straight through the C API.
    init(name: String) {
        self.name = name
        KAT.seedDeterministicRNG()
        let sig = OQS_SIG_new(name)!
        defer { OQS_SIG_free(sig) }
        var pk = [UInt8](repeating: 0, count: Int(sig.pointee.length_public_key))
        var sk = [UInt8](repeating: 0, count: Int(sig.pointee.length_secret_key))
        precondition(OQS_SIG_keypair(sig, &pk, &sk) == OQS_SUCCESS)
        publicKey = Data(pk)
        secretKey = Data(sk)
    }

    /// Seeds the DRBG, then signs through `OQS_SIG_sign_with_ctx_str`. A nil context is NULL with length 0.
    func signWithContext(_ ctx: Data?) -> Data {
        KAT.seedDeterministicRNG()
        let sig = OQS_SIG_new(name)!
        defer { OQS_SIG_free(sig) }
        var out = [UInt8](repeating: 0, count: Int(sig.pointee.length_signature))
        var outLen = 0
        let rc: OQS_STATUS = message.withUnsafeBytes { msg in
            let m = msg.bindMemory(to: UInt8.self).baseAddress
            return secretKey.withUnsafeBytes { sk in
                let k = sk.bindMemory(to: UInt8.self).baseAddress
                guard let ctx else {
                    return OQS_SIG_sign_with_ctx_str(sig, &out, &outLen, m, message.count, nil, 0, k)
                }
                return ctx.withUnsafeBytes { c in
                    OQS_SIG_sign_with_ctx_str(sig, &out, &outLen, m, message.count,
                                              c.bindMemory(to: UInt8.self).baseAddress, ctx.count, k)
                }
            }
        }
        precondition(rc == OQS_SUCCESS)
        return Data(out.prefix(outLen))
    }

    /// Seeds the DRBG, then signs through the plain `OQS_SIG_sign`.
    func signPlain() -> Data {
        KAT.seedDeterministicRNG()
        let sig = OQS_SIG_new(name)!
        defer { OQS_SIG_free(sig) }
        var out = [UInt8](repeating: 0, count: Int(sig.pointee.length_signature))
        var outLen = 0
        let rc: OQS_STATUS = message.withUnsafeBytes { msg in
            secretKey.withUnsafeBytes { sk in
                OQS_SIG_sign(sig, &out, &outLen,
                             msg.bindMemory(to: UInt8.self).baseAddress, message.count,
                             sk.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        precondition(rc == OQS_SUCCESS)
        return Data(out.prefix(outLen))
    }
}

/// Context signatures under the KAT seed, checked against raw liboqs and against
/// digests written by hand from the native Rust port (liboqs-rust 96205a0,
/// signWithContext, entropy bytes 0..47, seeded before keygen and before sign).
@Suite(.serialized) struct ContextKATTests {

    @Test("ML-DSA-44 public key and context signatures equal raw liboqs and the Rust port digests")
    func mldsa44ContextSignaturesMatchRawAndRust() throws {
        defer { KAT.restoreSystemRNG() }
        let raw = RawSig(name: "ML-DSA-44")

        KAT.seedDeterministicRNG()
        let key = try MLDSA44.PrivateKey()
        #expect(key.publicKey.rawRepresentation == raw.publicKey)
        #expect(key.publicKey.rawRepresentation.count == 1312)
        #expect(KAT.sha256Hex(key.publicKey.rawRepresentation) == "4ace4b79cf025091e4b4ecf3623703eaaafecdfa404fef78f3a9127affd21a8a")

        let cases: [(label: String, ctx: Data, digest: String)] = [
            ("ctx", shortContext, "376684a48ca2d3afdb53aeaddb8f6be2dcdc2764a6de423bc8caab49b26d3a4a"),
            ("empty", Data(), "00e7bb994dc7cd3098a6ff67e8649f9cd0b6dda9c9c08b7650406c98617374b8"),
            ("255 bytes of 0x41", longestContext, "23d32a2119128d5da622bc5675972c12ace826777349b73e74dbe7d85350e52c"),
        ]
        for c in cases {
            KAT.seedDeterministicRNG()
            let sig = try key.signature(for: message, context: c.ctx)
            #expect(sig.count == 2420, "\(c.label)")
            #expect(sig == raw.signWithContext(c.ctx.isEmpty ? nil : c.ctx), "\(c.label) differs from raw liboqs")
            #expect(KAT.sha256Hex(sig) == c.digest, "\(c.label) digest")
            #expect(try key.publicKey.isValidSignature(sig, for: message, context: c.ctx))
        }
    }

    @Test("SLH-DSA pure SHA2-128f public key and context signatures equal raw liboqs and the Rust port digests")
    func slhdsaSHA2128fContextSignaturesMatchRawAndRust() throws {
        defer { KAT.restoreSystemRNG() }
        let raw = RawSig(name: "SLH_DSA_PURE_SHA2_128F")

        KAT.seedDeterministicRNG()
        let key = try SLHDSAPureSHA2128f.PrivateKey()
        #expect(key.publicKey.rawRepresentation == raw.publicKey)
        #expect(key.publicKey.rawRepresentation.count == 32)
        #expect(KAT.sha256Hex(key.publicKey.rawRepresentation) == "34509f7a48fbcdfd4b0440f0627cb32f6c29b586952ade8ff8cd45a55ff164c8")

        let cases: [(label: String, ctx: Data, digest: String)] = [
            ("ctx", shortContext, "fc93de401cd05f38f8f447d91497e4a785a3e25ab3b38895b1c6fdeea3e5cd5f"),
            ("empty", Data(), "ca7bd552bf5f452cadfd1d89e933b0c0032f528373c3ad8f7e431b5375dd0f20"),
            ("255 bytes of 0x41", longestContext, "2bc5f09d1ec8ec1d45e3562d564a0a0c186190a97220e467fc3857796d64a85e"),
        ]
        for c in cases {
            KAT.seedDeterministicRNG()
            let sig = try key.signature(for: message, context: c.ctx)
            #expect(sig.count == 17088, "\(c.label)")
            #expect(sig == raw.signWithContext(c.ctx.isEmpty ? nil : c.ctx), "\(c.label) differs from raw liboqs")
            #expect(KAT.sha256Hex(sig) == c.digest, "\(c.label) digest")
            #expect(try key.publicKey.isValidSignature(sig, for: message, context: c.ctx))
        }
    }

    @Test("ML-DSA-44 empty context signature equals the plain signature under the same seed")
    func mldsa44EmptyContextEqualsPlainSignature() throws {
        defer { KAT.restoreSystemRNG() }
        KAT.seedDeterministicRNG()
        let key = try MLDSA44.PrivateKey()
        KAT.seedDeterministicRNG()
        let plain = try key.signature(for: message)
        KAT.seedDeterministicRNG()
        let empty = try key.signature(for: message, context: Data())
        #expect(plain == empty)
        #expect(plain.count == 2420)
    }

    @Test("Falcon-512 empty context signature equals raw plain sign and raw context sign with NULL")
    func falcon512EmptyContextEqualsRawSign() throws {
        defer { KAT.restoreSystemRNG() }
        let raw = RawSig(name: "Falcon-512")
        KAT.seedDeterministicRNG()
        let key = try Falcon512.PrivateKey()
        #expect(key.publicKey.rawRepresentation == raw.publicKey)

        KAT.seedDeterministicRNG()
        let sig = try key.signature(for: message, context: Data())
        let rawPlain = raw.signPlain()
        let rawNull = raw.signWithContext(nil)
        #expect(sig == rawPlain)
        #expect(sig == rawNull)
        #expect(!sig.isEmpty)
    }
}
