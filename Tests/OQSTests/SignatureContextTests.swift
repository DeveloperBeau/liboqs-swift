import Testing
import Foundation
@testable import OQS
internal import Cliboqs

private let message = Data("the quick brown fox".utf8)
private let context = Data("ctx".utf8)

/// Context string signing and verifying through the public key types.
@Suite struct SignatureContextTests {

    // MARK: - Which algorithms take a context (written out by hand)

    private static let takesContext = [
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHAKE_128F",
        "SLH_DSA_SHA2_256_PREHASH_SHA2_128F", "SLH_DSA_SHAKE_128_PREHASH_SHAKE_256S",
    ]
    private static let takesNoContext = [
        "Falcon-512", "Falcon-padded-512", "MAYO-1", "cross-rsdp-128-fast",
        "OV-Ip", "SNOVA_24_5_4", "mqom2_cat1_gf16_fast_r3",
    ]

    @Test("Hand-written families take a context and the others do not")
    func supportListMatchesHandWrittenFamilies() throws {
        for name in Self.takesContext {
            #expect(try sigSupportsContext(algorithm: name), "\(name) should take a context")
        }
        for name in Self.takesNoContext {
            #expect(try !sigSupportsContext(algorithm: name), "\(name) should not take a context")
        }
    }

    @Test("159 of 221 enabled signature schemes take a context, 3 ML-DSA and 156 SLH-DSA")
    func contextSupportCountMatchesHandWrittenTotals() throws {
        var enabled = 0
        var withContext = 0
        var mldsa = 0
        var slhdsa = 0
        for i in 0..<OQS_SIG_alg_count() {
            guard let id = OQS_SIG_alg_identifier(Int(i)) else { continue }
            let name = String(cString: id)
            guard OQS_SIG_alg_is_enabled(name) == 1 else { continue }
            enabled += 1
            if try sigSupportsContext(algorithm: name) {
                withContext += 1
                if name.hasPrefix("ML-DSA-") { mldsa += 1 }
                if name.hasPrefix("SLH_DSA_") { slhdsa += 1 }
            }
        }
        #expect(enabled == 221)
        #expect(withContext == 159)
        #expect(mldsa == 3)
        #expect(slhdsa == 156)
    }

    @Test("An unknown algorithm name has no context query answer")
    func supportQueryOnUnknownAlgorithmThrows() {
        #expect(throws: OQSError.algorithmNotAvailable("no-such-sig")) {
            _ = try sigSupportsContext(algorithm: "no-such-sig")
        }
    }

    // MARK: - Round trips through the public types

    @Test("ML-DSA-44 signs and verifies with a context")
    func mldsa44ContextRoundTrip() throws {
        let key = try MLDSA44.PrivateKey()
        let sig = try key.signature(for: message, context: context)
        #expect(try key.publicKey.isValidSignature(sig, for: message, context: context))
    }

    @Test("ML-DSA-65 and ML-DSA-87 sign and verify with a context")
    func mldsa65And87ContextRoundTrip() throws {
        let key65 = try MLDSA65.PrivateKey()
        let sig65 = try key65.signature(for: message, context: context)
        #expect(try key65.publicKey.isValidSignature(sig65, for: message, context: context))
        let key87 = try MLDSA87.PrivateKey()
        let sig87 = try key87.signature(for: message, context: context)
        #expect(try key87.publicKey.isValidSignature(sig87, for: message, context: context))
    }

    @Test("SLH-DSA pure SHA2-128f and SHAKE-128f sign and verify with a context")
    func slhdsaPureContextRoundTrip() throws {
        let sha2 = try SLHDSAPureSHA2128f.PrivateKey()
        let sha2Sig = try sha2.signature(for: message, context: context)
        #expect(try sha2.publicKey.isValidSignature(sha2Sig, for: message, context: context))
        #expect(try !sha2.publicKey.isValidSignature(sha2Sig, for: message, context: Data("other".utf8)))

        let shake = try SLHDSAPureSHAKE128f.PrivateKey()
        let shakeSig = try shake.signature(for: message, context: context)
        #expect(try shake.publicKey.isValidSignature(shakeSig, for: message, context: context))
        #expect(try !shake.publicKey.isValidSignature(shakeSig, for: message))
    }

    @Test("SLH-DSA prehash types sign and verify with a context")
    func slhdsaPrehashContextRoundTrip() throws {
        let a = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .sha2_128f)
        let aSig = try a.signature(for: message, context: context)
        #expect(try a.publicKey.isValidSignature(aSig, for: message, context: context))
        #expect(try !a.publicKey.isValidSignature(aSig, for: message, context: Data()))
        #expect(try !a.publicKey.isValidSignature(aSig, for: message))

        let b = try SLHDSA.Prehash.PrivateKey(prehash: .shake_128, paramSet: .shake_128f)
        let bSig = try b.signature(for: message, context: context)
        #expect(try b.publicKey.isValidSignature(bSig, for: message, context: context))
        #expect(try !b.publicKey.isValidSignature(bSig, for: message, context: Data("other".utf8)))
    }

    // MARK: - Rejections

    @Test("ML-DSA-44 rejects a wrong context, a plain verify and an empty-context verify of a context signature")
    func mldsa44ContextSignatureRejectedUnderOtherContexts() throws {
        let key = try MLDSA44.PrivateKey()
        let sig = try key.signature(for: message, context: context)
        #expect(try !key.publicKey.isValidSignature(sig, for: message, context: Data("cty".utf8)))
        #expect(try !key.publicKey.isValidSignature(sig, for: message, context: Data()))
        #expect(try !key.publicKey.isValidSignature(sig, for: message))
    }

    @Test("ML-DSA-44 rejects a context verify of a plain signature")
    func mldsa44PlainSignatureRejectedUnderContext() throws {
        let key = try MLDSA44.PrivateKey()
        let sig = try key.signature(for: message)
        #expect(try !key.publicKey.isValidSignature(sig, for: message, context: context))
    }

    @Test("ML-DSA-44 empty context round trips with the plain methods both ways")
    func mldsa44EmptyContextEqualsPlain() throws {
        let key = try MLDSA44.PrivateKey()
        let plain = try key.signature(for: message)
        let empty = try key.signature(for: message, context: Data())
        #expect(try key.publicKey.isValidSignature(plain, for: message, context: Data()))
        #expect(try key.publicKey.isValidSignature(empty, for: message))
        #expect(try key.publicKey.isValidSignature(empty, for: message, context: Data()))
    }

    @Test("Falcon-512 signs with an empty context and refuses a non-empty one")
    func falcon512ContextRules() throws {
        let key = try Falcon512.PrivateKey()
        let sig = try key.signature(for: message, context: Data())
        #expect(try key.publicKey.isValidSignature(sig, for: message))
        #expect(try key.publicKey.isValidSignature(sig, for: message, context: Data()))
        #expect(throws: OQSError.contextNotSupported) {
            _ = try key.signature(for: message, context: context)
        }
        #expect(try !key.publicKey.isValidSignature(sig, for: message, context: context))
    }

    @Test("Other families without context support throw contextNotSupported on sign and verify false")
    func nonContextFamiliesRefuseContext() throws {
        let mayo = try MAYO1.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try mayo.signature(for: message, context: context) }
        #expect(try !mayo.publicKey.isValidSignature(Data(count: 8), for: message, context: context))

        let cross = try CrossRSDP128Fast.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try cross.signature(for: message, context: context) }

        let uov = try OVIp.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try uov.signature(for: message, context: context) }

        let snova = try SNOVA24_5_4.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try snova.signature(for: message, context: context) }

        let mqom = try MQOM2Cat1GF16FastR3.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try mqom.signature(for: message, context: context) }

        let padded = try FalconPadded512.PrivateKey()
        #expect(throws: OQSError.contextNotSupported) { _ = try padded.signature(for: message, context: context) }
    }

    @Test("ML-DSA-44 accepts a 255 byte context and refuses 256 on sign, verifying false")
    func mldsa44ContextLengthLimit() throws {
        let key = try MLDSA44.PrivateKey()
        let ok = Data(repeating: 0x41, count: 255)
        let long = Data(repeating: 0x41, count: 256)
        let sig = try key.signature(for: message, context: ok)
        #expect(try key.publicKey.isValidSignature(sig, for: message, context: ok))
        #expect(throws: OQSError.contextTooLong) { _ = try key.signature(for: message, context: long) }
        #expect(try !key.publicKey.isValidSignature(sig, for: message, context: long))
    }

    @Test("SLH-DSA pure and prehash refuse a 256 byte context")
    func slhdsaContextTooLong() throws {
        let long = Data(repeating: 0x41, count: 256)
        let pure = try SLHDSAPureSHA2128f.PrivateKey()
        #expect(throws: OQSError.contextTooLong) { _ = try pure.signature(for: message, context: long) }
        let pre = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .sha2_128f)
        #expect(throws: OQSError.contextTooLong) { _ = try pre.signature(for: message, context: long) }
        #expect(try !pre.publicKey.isValidSignature(Data(count: 8), for: message, context: long))
    }

    @Test("Verifying with a public key of the wrong length throws invalidKeySize")
    func verifyWithWrongPublicKeyLengthThrows() throws {
        #expect(throws: OQSError.invalidKeySize(expected: 1312, actual: 1311)) {
            _ = try sigVerify(algorithm: "ML-DSA-44", message: message, signature: Data(count: 4), context: context, publicKey: Data(count: 1311))
        }
        #expect(throws: OQSError.invalidKeySize(expected: 897, actual: 896)) {
            _ = try sigVerify(algorithm: "Falcon-512", message: message, signature: Data(count: 4), context: Data(), publicKey: Data(count: 896))
        }
        #expect(throws: OQSError.invalidKeySize(expected: 1312, actual: 5)) {
            _ = try MLDSA44.PublicKey(rawRepresentation: Data(count: 5))
        }
    }

    @Test("Signing with a secret key of the wrong length throws invalidKeySize with both sizes")
    func signWithWrongSecretKeyLengthThrows() {
        #expect(throws: OQSError.invalidKeySize(expected: 2560, actual: 2559)) {
            _ = try sigSign(algorithm: "ML-DSA-44", message: message, context: context, secretKey: Data(count: 2559))
        }
        #expect(throws: OQSError.invalidKeySize(expected: 1281, actual: 1280)) {
            _ = try sigSign(algorithm: "Falcon-512", message: message, context: Data(), secretKey: Data(count: 1280))
        }
    }

    @Test("Sign checks run in the order support, key length, context length")
    func signCheckOrder() {
        let shortKey = Data(count: 10)
        // No support and a short key: support is reported first.
        #expect(throws: OQSError.contextNotSupported) {
            _ = try sigSign(algorithm: "Falcon-512", message: message, context: context, secretKey: shortKey)
        }
        // Context too long and a short key: the key length is reported first.
        #expect(throws: OQSError.invalidKeySize(expected: 2560, actual: 10)) {
            _ = try sigSign(algorithm: "ML-DSA-44", message: message, context: Data(count: 256), secretKey: shortKey)
        }
        // Valid key and context too long: the length is reported.
        #expect(throws: OQSError.contextTooLong) {
            _ = try sigSign(algorithm: "ML-DSA-44", message: message, context: Data(count: 256), secretKey: Data(count: 2560))
        }
    }

    @Test("An unknown algorithm throws algorithmNotAvailable on context sign and verify")
    func unknownAlgorithmThrowsOnContextCalls() {
        #expect(throws: OQSError.algorithmNotAvailable("nope")) {
            _ = try sigSign(algorithm: "nope", message: message, context: context, secretKey: Data())
        }
        #expect(throws: OQSError.algorithmNotAvailable("nope")) {
            _ = try sigVerify(algorithm: "nope", message: message, signature: Data(), context: context, publicKey: Data())
        }
    }

    @Test("An empty context that has a base address still reaches liboqs as NULL")
    func emptyContextWithBaseAddressIsSentAsNull() throws {
        // liboqs rejects any non-NULL context pointer for Falcon-512.
        let backing = Data([1, 2, 3, 4])
        let emptySlice = backing[2..<2]
        #expect(emptySlice.isEmpty)
        let key = try Falcon512.PrivateKey()
        let sig = try key.signature(for: message, context: emptySlice)
        #expect(try key.publicKey.isValidSignature(sig, for: message, context: emptySlice))
        #expect(try key.publicKey.isValidSignature(sig, for: message))

        var reserved = Data(capacity: 64)
        reserved.append(contentsOf: [9, 9])
        reserved.removeAll(keepingCapacity: true)
        let sig2 = try key.signature(for: message, context: reserved)
        #expect(try key.publicKey.isValidSignature(sig2, for: message, context: reserved))
    }

    // MARK: - Fuzz

    @Test("Fuzz: ML-DSA-44 context sign and verify accept valid input and reject mutated input")
    func fuzzMLDSA44Context() throws {
        let seed = FuzzSeed.value
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SplitMix64(seed: seed)
        let key = try MLDSA44.PrivateKey()
        let pub = key.publicKey

        for round in 0..<24 {
            // 0 and 255 are always covered, the rest are drawn.
            let length: Int
            switch round {
            case 0: length = 0
            case 1: length = 255
            default: length = Int(rng.next() % 256)
            }
            let ctx = rng.bytes(length)
            let msg = rng.bytes(Int(rng.next() % 64))
            let sig = try key.signature(for: msg, context: ctx)

            // No false negative: the same message and context always verify.
            #expect(try pub.isValidSignature(sig, for: msg, context: ctx), "round \(round) length \(length)")

            // No false positive: nothing changed is accepted.
            if length > 0 {
                var flipped = ctx
                flipped[Int(rng.next() % UInt64(length))] ^= 1 << UInt8(rng.next() % 8)
                #expect(try !pub.isValidSignature(sig, for: msg, context: flipped))
                #expect(try !pub.isValidSignature(sig, for: msg, context: ctx.dropLast()))
            }
            if length < 255 {
                #expect(try !pub.isValidSignature(sig, for: msg, context: ctx + [UInt8(rng.next() & 0xff)]))
            }
            var otherMessage = msg
            if otherMessage.isEmpty { otherMessage.append(0) } else { otherMessage[0] ^= 1 }
            #expect(try !pub.isValidSignature(sig, for: otherMessage, context: ctx))
            var badSig = sig
            badSig[Int(rng.next() % UInt64(sig.count))] ^= 1 << UInt8(rng.next() % 8)
            #expect(try !pub.isValidSignature(badSig, for: msg, context: ctx))

            // Too long: 256 always in the first round, then 256 to 1024.
            let tooLong = round == 0 ? 256 : 256 + Int(rng.next() % 769)
            let longCtx = rng.bytes(tooLong)
            #expect(throws: OQSError.contextTooLong) { _ = try key.signature(for: msg, context: longCtx) }
            #expect(try !pub.isValidSignature(sig, for: msg, context: longCtx))
        }
    }

    @Test("Fuzz: a non-empty context on Falcon-512 always throws contextNotSupported")
    func fuzzFalcon512NonEmptyContextRefused() throws {
        let seed = FuzzSeed.value
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SplitMix64(seed: seed ^ 0xF512)
        let key = try Falcon512.PrivateKey()
        for _ in 0..<16 {
            let ctx = rng.bytes(1 + Int(rng.next() % 300))
            #expect(throws: OQSError.contextNotSupported) { _ = try key.signature(for: message, context: ctx) }
            #expect(try !key.publicKey.isValidSignature(Data(count: 10), for: message, context: ctx))
        }
    }
}

/// The fuzz seed, taken from `OQS_FUZZ_SEED` (hex) or a fixed default.
enum FuzzSeed {
    static let value: UInt64 = {
        if let text = ProcessInfo.processInfo.environment["OQS_FUZZ_SEED"] {
            let digits = text.hasPrefix("0x") || text.hasPrefix("0X") ? String(text.dropFirst(2)) : text
            if let parsed = UInt64(digits, radix: 16) { return parsed }
        }
        return 0x5717_F022
    }()
}

extension SplitMix64 {
    /// `count` generated bytes.
    mutating func bytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8(truncatingIfNeeded: next()) })
    }
}
