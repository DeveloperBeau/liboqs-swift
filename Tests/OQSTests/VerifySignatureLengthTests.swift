import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// Verify must never hand liboqs a signature buffer of the wrong size. For
/// some schemes liboqs reads the signature before it checks the length, so an
/// empty or short signature must come back as a plain `false`.
///
/// Every hostile signature is its own exact-size allocation, built from a new
/// array. It is never a slice or a view of a bigger buffer, so a read past its
/// end is a real read past an allocation.

/// A new `Data` with its own storage that holds exactly `bytes`.
private func fresh(_ bytes: some Collection<UInt8>) -> Data {
    Data(Array(bytes))
}

private let longExtra = 4096

/// True when `bad` is the valid signature with only trailing zero bytes cut off.
/// Some schemes, such as padded Falcon, end the signature in zero padding, so
/// this is the same signature and not a forgery.
private func isValidWithoutTrailingZeros(_ bad: [UInt8], valid: [UInt8]) -> Bool {
    bad.count <= valid.count && bad + [UInt8](repeating: 0, count: valid.count - bad.count) == valid
}

/// The names of the stateless signature types, from the registry of public types.
private let statelessNames: [String] = ParityRegistry.sigs().filter { $0.signed != nil }.map(\.name)

/// A valid signature of a stateful scheme, from the smallest variant of its family.
private func statefulSample(_ family: String) throws -> (name: String, max: Int, sample: SignedSample) {
    let message = ParityRegistry.message
    switch family {
    case "XMSS":
        let variant = XMSS.Variant.sha2_10_256
        let key = try XMSS.PrivateKey(variant)
        let pub = key.publicKey
        let sig = try key.signature(for: message) { _ in }
        return (variant.rawValue, try statefulSignatureLength(variant.rawValue),
                SignedSample(message: message, publicKey: pub.rawRepresentation, signature: sig,
                             verify: { try pub.isValidSignature($0, for: message) }))
    case "XMSSMT":
        let variant = XMSSMT.Variant.sha2_h20_2
        let key = try XMSSMT.PrivateKey(variant)
        let pub = key.publicKey
        let sig = try key.signature(for: message) { _ in }
        return (variant.rawValue, try statefulSignatureLength(variant.rawValue),
                SignedSample(message: message, publicKey: pub.rawRepresentation, signature: sig,
                             verify: { try pub.isValidSignature($0, for: message) }))
    default:
        let variant = LMS.Variant.sha256_h5_w1
        let key = try LMS.PrivateKey(variant)
        let pub = key.publicKey
        let sig = try key.signature(for: message) { _ in }
        return (variant.rawValue, try statefulSignatureLength(variant.rawValue),
                SignedSample(message: message, publicKey: pub.rawRepresentation, signature: sig,
                             verify: { try pub.isValidSignature($0, for: message) }))
    }
}

/// The signature length that liboqs reports for a stateful scheme.
private func statefulSignatureLength(_ name: String) throws -> Int {
    guard let sig = OQS_SIG_STFL_new(name) else { throw OQSError.algorithmNotAvailable(name) }
    defer { OQS_SIG_STFL_free(sig) }
    return Int(sig.pointee.length_signature)
}

/// Runs every hostile and every valid case for one signature. Returns one
/// line for each case that went wrong, and an empty list when all pass.
private func lengthProblems(_ name: String, _ sample: SignedSample) -> [String] {
    var problems: [String] = []
    let valid = Array(sample.signature)
    let n = valid.count

    func expect(_ label: String, _ signature: Data, accepted: Bool) {
        do {
            let got = try sample.verify(signature)
            if !accepted, got, isValidWithoutTrailingZeros(Array(signature), valid: valid) { return }
            if got != accepted { problems.append("\(name): \(label) gave \(got), expected \(accepted)") }
        } catch {
            problems.append("\(name): \(label) threw \(error)")
        }
    }

    expect("exact-length valid signature", fresh(valid), accepted: true)

    // Too short, including empty.
    expect("empty signature", fresh([UInt8]()), accepted: false)
    expect("1-byte signature", fresh([0xA5]), accepted: false)
    expect("valid signature minus 1 byte", fresh(valid.dropLast(1)), accepted: false)
    expect("valid signature minus 2 bytes", fresh(valid.dropLast(2)), accepted: false)

    // Too long, up to far past the longest signature.
    expect("valid signature plus 1 byte", fresh(valid + [0]), accepted: false)
    expect("valid signature plus 2 bytes", fresh(valid + [0, 0]), accepted: false)
    expect("valid signature plus \(longExtra) bytes", fresh(valid + [UInt8](repeating: 0x5A, count: longExtra)), accepted: false)

    // One flipped byte at the start, middle and end.
    for (label, index) in [("first", 0), ("middle", n / 2), ("last", n - 1)] {
        var flipped = valid
        flipped[index] ^= 0xFF
        expect("valid signature with \(label) byte flipped", fresh(flipped), accepted: false)
    }
    return problems
}

@Suite struct VerifySignatureLengthTests {

    // MARK: - Every stateless signature type

    @Test("every stateless signature type is in the registry of public types", .timeLimit(.minutes(10)))
    func registryIsNotEmpty() {
        #expect(statelessNames.count >= 100, "only \(statelessNames.count) stateless signature types")
    }

    @Test(
        "stateless verify returns false for empty, short and long signatures and keeps valid ones",
        .timeLimit(.minutes(10)),
        arguments: statelessNames)
    func statelessVerifyHandlesEveryLength(name: String) throws {
        let alg = try #require(ParityRegistry.sigs().first { $0.name == name })
        let make = try #require(alg.signed)
        // Some schemes need more stack than a test worker has.
        let problems = try onLargeStack {
            lengthProblems(name, try make())
        }
        #expect(problems.isEmpty, "\(problems)")
    }

    // MARK: - Stateful families, smallest variant of each

    @Test(
        "stateful verify returns false for empty, short and long signatures and keeps valid ones",
        .timeLimit(.minutes(10)),
        arguments: ["XMSS", "XMSSMT", "LMS"])
    func statefulVerifyHandlesEveryLength(family: String) throws {
        let (name, max, sample) = try statefulSample(family)
        #expect(sample.signature.count == max, "\(name) signature size is not the size liboqs reports")
        let problems = lengthProblems(name, sample)
        #expect(problems.isEmpty, "\(problems)")
    }

    // MARK: - Core set: a few schemes, fast to run, for mutation and sanitizer runs

    /// Schemes that read the signature before they check its length, and fast ones.
    private static let coreStateless = ["ML-DSA-44", "Falcon-512", "SLH_DSA_PURE_SHA2_128F", "cross-rsdp-128-fast"]

    @Test("core stateless schemes handle empty, short, long and valid signatures", .timeLimit(.minutes(10)))
    func coreStatelessSchemesHandleEveryLength() throws {
        var problems: [String] = []
        for name in Self.coreStateless {
            let make = try Self.signedMaker(name)
            problems += lengthProblems(name, try make())
        }
        #expect(problems.isEmpty, "\(problems)")
    }

    @Test("core stateful schemes handle empty, short, long and valid signatures", .timeLimit(.minutes(10)))
    func coreStatefulSchemesHandleEveryLength() throws {
        var problems: [String] = []
        for family in ["XMSS", "LMS"] {
            let (name, _, sample) = try statefulSample(family)
            problems += lengthProblems(name, sample)
        }
        #expect(problems.isEmpty, "\(problems)")
    }

    // MARK: - Public key check comes first

    @Test("stateless verify throws invalidKeySize for a wrong-size public key even with an empty signature")
    func statelessPublicKeyCheckRunsFirst() throws {
        for alg in ParityRegistry.sigs() where alg.signed != nil {
            let pk = try alg.typedLengths().publicKey
            for wrong in [0, pk - 1, pk + 1] {
                do {
                    _ = try sigVerify(algorithm: alg.name, message: ParityRegistry.message,
                                      signature: Data(), publicKey: fresh([UInt8](repeating: 1, count: wrong)))
                    Issue.record("\(alg.name): no error for a public key of \(wrong) bytes")
                } catch OQSError.invalidKeySize(let expected, let actual) {
                    #expect(expected == pk && actual == wrong, "\(alg.name): expected \(pk) actual \(wrong), got \(expected) and \(actual)")
                } catch {
                    Issue.record("\(alg.name): wrong error \(error)")
                }
            }
        }
    }

    @Test("stateful verify throws invalidKeySize for a wrong-size public key even with an empty signature")
    func statefulPublicKeyCheckRunsFirst() throws {
        func check(_ name: String, _ verify: (Data) throws -> Bool) throws {
            let pk = try StatefulSignatureVerifier.expectedPublicKeyLength(algorithm: name)
            do {
                _ = try verify(fresh([UInt8](repeating: 1, count: pk + 1)))
                Issue.record("\(name): no error for a wrong-size public key")
            } catch OQSError.invalidKeySize(let expected, let actual) {
                #expect(expected == pk && actual == pk + 1, "\(name): got \(expected) and \(actual)")
            }
        }
        let message = ParityRegistry.message
        for v in XMSS.Variant.allCases {
            try check(v.rawValue) { try XMSS.PublicKey(v, rawRepresentation: $0).isValidSignature(Data(), for: message) }
        }
        for v in XMSSMT.Variant.allCases {
            try check(v.rawValue) { try XMSSMT.PublicKey(v, rawRepresentation: $0).isValidSignature(Data(), for: message) }
        }
        for v in LMS.Variant.allCases {
            try check(v.rawValue) { try LMS.PublicKey(v, rawRepresentation: $0).isValidSignature(Data(), for: message) }
        }
    }

    // MARK: - Seeded fuzz, both directions

    /// Fast schemes: one lattice scheme, two Falcon forms and the smallest LMS set.
    private static let fuzzStateless = ["ML-DSA-44", "Falcon-512", "Falcon-padded-512"]
    private static let fuzzIterations = 150

    private static func fuzz(_ name: String, _ sample: SignedSample, seed: UInt64) -> [String] {
        var rng = SeededGenerator(seed: seed)
        var problems: [String] = []
        let valid = Array(sample.signature)
        for i in 0..<fuzzIterations {
            var bad = valid
            let kind: String
            switch Int.random(in: 0..<3, using: &rng) {
            case 0:
                kind = "truncate"
                bad = Array(valid.prefix(Int.random(in: 0..<valid.count, using: &rng)))
            case 1:
                kind = "extend"
                let extra = Int.random(in: 1...(i % 10 == 0 ? 5000 : 64), using: &rng)
                bad += (0..<extra).map { _ in UInt8.random(in: 0...255, using: &rng) }
            default:
                kind = "flip"
                bad[Int.random(in: 0..<bad.count, using: &rng)] ^= UInt8.random(in: 1...255, using: &rng)
            }
            // False positive check: a mutated signature is never accepted.
            if (try? sample.verify(fresh(bad))) == true, !isValidWithoutTrailingZeros(bad, valid: valid) {
                problems.append("\(name) iteration \(i): \(kind) signature accepted, seed \(seed)")
            }
            // False negative check: the untouched signature is always accepted.
            if (try? sample.verify(fresh(valid))) != true {
                problems.append("\(name) iteration \(i): valid signature rejected, seed \(seed)")
            }
        }
        return problems
    }

    private static func signedMaker(_ name: String) throws -> @Sendable () throws -> SignedSample {
        for alg in ParityRegistry.sigs() where alg.name == name {
            if let make = alg.signed { return make }
        }
        throw FuzzSetupError(name: name)
    }

    private struct FuzzSetupError: Error { let name: String }

    @Test("fuzzed truncations, extensions and flips are never accepted and valid signatures always are", .timeLimit(.minutes(10)))
    func fuzzBothDirections() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("VerifySignatureLengthTests fuzz seed: 0x\(String(seed, radix: 16))")
        var problems: [String] = []
        for name in Self.fuzzStateless {
            let make = try Self.signedMaker(name)
            let sample = try make()
            problems += Self.fuzz(name, sample, seed: seed)
        }
        let (name, _, sample) = try statefulSample("LMS")
        problems += Self.fuzz(name, sample, seed: seed)
        #expect(problems.isEmpty, "\(problems.prefix(10))")
    }
}

/// The decision about a signature length, checked without calling liboqs.
@Suite struct VerifySignatureInputTests {
    private let max = 8

    @Test("an empty signature gets a zeroed buffer of full length, a real count of 0 and a non-nil base")
    func emptySignature() {
        #expect(VerifySignatureInput.plan(for: Data(), maxLength: max)
                == .padded(buffer: [UInt8](repeating: 0, count: 8), count: 0))
        var sawBase = false
        let result = withVerifiableSignature(Data(), maxLength: max) { buf in
            sawBase = buf.baseAddress != nil && buf.count == 0
            return true
        }
        #expect(result && sawBase)
    }

    @Test("a short signature is copied in front of zeros and passed with its real count")
    func shortSignature() {
        let sig = fresh([1, 2, 3])
        #expect(VerifySignatureInput.plan(for: sig, maxLength: max)
                == .padded(buffer: [1, 2, 3, 0, 0, 0, 0, 0], count: 3))
        var seen: (count: Int, hasBase: Bool, tail: [UInt8])?
        _ = withVerifiableSignature(sig, maxLength: max) { buf in
            // The bytes after the count are owned by the padded buffer and are zero.
            let all = UnsafeRawBufferPointer(start: buf.baseAddress, count: 8)
            seen = (buf.count, buf.baseAddress != nil, Array(all[3...]))
            return true
        }
        #expect(seen?.count == 3 && seen?.hasBase == true && seen?.tail == [0, 0, 0, 0, 0])
    }

    @Test("a signature of full length goes through as the caller's own bytes")
    func fullLengthSignature() {
        let sig = fresh(Array(1...8))
        #expect(VerifySignatureInput.plan(for: sig, maxLength: max) == .passThrough)
        var seen: [UInt8] = []
        _ = withVerifiableSignature(sig, maxLength: max) { seen = Array($0); return true }
        #expect(seen == Array(1...8))
    }

    @Test("a signature longer than the maximum is rejected and liboqs is not called")
    func longSignature() {
        let sig = fresh(Array(1...9))
        #expect(VerifySignatureInput.plan(for: sig, maxLength: max) == .reject)
        var called = false
        let result = withVerifiableSignature(sig, maxLength: max) { _ in called = true; return true }
        #expect(!result && !called)
    }
}
