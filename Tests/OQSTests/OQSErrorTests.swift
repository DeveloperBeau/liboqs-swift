import Testing
import Foundation
@testable import OQS

@Suite struct OQSErrorTests {

    // MARK: - Case list

    /// One sample of every case. The switch has no default, so adding a case breaks the build here.
    static var oneOfEachCase: [OQSError] {
        let samples: [OQSError] = [
            .algorithmNotAvailable("Sample-1"),
            .keyGenerationFailed,
            .encapsulationFailed,
            .decapsulationFailed,
            .signFailed,
            .verifyFailed,
            .invalidKeySize(expected: 32, actual: 16),
            .contextNotSupported,
            .contextTooLong,
            .seedNotSupported,
            .keyExhausted,
            .persistenceFailed,
        ]
        for sample in samples {
            switch sample {
            case .algorithmNotAvailable, .keyGenerationFailed, .encapsulationFailed,
                 .decapsulationFailed, .signFailed, .verifyFailed, .invalidKeySize,
                 .contextNotSupported, .contextTooLong, .seedNotSupported,
                 .keyExhausted, .persistenceFailed:
                break
            }
        }
        return samples
    }

    @Test("The sample list holds twelve distinct cases")
    func sampleListIsComplete() {
        #expect(Self.oneOfEachCase.count == 12)
        #expect(Set(Self.oneOfEachCase).count == 12)
    }

    // MARK: - Descriptions

    @Test("algorithmNotAvailable describes the algorithm name")
    func algorithmNotAvailableText() {
        #expect(OQSError.algorithmNotAvailable("FakeAlgo-999").description == "Algorithm not available: FakeAlgo-999")
    }

    @Test("keyGenerationFailed has its exact description")
    func keyGenerationFailedText() {
        #expect(OQSError.keyGenerationFailed.description == "Key generation failed")
    }

    @Test("encapsulationFailed has its exact description")
    func encapsulationFailedText() {
        #expect(OQSError.encapsulationFailed.description == "KEM encapsulation failed")
    }

    @Test("decapsulationFailed has its exact description")
    func decapsulationFailedText() {
        #expect(OQSError.decapsulationFailed.description == "KEM decapsulation failed")
    }

    @Test("signFailed has its exact description")
    func signFailedText() {
        #expect(OQSError.signFailed.description == "Signature generation failed")
    }

    @Test("verifyFailed has its exact description")
    func verifyFailedText() {
        #expect(OQSError.verifyFailed.description == "Signature verification failed")
    }

    @Test("invalidKeySize has its exact description")
    func invalidKeySizeText() {
        #expect(OQSError.invalidKeySize(expected: 800, actual: 799).description == "Invalid key size: expected 800 bytes, got 799")
    }

    @Test("contextNotSupported has its exact description")
    func contextNotSupportedText() {
        #expect(OQSError.contextNotSupported.description == "The algorithm does not take a context string")
    }

    @Test("contextTooLong has its exact description")
    func contextTooLongText() {
        #expect(OQSError.contextTooLong.description == "The context string is too long")
    }

    @Test("seedNotSupported has its exact description")
    func seedNotSupportedText() {
        #expect(OQSError.seedNotSupported.description == "The algorithm has no form of the operation that takes a seed")
    }

    @Test("keyExhausted has its exact description")
    func keyExhaustedText() {
        #expect(OQSError.keyExhausted.description == "The secret key has no signature left")
    }

    @Test("persistenceFailed has its exact description")
    func persistenceFailedText() {
        #expect(OQSError.persistenceFailed.description == "The advanced secret key was not saved")
    }

    @Test("Every case has a different description")
    func descriptionsAreUnique() {
        let texts = Self.oneOfEachCase.map(\.description)
        #expect(Set(texts).count == texts.count)
    }

    // MARK: - Equality

    @Test("The same case is equal to itself")
    func sameCaseEqual() {
        for error in Self.oneOfEachCase {
            #expect(error == error)
        }
    }

    @Test("Different cases are never equal")
    func differentCasesNotEqual() {
        let all = Self.oneOfEachCase
        for (i, left) in all.enumerated() {
            for (j, right) in all.enumerated() where i != j {
                #expect(left != right, "\(left) should differ from \(right)")
            }
        }
    }

    @Test("algorithmNotAvailable compares the name")
    func algorithmNotAvailableCompares() {
        #expect(OQSError.algorithmNotAvailable("A") == .algorithmNotAvailable("A"))
        #expect(OQSError.algorithmNotAvailable("A") != .algorithmNotAvailable("B"))
        #expect(OQSError.algorithmNotAvailable("") != .algorithmNotAvailable(" "))
    }

    @Test("invalidKeySize compares both sizes")
    func invalidKeySizeCompares() {
        #expect(OQSError.invalidKeySize(expected: 1, actual: 2) == .invalidKeySize(expected: 1, actual: 2))
        #expect(OQSError.invalidKeySize(expected: 1, actual: 2) != .invalidKeySize(expected: 1, actual: 3))
        #expect(OQSError.invalidKeySize(expected: 1, actual: 2) != .invalidKeySize(expected: 3, actual: 2))
        #expect(OQSError.invalidKeySize(expected: 1, actual: 2) != .invalidKeySize(expected: 2, actual: 1))
    }

    @Test("A thrown error can be matched by case")
    func thrownErrorMatches() {
        func fail() throws { throw OQSError.keyExhausted }
        #expect(throws: OQSError.keyExhausted) { try fail() }
    }

    // MARK: - Hashable

    @Test("Equal values hash equal")
    func equalValuesHashEqual() {
        #expect(OQSError.invalidKeySize(expected: 7, actual: 9).hashValue == OQSError.invalidKeySize(expected: 7, actual: 9).hashValue)
        #expect(OQSError.algorithmNotAvailable("X").hashValue == OQSError.algorithmNotAvailable("X").hashValue)
        #expect(OQSError.persistenceFailed.hashValue == OQSError.persistenceFailed.hashValue)
    }

    @Test("A set keeps equal values once and different values apart")
    func setCountsDistinctValues() {
        var set = Set(Self.oneOfEachCase)
        #expect(set.count == 12)
        set.insert(.invalidKeySize(expected: 32, actual: 16))
        set.insert(.keyExhausted)
        #expect(set.count == 12)
        set.insert(.invalidKeySize(expected: 16, actual: 32))
        set.insert(.algorithmNotAvailable("Sample-2"))
        #expect(set.count == 14)
    }

    // MARK: - Failure through a public type

    @Test("A wrong-size ML-KEM-512 public key throws invalidKeySize with both sizes")
    func wrongSizePublicKeyThrows() {
        let tooShort = Data(repeating: 0, count: 799)
        #expect(throws: OQSError.invalidKeySize(expected: 800, actual: 799)) {
            _ = try MLKEM512.PublicKey(rawRepresentation: tooShort)
        }
        #expect(throws: OQSError.invalidKeySize(expected: 800, actual: 0)) {
            _ = try MLKEM512.PublicKey(rawRepresentation: Data())
        }
    }

    // MARK: - Fuzz

    @Test("Fuzz: invalidKeySize text and equality track both sizes")
    func fuzzInvalidKeySize() {
        let seed: UInt64 = 0x0A5C_E44E_0001
        print("OQSErrorTests fuzz seed: \(seed)")
        var rng = SplitMix64(seed: seed)
        let edges = [0, 1, 2, 31, 32, 800, 1_000_000, Int.max, Int.max - 1]
        var pairs: [(Int, Int)] = []
        for e in edges { for a in edges { pairs.append((e, a)) } }
        for _ in 0..<2000 {
            let e = Int(rng.next() % 1_000_000)
            let a = Int(rng.next() % 1_000_000)
            pairs.append((e, a))
            pairs.append((e, e))
            pairs.append((a, e))
        }
        for (e, a) in pairs {
            let error = OQSError.invalidKeySize(expected: e, actual: a)
            // Valid direction: the hand-built text is always produced and equal values are never rejected.
            #expect(error.description == "Invalid key size: expected \(e) bytes, got \(a)")
            #expect(error == .invalidKeySize(expected: e, actual: a))
            #expect(error.hashValue == OQSError.invalidKeySize(expected: e, actual: a).hashValue)
            // Invalid direction: changing either size, or swapping unequal sizes, is never equal.
            #expect(error != .invalidKeySize(expected: e &+ 1, actual: a))
            #expect(error != .invalidKeySize(expected: e, actual: a &+ 1))
            if e != a {
                #expect(error != .invalidKeySize(expected: a, actual: e))
                #expect(error.description != OQSError.invalidKeySize(expected: a, actual: e).description)
            }
            for other in Self.oneOfEachCase where other != error {
                #expect(error != other)
            }
        }
    }
}

/// Small seeded generator so a fuzz failure can be replayed from the printed seed.
private struct SplitMix64 {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D4_9B7A_C4A7_2F13
        return z ^ (z >> 31)
    }
}
