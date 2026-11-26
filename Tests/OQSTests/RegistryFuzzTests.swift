import Testing
@testable import OQS

/// Seeded fuzz of the ``Registry`` name lookup, in both directions.
///
/// The seed comes from `OQS_FUZZ_SEED` (hex), with a fixed default. It is
/// printed at the start and in every failure message, so a failing run can be
/// replayed.
@Suite struct RegistryFuzzTests {
    enum Kind: CaseIterable, CustomStringConvertible {
        case kem, signature, stateful

        var names: [String] {
            switch self {
            case .kem: Registry.enabledKEMNames
            case .signature: Registry.enabledSignatureNames
            case .stateful: Registry.enabledStatefulSignatureNames
            }
        }

        var description: String {
            switch self {
            case .kem: "KEM"
            case .signature: "signature"
            case .stateful: "stateful signature"
            }
        }
    }

    // The description name a lookup of `kind` gives. The enabled check must
    // agree with the lookup.
    private static func lookUp(_ kind: Kind, _ name: String, context: String) -> String? {
        let found: String?
        let enabled: Bool
        switch kind {
        case .kem:
            found = Registry.kemDescription(named: name)?.name
            enabled = Registry.isKEMEnabled(name)
        case .signature:
            found = Registry.signatureDescription(named: name)?.name
            enabled = Registry.isSignatureEnabled(name)
        case .stateful:
            found = Registry.statefulSignatureDescription(named: name)?.name
            enabled = Registry.isStatefulSignatureEnabled(name)
        }
        #expect((found != nil) == enabled, "enabled check and lookup disagree for \(kind) \(Array(name.utf8)) (\(context))")
        return found
    }

    // The listed name that `bytes` equals when the case of A to Z is ignored,
    // or nil. Written out with its own byte loop, not with the helper the
    // registry uses.
    private static func listHolds(_ list: [String], _ bytes: [UInt8]) -> String? {
        func fold(_ b: UInt8) -> UInt8 { (65...90).contains(b) ? b + 32 : b }
        outer: for entry in list {
            let e = Array(entry.utf8)
            guard e.count == bytes.count else { continue }
            for i in e.indices where fold(e[i]) != fold(bytes[i]) {
                continue outer
            }
            return entry
        }
        return nil
    }

    private static func lower(_ b: UInt8) -> UInt8 { (65...90).contains(b) ? b + 32 : b }
    private static func upper(_ b: UInt8) -> UInt8 { (97...122).contains(b) ? b - 32 : b }

    // A copy of `bytes` with the case of each ASCII letter picked at random.
    private static func randomCase(_ bytes: [UInt8], _ rng: inout SeededGenerator) -> [UInt8] {
        bytes.map { Bool.random(using: &rng) ? upper($0) : lower($0) }
    }

    // Non-ASCII characters, some of which Unicode case mapping turns into ASCII letters.
    private static let nonASCII: [Unicode.Scalar] = ["\u{212A}", "\u{131}", "\u{130}", "\u{17F}", "\u{FF2D}", "\u{E9}", "\u{FFFD}"]

    @Test("Fuzz with a seed: every listed name in any ASCII case is found as the listed name, and mutated or swapped names are found only when listed")
    func fuzzLookup() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SeededGenerator(seed: seed)
        let lists = Kind.allCases.map(\.names)

        // False negatives: every listed name, as listed, all lowercase, all
        // uppercase and in four random cases, is found under its own kind
        // and gives back the listed name.
        for (k, kind) in Kind.allCases.enumerated() {
            for name in lists[k] {
                let bytes = Array(name.utf8)
                var asked = [bytes, bytes.map(Self.lower), bytes.map(Self.upper)]
                for _ in 0..<4 { asked.append(Self.randomCase(bytes, &rng)) }
                for a in asked {
                    let text = String(decoding: a, as: UTF8.self)
                    let found = Self.lookUp(kind, text, context: "seed 0x\(String(seed, radix: 16))")
                    #expect(found == name, "listed \(kind) \(name) asked as \(text) gave \(found ?? "nil") (seed 0x\(String(seed, radix: 16)))")
                }
            }
        }

        // False positives: a mutated name, or a name looked up under another
        // kind, is found only when the list of that kind holds it ignoring
        // ASCII case, and then gives back the listed name.
        var matchedRounds = 0
        for round in 0..<2000 {
            let from = Int.random(in: 0..<Kind.allCases.count, using: &rng)
            let original = lists[from].randomElement(using: &rng)!
            // Start from a random case, so every mutation also meets mixed case.
            var bytes = Self.randomCase(Array(original.utf8), &rng)
            var into = from
            let mutation = Int.random(in: 0..<7, using: &rng)
            switch mutation {
            case 0:
                // Flip one byte.
                bytes[Int.random(in: 0..<bytes.count, using: &rng)] ^= UInt8.random(in: 1...255, using: &rng)
            case 1:
                // Cut the name short.
                bytes.removeLast(Int.random(in: 1...bytes.count, using: &rng))
            case 2:
                // Add one to four bytes at the end.
                for _ in 0..<Int.random(in: 1...4, using: &rng) { bytes.append(UInt8.random(in: 0...255, using: &rng)) }
            case 3:
                // Flip bit 0x20 of one byte. For a letter that is a case
                // change, which must still match.
                bytes[Int.random(in: 0..<bytes.count, using: &rng)] ^= 0x20
            case 4:
                // Replace one byte with a non-ASCII character.
                let at = Int.random(in: 0..<bytes.count, using: &rng)
                let scalar = Self.nonASCII.randomElement(using: &rng)!
                bytes.replaceSubrange(at...at, with: Array(String(Character(scalar)).utf8))
            case 5:
                // Put a NUL byte in, or at the end.
                bytes.insert(0, at: Int.random(in: 0...bytes.count, using: &rng))
            default:
                // Keep the name but look it up under another kind.
                into = (from + Int.random(in: 1..<Kind.allCases.count, using: &rng)) % Kind.allCases.count
            }
            // Bytes that are not valid UTF-8 become U+FFFD here, so the
            // expected result is worked out from the bytes the string holds.
            let text = String(decoding: bytes, as: UTF8.self)
            let expected = Self.listHolds(lists[into], Array(text.utf8))
            let context = "seed 0x\(String(seed, radix: 16)), round \(round), mutation \(mutation), from \(original)"
            let found = Self.lookUp(Kind.allCases[into], text, context: context)
            #expect(found == expected, "\(Kind.allCases[into]) \(Array(text.utf8)) gave \(found ?? "nil"), listed \(expected ?? "nil") (\(context))")
            if expected != nil { matchedRounds += 1 }
        }
        // Case flips of letters must still match, so some rounds are expected
        // hits. Without any, the false-positive half would not test the
        // returned name at all.
        #expect(matchedRounds > 0, "no fuzz round was expected to match (seed 0x\(String(seed, radix: 16)))")
    }
}
