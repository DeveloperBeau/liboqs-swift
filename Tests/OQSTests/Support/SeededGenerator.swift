import Foundation

/// A small seeded random number generator (SplitMix64) for fuzz tests.
///
/// The same seed always gives the same values, so a failing fuzz run can be
/// replayed. It is not for cryptographic use.
struct SeededGenerator: RandomNumberGenerator {
    /// The seed used when `OQS_FUZZ_SEED` is not set.
    static let defaultSeed: UInt64 = 0x5717_F022

    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    /// The seed from `OQS_FUZZ_SEED` (hex, with or without `0x`), or the default seed.
    ///
    /// A value that is not hex is a test failure, not a quiet fallback.
    static func seedFromEnvironment() throws -> UInt64 {
        guard let text = ProcessInfo.processInfo.environment["OQS_FUZZ_SEED"] else { return defaultSeed }
        let digits = text.hasPrefix("0x") || text.hasPrefix("0X") ? String(text.dropFirst(2)) : text
        guard let seed = UInt64(digits, radix: 16) else { throw InvalidSeed(text: text) }
        return seed
    }

    struct InvalidSeed: Error, CustomStringConvertible {
        let text: String
        var description: String { "OQS_FUZZ_SEED is not a hex number: \(text)" }
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
