import Foundation
import Testing
@testable import OQS
internal import Cliboqs

enum KAT {
    /// The standard liboqs NIST-KAT entropy seed: bytes 0..47.
    static let seed: [UInt8] = Array(0..<48)

    /// Switches liboqs RNG to the deterministic NIST-KAT DRBG seeded with `seed`.
    ///
    /// Note: liboqs 0.15.0's `OQS_randombytes_switch_algorithm` only recognizes
    /// "system" and "OpenSSL" (verified in `src/common/rand/rand.c`); there is no
    /// "NIST-KAT" branch. The NIST-KAT DRBG is activated via
    /// `OQS_randombytes_custom_algorithm(&OQS_randombytes_nist_kat)`, which is the
    /// mechanism liboqs's own KAT harness uses.
    static func seedDeterministicRNG() {
        OQS_randombytes_custom_algorithm(OQS_randombytes_nist_kat)
        seed.withUnsafeBufferPointer { buf in
            OQS_randombytes_nist_kat_init_256bit(buf.baseAddress, nil)
        }
    }

    /// Restores the default system RNG so other tests are non-deterministic.
    static func restoreSystemRNG() {
        _ = OQS_randombytes_switch_algorithm("system")
    }

    /// SHA3-256 hex digest of `data` (uses liboqs `OQS_SHA3_sha3_256`).
    static func sha3_256Hex(_ data: Data) -> String {
        var out = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { inBuf in
            OQS_SHA3_sha3_256(&out, inBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count)
        }
        return out.map { String(format: "%02x", $0) }.joined()
    }
}

struct KATHashes {
    static let shared = KATHashes()
    private let table: [String: String]

    private init() {
        let url = Bundle.module.url(forResource: "kat_hashes", withExtension: "json", subdirectory: "Vectors")!
        let data = try! Data(contentsOf: url)
        table = try! JSONDecoder().decode([String: String].self, from: data)
    }

    func hash(for algorithm: String) throws -> String {
        guard let h = table[algorithm] else {
            throw OQSError.algorithmNotAvailable("no KAT hash for \(algorithm)")
        }
        return h
    }
}
