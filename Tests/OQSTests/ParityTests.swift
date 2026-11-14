import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// Differential parity: every enabled liboqs algorithm, every output buffer,
/// raw C API vs the Swift FFI layer, byte-identical under the deterministic
/// NIST-KAT seed. This is ZigOQS's cref/zref design collapsed into one
/// process: both sides link the same vendored library, so the comparison
/// isolates the Swift wrapper layer (Data bridging, length handling, and the
/// `oqs_*_safe` bounds-annotated overloads, which are a genuinely different
/// call path from the raw `OQS_KEM_*`/`OQS_SIG_*` functions used here as the
/// reference).
///
/// KEMs compare ct/pk/sk/ss/ss2 (5 fields); signatures pk/sig/sk (3). Each
/// algorithm additionally gets a SHA-256 digest of its field bytes
/// concatenated in field-name byte order. The snapshot is one `NAME digest`
/// line per algorithm, sorted by name, the same file as the Rust and Zig
/// ports. The whole file is compared byte for byte with
/// Vectors/parity_snapshot.txt - the full-coverage drift tripwire across
/// vendored-liboqs bumps, frozen on macOS arm64 (the reference platform).
/// Sharded runs skip the whole-file comparison.
///
/// Stateful signatures are excluded (large XMSS keygen runs for hours);
/// KATTests anchors cover XMSS/LMS.
///
/// The full set takes minutes (Classic McEliece keygen and the 144 SLH-DSA
/// prehash signs dominate), so the suite is opt-in:
///
///     OQS_PARITY=1 swift test --no-parallel --filter ParityTests
///
/// Shardable for CI parallelism via OQS_SHARD / OQS_TOTAL (separate
/// processes; per-operation reseeding makes each algorithm's output
/// independent of the split). OQS_PARITY_WRITE_SNAPSHOT=1 regenerates the
/// snapshot file in the source tree instead of comparing.
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["OQS_PARITY"] == "1"))
struct ParityTests {
    // MARK: - Raw C reference side

    private static func rawKEM(_ name: String) throws -> [(String, Data)] {
        guard let kem = OQS_KEM_new(name) else { throw OQSError.algorithmNotAvailable(name) }
        defer { OQS_KEM_free(kem) }
        var pk = Data(count: Int(kem.pointee.length_public_key))
        var sk = Data(count: Int(kem.pointee.length_secret_key))
        var ct = Data(count: Int(kem.pointee.length_ciphertext))
        var ss = Data(count: Int(kem.pointee.length_shared_secret))
        var ss2 = Data(count: Int(kem.pointee.length_shared_secret))

        KAT.seedDeterministicRNG()
        var rc = pk.withUnsafeMutableBytes { p in
            sk.withUnsafeMutableBytes { s in
                OQS_KEM_keypair(kem,
                    p.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    s.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

        KAT.seedDeterministicRNG()
        rc = ct.withUnsafeMutableBytes { c in
            ss.withUnsafeMutableBytes { s in
                pk.withUnsafeBytes { p in
                    OQS_KEM_encaps(kem,
                        c.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        p.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.encapsulationFailed }

        rc = ss2.withUnsafeMutableBytes { s2 in
            ct.withUnsafeBytes { c in
                sk.withUnsafeBytes { s in
                    OQS_KEM_decaps(kem,
                        s2.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        c.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.decapsulationFailed }

        return [("pk", pk), ("sk", sk), ("ct", ct), ("ss", ss), ("ss2", ss2)]
    }

    private static let message = Data("the quick brown fox".utf8)

    private static func rawSig(_ name: String) throws -> [(String, Data)] {
        guard let sig = OQS_SIG_new(name) else { throw OQSError.algorithmNotAvailable(name) }
        defer { OQS_SIG_free(sig) }
        var pk = Data(count: Int(sig.pointee.length_public_key))
        var sk = Data(count: Int(sig.pointee.length_secret_key))
        var sg = Data(count: Int(sig.pointee.length_signature))
        var sgLen = 0

        KAT.seedDeterministicRNG()
        var rc = pk.withUnsafeMutableBytes { p in
            sk.withUnsafeMutableBytes { s in
                OQS_SIG_keypair(sig,
                    p.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    s.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

        KAT.seedDeterministicRNG()
        rc = sg.withUnsafeMutableBytes { g in
            message.withUnsafeBytes { m in
                sk.withUnsafeBytes { s in
                    OQS_SIG_sign(sig,
                        g.baseAddress?.assumingMemoryBound(to: UInt8.self), &sgLen,
                        m.baseAddress?.assumingMemoryBound(to: UInt8.self), message.count,
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.signFailed }
        sg.removeSubrange(sgLen...)

        return [("pk", pk), ("sk", sk), ("sig", sg)]
    }

    // MARK: - Swift wrapper side (the layer under test)

    private static func wrapperKEM(_ name: String) throws -> [(String, Data)] {
        KAT.seedDeterministicRNG()
        let kp = try kemGenerateKeyPair(algorithm: name)
        KAT.seedDeterministicRNG()
        let enc = try kemEncapsulate(algorithm: name, publicKey: kp.publicKey)
        let ss2 = try kemDecapsulate(algorithm: name, ciphertext: enc.ciphertext, secretKey: kp.secretKey)
        return [("pk", kp.publicKey), ("sk", kp.secretKey), ("ct", enc.ciphertext), ("ss", enc.sharedSecret), ("ss2", ss2)]
    }

    private static func wrapperSig(_ name: String) throws -> [(String, Data)] {
        KAT.seedDeterministicRNG()
        let kp = try sigGenerateKeyPair(algorithm: name)
        KAT.seedDeterministicRNG()
        let sg = try sigSign(algorithm: name, message: message, secretKey: kp.secretKey)
        return [("pk", kp.publicKey), ("sk", kp.secretKey), ("sig", sg)]
    }

    // MARK: - Enumeration and sharding

    private static func enabledAlgorithms() -> (kems: [String], sigs: [String]) {
        var kems: [String] = []
        for i in 0..<OQS_KEM_alg_count() {
            guard let id = OQS_KEM_alg_identifier(Int(i)) else { continue }
            let name = String(cString: id)
            if OQS_KEM_alg_is_enabled(name) == 1 { kems.append(name) }
        }
        var sigs: [String] = []
        for i in 0..<OQS_SIG_alg_count() {
            guard let id = OQS_SIG_alg_identifier(Int(i)) else { continue }
            let name = String(cString: id)
            if OQS_SIG_alg_is_enabled(name) == 1 { sigs.append(name) }
        }
        return (kems, sigs)
    }

    private static func shardFilter<T>(_ items: [T], offset: Int) -> [T] {
        let env = ProcessInfo.processInfo.environment
        guard let total = env["OQS_TOTAL"].flatMap({ Int($0) }), total > 1 else { return items }
        let shard = env["OQS_SHARD"].flatMap({ Int($0) }) ?? 0
        return items.enumerated().compactMap { (offset + $0.offset) % total == shard ? $0.element : nil }
    }

    // MARK: - The gate

    @Test("Every algorithm: raw C and Swift wrapper outputs are byte-identical")
    func parity() throws {
        defer { KAT.restoreSystemRNG() }
        let (allKEMs, allSigs) = Self.enabledAlgorithms()
        let kems = Self.shardFilter(allKEMs, offset: 0)
        let sigs = Self.shardFilter(allSigs, offset: allKEMs.count)

        struct Mismatch: CustomStringConvertible {
            let algo: String, field: String, detail: String
            var description: String { "\(algo) \(field): \(detail)" }
        }

        // MQOM2/SNOVA signing overflows the 512 KB test-worker stack; the
        // whole sweep runs on one 8 MB thread.
        let result = try onLargeStack { () -> (mismatches: [String], digests: [(String, String)], fields: Int) in
            var mismatches: [String] = []
            var digests: [(String, String)] = []
            var fields = 0

            func compare(_ algo: String, _ raw: [(String, Data)], _ wrapped: [(String, Data)]) {
                for ((field, r), (_, w)) in zip(raw, wrapped) {
                    fields += 1
                    if r != w {
                        let detail = r.count != w.count
                            ? "length \(r.count) vs \(w.count)"
                            : "content differs (\(r.count) bytes)"
                        mismatches.append("\(algo) \(field): \(detail)")
                    }
                }
                digests.append((algo, SnapshotFormat.digest(wrapped)))
            }

            for name in kems {
                print("  parity kem \(name)")
                compare(name, try Self.rawKEM(name), try Self.wrapperKEM(name))
            }
            for name in sigs {
                print("  parity sig \(name)")
                compare(name, try Self.rawSig(name), try Self.wrapperSig(name))
            }
            return (mismatches, digests, fields)
        }

        print("parity: \(kems.count) KEMs + \(sigs.count) sigs, \(result.fields) field pairs compared")
        for m in result.mismatches {
            Issue.record("parity mismatch: \(m)")
        }
        #expect(result.mismatches.isEmpty)

        try Self.checkOrWriteSnapshot(result.digests)
    }

    // MARK: - Full-coverage snapshot (reference platform only)

    private static var snapshotSourcePath: String {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Vectors/parity_snapshot.txt").path
    }

    private static func checkOrWriteSnapshot(_ digests: [(String, String)]) throws {
        let env = ProcessInfo.processInfo.environment
        if env["OQS_PARITY_WRITE_SNAPSHOT"] == "1" {
            // Regeneration only makes sense unsharded (a shard would drop lines).
            guard env["OQS_TOTAL"].flatMap({ Int($0) }) ?? 1 <= 1 else {
                Issue.record("refusing to write snapshot from a sharded run")
                return
            }
            let text = SnapshotFormat.text(digests)
            try text.write(toFile: snapshotSourcePath, atomically: true, encoding: .utf8)
            print("parity: wrote \(digests.count) digests to \(snapshotSourcePath)")
            return
        }

        // A shard holds only part of the lines, so the whole-file check cannot run.
        guard env["OQS_TOTAL"].flatMap({ Int($0) }) ?? 1 <= 1 else {
            print("parity: sharded run, skipping whole-file snapshot comparison")
            return
        }

        // The snapshot is frozen on macOS arm64; other platforms validate
        // parity (self-consistent anywhere) but skip the drift check.
        #if !(os(macOS) && arch(arm64))
        print("parity: not macOS arm64, skipping snapshot comparison")
        return
        #else
        guard let url = Bundle.module.url(forResource: "parity_snapshot", withExtension: "txt", subdirectory: "Vectors") else {
            Issue.record("parity_snapshot.txt missing from test bundle; regenerate with OQS_PARITY_WRITE_SNAPSHOT=1")
            return
        }
        let expected = try String(contentsOf: url, encoding: .utf8)
        let actual = SnapshotFormat.text(digests)
        if actual != expected {
            let diffs = SnapshotFormat.differences(expected: expected, actual: actual)
            Issue.record("snapshot drift (regenerate with OQS_PARITY_WRITE_SNAPSHOT=1): \(diffs.isEmpty ? "formatting differs" : diffs.joined(separator: ", "))")
        }
        #endif
    }
}
