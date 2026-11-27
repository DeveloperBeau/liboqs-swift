import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// Differential parity for the stateful hash-based signatures (XMSS, XMSS^MT,
/// LMS): the raw `OQS_SIG_STFL_*` C API against the public `XMSS`, `XMSSMT`
/// and `LMS` types, under the deterministic NIST-KAT seed.
///
/// Compared per algorithm: public key, the C-format secret key after one sign,
/// the signature, and the remaining and total signature counts after that sign. The public types expose the secret key as a blob of
/// `publicKey || liboqs-secret-key`, so the test drops the public-key prefix
/// before it compares with the C secret key. The signature must also verify
/// through the public type.
///
/// This suite is outside the frozen snapshot: it writes no snapshot line and
/// reads none. Key generation cost grows with tree height, so by default only
/// parameter sets with a total height of 16 or less (at most 2^16 signatures)
/// run, and each skipped name is printed. Set OQS_STATEFUL_ALL=1 to run all.
///
///     OQS_PARITY=1 swift test --no-parallel --filter StatefulParityTests
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["OQS_PARITY"] == "1"))
struct StatefulParityTests {
    private static let maxDefaultHeight = 16
    private static let message = ParityRegistry.message

    // MARK: - Enumeration

    private static func enabledNames() -> [String] {
        (0..<OQS_SIG_STFL_alg_count()).compactMap { i in
            guard let id = OQS_SIG_STFL_alg_identifier(Int(i)) else { return nil }
            let name = String(cString: id)
            return OQS_SIG_STFL_alg_is_enabled(name) == 1 ? name : nil
        }
    }

    /// Total tree height from the liboqs name: `XMSS-SHA2_10_256` is 10,
    /// `XMSSMT-SHA2_20/2_256` is 20, `LMS_SHA256_H10_W4_H5_W8` is 10 + 5.
    private static func totalHeight(_ name: String) -> Int {
        let parts = name.split(separator: "_")
        if name.hasPrefix("LMS") {
            return parts.compactMap { $0.hasPrefix("H") ? Int($0.dropFirst()) : nil }.reduce(0, +)
        }
        return Int(parts[1].prefix(while: \.isNumber)) ?? Int.max
    }

    // MARK: - Raw C reference side

    private struct Outputs: Sendable {
        let pk: Data, sk: Data, sig: Data, remaining: UInt64, total: UInt64
    }

    private static func raw(_ name: String) throws -> Outputs {
        guard let sig = OQS_SIG_STFL_new(name) else { throw OQSError.algorithmNotAvailable(name) }
        defer { OQS_SIG_STFL_free(sig) }
        guard let key = OQS_SIG_STFL_SECRET_KEY_new(name) else { throw OQSError.algorithmNotAvailable(name) }
        defer { OQS_SIG_STFL_SECRET_KEY_free(key) }

        // liboqs calls the store callback after keygen and sign. This one keeps
        // nothing and reports success. The context must be non-NULL: LMS drops
        // a callback registered with a NULL context.
        OQS_SIG_STFL_SECRET_KEY_SET_store_cb(key, { _, _, _ in OQS_SUCCESS }, UnsafeMutableRawPointer(bitPattern: 1))

        var pk = Data(count: Int(sig.pointee.length_public_key))
        var sg = Data(count: Int(sig.pointee.length_signature))
        var sgLen = 0

        KAT.seedDeterministicRNG()
        var rc = pk.withUnsafeMutableBytes { p in
            OQS_SIG_STFL_keypair(sig, p.baseAddress?.assumingMemoryBound(to: UInt8.self), key)
        }
        guard rc == OQS_SUCCESS else { throw OQSError.keyGenerationFailed }

        KAT.seedDeterministicRNG()
        rc = sg.withUnsafeMutableBytes { g in
            message.withUnsafeBytes { m in
                OQS_SIG_STFL_sign(sig,
                    g.baseAddress?.assumingMemoryBound(to: UInt8.self), &sgLen,
                    m.baseAddress?.assumingMemoryBound(to: UInt8.self), message.count, key)
            }
        }
        guard rc == OQS_SUCCESS else { throw OQSError.signFailed }
        sg.removeSubrange(sgLen...)

        var remaining: UInt64 = 0
        var total: UInt64 = 0
        guard OQS_SIG_STFL_sigs_remaining(sig, &remaining, key) == OQS_SUCCESS,
              OQS_SIG_STFL_sigs_total(sig, &total, key) == OQS_SUCCESS else {
            throw OQSError.invalidKeySize(expected: 0, actual: 0)
        }

        var buf: UnsafeMutablePointer<UInt8>?
        var bufLen = 0
        guard OQS_SIG_STFL_SECRET_KEY_serialize(&buf, &bufLen, key) == OQS_SUCCESS, let buf else {
            throw OQSError.keyGenerationFailed
        }
        defer { OQS_MEM_secure_free(buf, bufLen) }
        return Outputs(pk: pk, sk: Data(bytes: buf, count: bufLen), sig: sg, remaining: remaining, total: total)
    }

    // MARK: - Public type side

    /// The public API of the three families, which share no protocol, behind
    /// one shape. `verified` is the result of `isValidSignature` on the public key.
    private static func wrapper(_ name: String) throws -> (outputs: Outputs, verified: Bool) {
        KAT.seedDeterministicRNG()
        let pk: Data
        let blob: Data
        let sig: Data
        let verified: Bool
        let remaining: UInt64
        let total: UInt64
        if let v = XMSSMT.Variant(rawValue: name) {
            let key = try XMSSMT.PrivateKey(v)
            KAT.seedDeterministicRNG()
            sig = try key.signature(for: message) { _ in }
            pk = key.publicKey.rawRepresentation
            blob = try key.serializedSecretKey
            verified = try key.publicKey.isValidSignature(sig, for: message)
            remaining = try key.remainingSignatures
            total = try key.totalSignatures
        } else if let v = XMSS.Variant(rawValue: name) {
            let key = try XMSS.PrivateKey(v)
            KAT.seedDeterministicRNG()
            sig = try key.signature(for: message) { _ in }
            pk = key.publicKey.rawRepresentation
            blob = try key.serializedSecretKey
            verified = try key.publicKey.isValidSignature(sig, for: message)
            remaining = try key.remainingSignatures
            total = try key.totalSignatures
        } else if let v = LMS.Variant(rawValue: name) {
            let key = try LMS.PrivateKey(v)
            KAT.seedDeterministicRNG()
            sig = try key.signature(for: message) { _ in }
            pk = key.publicKey.rawRepresentation
            blob = try key.serializedSecretKey
            verified = try key.publicKey.isValidSignature(sig, for: message)
            remaining = try key.remainingSignatures
            total = try key.totalSignatures
        } else {
            throw OQSError.algorithmNotAvailable(name)
        }
        return (Outputs(pk: pk, sk: Data(blob.dropFirst(pk.count)), sig: sig,
                         remaining: remaining, total: total), verified)
    }

    // MARK: - The gate

    @Test("Stateful XMSS, XMSS^MT and LMS: raw C and public types are byte-identical")
    func parity() throws {
        defer { KAT.restoreSystemRNG() }
        guard StatefulSignatureSupport.isKeyGenerationSupported else {
            print("stateful parity: key generation not supported in this build, skipping")
            return
        }
        let runAll = ProcessInfo.processInfo.environment["OQS_STATEFUL_ALL"] == "1"
        let names = Self.enabledNames().filter { name in
            let height = Self.totalHeight(name)
            if runAll || height <= Self.maxDefaultHeight { return true }
            print("stateful parity: skipping \(name), total height \(height) > \(Self.maxDefaultHeight) (set OQS_STATEFUL_ALL=1 to run)")
            return false
        }

        // Same 8 MB stack as ParityTests, for the deep hash-tree recursion.
        let failures = try onLargeStack { () -> [String] in
            var failures: [String] = []
            for name in names {
                print("  stateful parity \(name)")
                let ref: Outputs, got: Outputs, verified: Bool
                do {
                    ref = try Self.raw(name)
                    (got, verified) = try Self.wrapper(name)
                } catch {
                    // Includes an enabled name that no public Variant covers.
                    failures.append("\(name): \(error)")
                    continue
                }
                for (field, r, w) in [("pk", ref.pk, got.pk), ("sk", ref.sk, got.sk), ("sig", ref.sig, got.sig)] where r != w {
                    failures.append("\(name) \(field): " + (r.count != w.count
                        ? "length \(r.count) vs \(w.count)" : "content differs (\(r.count) bytes)"))
                }
                if ref.remaining != got.remaining {
                    failures.append("\(name) remaining: \(ref.remaining) vs \(got.remaining)")
                }
                if ref.total != got.total { failures.append("\(name) total: \(ref.total) vs \(got.total)") }
                if !verified { failures.append("\(name): signature does not verify through the public type") }
            }
            return failures
        }

        print("stateful parity: \(names.count) algorithms checked")
        for f in failures { Issue.record("stateful parity mismatch: \(f)") }
        #expect(failures.isEmpty)
    }
}
