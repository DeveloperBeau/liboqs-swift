import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// A test-only error thrown from the persist closure. The wrapper must hide it
/// behind `OQSError.persistenceFailed`.
private struct PersistFailure: Error, Equatable {}

@Suite(.serialized) struct StatefulSignatureTests {

    // MARK: - Round-trip (small variants only)

    @Test("XMSS round-trip: generate, sign with persist, verify")
    func xmssRoundTrip() throws {
        let key = try XMSS.PrivateKey(.sha2_10_256)
        var stored: Data? = try key.serializedSecretKey
        #expect(stored != nil)

        let message = Data("hello xmss".utf8)
        let sig = try key.signature(for: message) { advanced in
            stored = advanced
        }
        let pub = XMSS.PublicKey(.sha2_10_256, rawRepresentation: key.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    @Test("XMSSMT round-trip: generate, sign with persist, verify")
    func xmssmtRoundTrip() throws {
        let key = try XMSSMT.PrivateKey(.sha2_h20_2)
        var stored: Data? = try key.serializedSecretKey
        #expect(stored != nil)

        let message = Data("hello xmssmt".utf8)
        let sig = try key.signature(for: message) { advanced in
            stored = advanced
        }
        let pub = XMSSMT.PublicKey(.sha2_h20_2, rawRepresentation: key.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    @Test("LMS round-trip: generate, sign with persist, verify")
    func lmsRoundTrip() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        var stored: Data? = try key.serializedSecretKey
        #expect(stored != nil)

        let message = Data("hello lms".utf8)
        let sig = try key.signature(for: message) { advanced in
            stored = advanced
        }
        let pub = LMS.PublicKey(.sha256_h5_w1, rawRepresentation: key.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    // MARK: - NEGATIVE test: safety invariant (no signature without persistence)

    /// Proves the core stateful-safety invariant: a signature is returned IFF the
    /// user's persist closure succeeded.
    ///
    /// Asserts:
    /// (a) when the persist closure throws, `signature(for:persistingTo:)` throws
    ///     `OQSError.persistenceFailed`;
    /// (b) no signature value escapes the wrapper on that path;
    /// (c) state consistency — a subsequent sign with a real persist closure
    ///     produces a verifiable signature.
    ///
    /// Observed index semantics (verified empirically against liboqs 0.15.0): on a
    /// thrown persist the in-memory index has ALREADY advanced, but the new state
    /// was NOT persisted. The next sign therefore uses the following index — one
    /// index is skipped, never reused. Restoring from the last persisted blob would
    /// resume at the prior (un-advanced) index. In all cases, no index that
    /// produced a *returned* signature is ever reused. (This is the safe direction:
    /// the catastrophe — sign returning SUCCESS while state is unpersisted — does
    /// not occur, confirmed in liboqs's XMSS/LMS sign sources.)
    @Test("XMSS negative: throwing persist yields no signature, then recovers")
    func xmssNegativePersistFailure() throws {
        let key = try XMSS.PrivateKey(.sha2_10_256)
        var stored: Data? = try key.serializedSecretKey
        let message = Data("negative-test".utf8)

        // (a)+(b): throwing persist must throw persistenceFailed; no sig returned.
        var captured: Data? = nil
        var thrown: Error? = nil
        do {
            captured = try key.signature(for: message) { _ in
                throw PersistFailure()
            }
        } catch {
            thrown = error
        }
        #expect(captured == nil, "no signature must escape on a failed persist")
        #expect(thrown as? OQSError == .persistenceFailed, "got \(String(describing: thrown))")

        // (c): the key is still usable; a real sign produces a verifiable signature.
        let sig = try key.signature(for: message) { advanced in
            stored = advanced
        }
        #expect(stored != nil)
        let pub = XMSS.PublicKey(.sha2_10_256, rawRepresentation: key.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    @Test("LMS negative: throwing persist yields no signature, then recovers")
    func lmsNegativePersistFailure() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        var stored: Data? = try key.serializedSecretKey
        let message = Data("negative-test".utf8)

        var captured: Data? = nil
        var thrown: Error? = nil
        do {
            captured = try key.signature(for: message) { _ in
                throw PersistFailure()
            }
        } catch {
            thrown = error
        }
        #expect(captured == nil, "no signature must escape on a failed persist")
        #expect(thrown as? OQSError == .persistenceFailed, "got \(String(describing: thrown))")

        let sig = try key.signature(for: message) { advanced in
            stored = advanced
        }
        let pub = LMS.PublicKey(.sha256_h5_w1, rawRepresentation: key.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    // MARK: - Generation persist + restore round-trip

    @Test("serializedSecretKey is non-empty after generation and round-trips")
    func generationPersistRoundTrip() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        let blob = try key.serializedSecretKey
        #expect(!blob.isEmpty)

        // Restore a fresh key from the persisted bytes and sign with it.
        let restored = try LMS.PrivateKey(.sha256_h5_w1, serializedSecretKey: blob)
        #expect(restored.publicKey.rawRepresentation == key.publicKey.rawRepresentation)

        let message = Data("restored".utf8)
        var stored: Data? = nil
        let sig = try restored.signature(for: message) { stored = $0 }
        #expect(stored != nil)
        let pub = LMS.PublicKey(.sha256_h5_w1, rawRepresentation: restored.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    @Test("XMSS restore from generation blob round-trips")
    func xmssGenerationRestore() throws {
        let key = try XMSS.PrivateKey(.sha2_10_256)
        let blob = try key.serializedSecretKey
        let restored = try XMSS.PrivateKey(.sha2_10_256, serializedSecretKey: blob)
        #expect(restored.publicKey.rawRepresentation == key.publicKey.rawRepresentation)

        let message = Data("xmss-restore".utf8)
        var stored: Data? = nil
        let sig = try restored.signature(for: message) { stored = $0 }
        #expect(stored != nil)
        let pub = XMSS.PublicKey(.sha2_10_256, rawRepresentation: restored.publicKey.rawRepresentation)
        #expect(try pub.isValidSignature(sig, for: message))
    }

    // MARK: - remainingSignatures

    @Test("remainingSignatures decreases by one after a successful sign")
    func remainingSignaturesDecrements() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        let before = try key.remainingSignatures
        #expect(before > 0)

        var stored: Data? = nil
        _ = try key.signature(for: Data("count".utf8)) { stored = $0 }
        let after = try key.remainingSignatures
        #expect(after == before - 1, "expected \(before - 1), got \(after)")
    }

    // MARK: - totalSignatures

    // Expected values are written by hand from the schemes. A tree of height h
    // makes 2^h - 1 signatures in liboqs. LMS_SHA256_H5_W1 is 2^5 - 1 = 31.
    // XMSS-SHA2_10_256 is 2^10 - 1 = 1023. XMSSMT-SHA2_20/2_256 is 2^20 - 1.
    // The LMS_SHA256_H5_W1 signature is 4 + 4 + 4 + 32 + 265 * 32 + 4 + 5 * 32 = 8688.

    @Test("totalSignatures is 2^h - 1 and constant while remainingSignatures drops, for LMS, XMSS and XMSS^MT")
    func totalSignaturesIsConstant() throws {
        let message = Data("count".utf8)
        let lms = try LMS.PrivateKey(.sha256_h5_w1)
        let xmss = try XMSS.PrivateKey(.sha2_10_256)
        let xmssmt = try XMSSMT.PrivateKey(.sha2_h20_2)
        #expect(try lms.totalSignatures == 31)
        #expect(try lms.remainingSignatures == 31)
        #expect(try xmss.totalSignatures == 1023)
        #expect(try xmss.remainingSignatures == 1023)
        #expect(try xmssmt.totalSignatures == 1_048_575)
        #expect(try xmssmt.remainingSignatures == 1_048_575)
        for i: UInt64 in 1...2 {
            _ = try lms.signature(for: message) { _ in }
            _ = try xmss.signature(for: message) { _ in }
            _ = try xmssmt.signature(for: message) { _ in }
            #expect(try lms.remainingSignatures == 31 - i)
            #expect(try lms.totalSignatures == 31)
            #expect(try xmss.remainingSignatures == 1023 - i)
            #expect(try xmss.totalSignatures == 1023)
            #expect(try xmssmt.remainingSignatures == 1_048_575 - i)
            #expect(try xmssmt.totalSignatures == 1_048_575)
        }
    }

    @Test("a throwing persist skips one index but never returns a signature, and the counts still drop by one")
    func persistFailureConsumesOneIndex() throws {
        let key = try XMSS.PrivateKey(.sha2_10_256)
        #expect(throws: OQSError.persistenceFailed) {
            _ = try key.signature(for: Data("x".utf8)) { _ in throw PersistFailure() }
        }
        #expect(try key.remainingSignatures == 1022)
        #expect(try key.totalSignatures == 1023)
    }

    // MARK: - Used-up keys

    // liboqs makes totalSignatures + 1 signatures per key. The last one is made
    // when remainingSignatures already reads 0. Checked against liboqs 0.16.0
    // by hand before the expected values were written.
    @Test("LMS_SHA256_H5_W1 makes 32 signatures, the 32nd at remaining 0 verifies, then the counts throw invalidKeySize and sign throws keyExhausted")
    func lmsExhaustion() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        let message = Data("the quick brown fox".utf8)
        for i: UInt64 in 0..<32 {
            #expect(try key.remainingSignatures == 31 - i)
            #expect(try key.totalSignatures == 31)
            let sig = try key.signature(for: message) { _ in }
            #expect(sig.count == 8688)
            #expect(try key.publicKey.isValidSignature(sig, for: message))
        }
        do {
            _ = try key.remainingSignatures
            Issue.record("remainingSignatures must throw on a used-up LMS key")
        } catch let OQSError.invalidKeySize(expected, actual) {
            #expect(expected > 0 && actual == 0)
        }
        do {
            _ = try key.totalSignatures
            Issue.record("totalSignatures must throw on a used-up LMS key")
        } catch let OQSError.invalidKeySize(expected, actual) {
            #expect(expected > 0 && actual == 0)
        }
        for _ in 0..<2 {
            var captured: Data?
            #expect(throws: OQSError.keyExhausted) {
                captured = try key.signature(for: message) { _ in }
            }
            #expect(captured == nil)
        }
    }

    @Test("a throwing persist on a used-up LMS key throws persistenceFailed, not keyExhausted")
    func persistFailureOutranksExhaustion() throws {
        let key = try LMS.PrivateKey(.sha256_h5_w1)
        let message = Data("x".utf8)
        for _ in 0..<32 { _ = try key.signature(for: message) { _ in } }
        var storeCalls = 0
        var captured: Data?
        // liboqs LMS still calls the store callback when it has no signature,
        // so the failed save is what the caller sees.
        #expect(throws: OQSError.persistenceFailed) {
            captured = try key.signature(for: message) { _ in
                storeCalls += 1
                throw PersistFailure()
            }
        }
        #expect(storeCalls == 1)
        #expect(captured == nil)
    }

    @Test("XMSS-SHA2_10_256 makes 1024 signatures, the 1024th at remaining 0 does not verify, remaining then wraps to UInt64.max, and the next sign throws signFailed")
    func xmssExhaustion() throws {
        let key = try XMSS.PrivateKey(.sha2_10_256)
        let message = Data("the quick brown fox".utf8)
        for i: UInt64 in 0..<1023 {
            #expect(try key.remainingSignatures == 1023 - i)
            let sig = try key.signature(for: message) { _ in }
            #expect(try key.publicKey.isValidSignature(sig, for: message))
        }
        #expect(try key.remainingSignatures == 0)
        #expect(try key.totalSignatures == 1023)

        // At the last index liboqs wipes the key and signs with zeroed seeds.
        // The signature has the full length and does not verify.
        let last = try key.signature(for: message) { _ in }
        #expect(last.count == 2500)
        #expect(try !key.publicKey.isValidSignature(last, for: message))

        // liboqs computes 1023 - 1024 in unsigned 64-bit arithmetic.
        #expect(try key.remainingSignatures == 18_446_744_073_709_551_615)
        #expect(try key.totalSignatures == 1023)

        var captured: Data?
        #expect(throws: OQSError.signFailed) {
            captured = try key.signature(for: message) { _ in }
        }
        #expect(captured == nil)
    }

    // MARK: - Decision seam and fuzz

    @Test("producedLength follows the shared check order for every status, length and persist outcome")
    func producedLengthTable() throws {
        let statuses: [OQS_STATUS] = [OQS_SUCCESS, OQS_ERROR, OQS_EXTERNAL_LIB_ERROR_OPENSSL]
        for status in statuses {
            for length in [0, 1, 2500, 8688] {
                for persistFailed in [false, true] {
                    let outcome = Result { try StatefulSigningKey.producedLength(
                        status: status, length: length, persistFailed: persistFailed) }
                    let expected: Result<Int, OQSError>
                    if persistFailed {
                        expected = .failure(.persistenceFailed)
                    } else if status != OQS_SUCCESS {
                        expected = .failure(.signFailed)
                    } else if length == 0 {
                        expected = .failure(.keyExhausted)
                    } else {
                        expected = .success(length)
                    }
                    switch (outcome, expected) {
                    case let (.success(a), .success(b)): #expect(a == b)
                    case let (.failure(a), .failure(b)): #expect(a as? OQSError == b)
                    default: Issue.record("status \(status) length \(length) persistFailed \(persistFailed)")
                    }
                }
            }
        }
    }

    @Test("Fuzz with a seed: signs with random persist outcomes only return verifying signatures, and flipped signatures never verify")
    func fuzzPersistOutcomes() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SeededGenerator(seed: seed)
        let key = try LMS.PrivateKey(.sha256_h5_w8)
        var attempts: UInt64 = 0
        for round in 0..<12 {
            let message = Data((0..<Int.random(in: 1...64, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) })
            let persistFails = Bool.random(using: &rng)
            var returned: Data?
            var thrown: OQSError?
            do {
                returned = try key.signature(for: message) { _ in
                    if persistFails { throw PersistFailure() }
                }
            } catch { thrown = error as? OQSError }
            attempts += 1
            // The index advances on every attempt, persisted or not.
            #expect(try key.remainingSignatures == 31 - attempts, "seed \(seed) round \(round)")
            #expect(try key.totalSignatures == 31, "seed \(seed) round \(round)")
            if persistFails {
                // No false positive: a failed save never yields a signature.
                #expect(returned == nil && thrown == .persistenceFailed, "seed \(seed) round \(round)")
            } else {
                // No false negative: a saved sign always yields a verifying signature.
                let sig = try #require(returned, "seed \(seed) round \(round)")
                #expect(try key.publicKey.isValidSignature(sig, for: message), "seed \(seed) round \(round)")
                var bad = sig
                let at = Int.random(in: 0..<bad.count, using: &rng)
                bad[at] ^= UInt8.random(in: 1...255, using: &rng)
                #expect(try !key.publicKey.isValidSignature(bad, for: message), "seed \(seed) round \(round)")
                var other = message
                other.append(0)
                #expect(try !key.publicKey.isValidSignature(sig, for: other), "seed \(seed) round \(round)")
            }
        }
    }

    @Test("Fuzz with a seed: producedLength throws exactly the mapped error and returns the length otherwise")
    func fuzzProducedLength() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SeededGenerator(seed: seed)
        for _ in 0..<2000 {
            let status: OQS_STATUS = [OQS_SUCCESS, OQS_ERROR, OQS_EXTERNAL_LIB_ERROR_OPENSSL].randomElement(using: &rng)!
            let length = Bool.random(using: &rng) ? 0 : Int.random(in: 1...10_000, using: &rng)
            let persistFailed = Bool.random(using: &rng)
            let wantsLength = !persistFailed && status == OQS_SUCCESS && length > 0
            do {
                let got = try StatefulSigningKey.producedLength(status: status, length: length, persistFailed: persistFailed)
                #expect(wantsLength && got == length, "seed \(seed): accepted \(status) \(length) \(persistFailed)")
            } catch {
                #expect(!wantsLength, "seed \(seed): rejected a good sign \(length)")
                let want: OQSError = persistFailed ? .persistenceFailed : status != OQS_SUCCESS ? .signFailed : .keyExhausted
                #expect(error as? OQSError == want, "seed \(seed)")
            }
        }
    }
}
