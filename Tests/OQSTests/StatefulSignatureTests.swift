import Testing
import Foundation
@testable import OQS

/// A test-only error so the negative test can assert the *user's* error
/// propagates (not a generic OQSError).
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
    /// (a) when the persist closure throws, `signature(for:persistingTo:)` rethrows
    ///     the *user's* error (`PersistFailure`), not a generic OQSError;
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

        // (a)+(b): throwing persist must rethrow the user's error; no sig returned.
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
        #expect(thrown is PersistFailure, "must rethrow the user's error, got \(String(describing: thrown))")

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
        #expect(thrown is PersistFailure, "must rethrow the user's error")

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
}
