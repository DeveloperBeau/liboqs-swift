import Testing
import Foundation
@testable import OQS

/// Every stateless signature type forwards the context through its own typed
/// methods. A typed method that drops the context signs or verifies as if it
/// were empty, so each case checks the context in both directions. The table
/// is ContextForwardTable. Whether a type takes a context is read from the
/// registry, never written by hand.
@Suite struct ContextForwardTests {
    private static let message = Data("the quick brown fox".utf8)
    private static let context = Data("ctx".utf8)
    private static let otherContext = Data("other".utf8)

    /// What one type did. The calls run on a large stack because some algorithms
    /// need more than a test worker thread has.
    private struct Outcome: Sendable {
        var sameContextValid = false
        var otherContextValid = false
        var emptyContextValid = false
        var refusedNonEmptyContext = false
        var plainWithEmptyContextValid = false
        var plainWithContextValid = false
    }

    @Test("Typed context forwards sign and verify with the context, or refuse it", arguments: ContextForwardTable.cases)
    func contextForwardsOfEveryType(_ entry: ContextForwardCase) throws {
        let description = try #require(Registry.signatureDescription(named: entry.name), "\(entry.name) has no description")
        let supportsContext = description.supportsContext
        let outcome = try onLargeStack { () -> Outcome in
            var outcome = Outcome()
            let signer = try entry.makeSigner()
            if supportsContext {
                let signature = try signer.signWithContext(Self.message, Self.context)
                outcome.sameContextValid = try signer.verifyWithContext(signature, Self.message, Self.context)
                outcome.otherContextValid = try signer.verifyWithContext(signature, Self.message, Self.otherContext)
                outcome.emptyContextValid = try signer.verifyWithContext(signature, Self.message, Data())
            } else {
                do {
                    _ = try signer.signWithContext(Self.message, Self.context)
                } catch OQSError.contextNotSupported {
                    outcome.refusedNonEmptyContext = true
                }
                let plain = try signer.sign(Self.message)
                outcome.plainWithEmptyContextValid = try signer.verifyWithContext(plain, Self.message, Data())
                outcome.plainWithContextValid = try signer.verifyWithContext(plain, Self.message, Self.context)
            }
            return outcome
        }
        if supportsContext {
            #expect(outcome.sameContextValid, "same context")
            #expect(!outcome.otherContextValid, "different context")
            #expect(!outcome.emptyContextValid, "empty context")
        } else {
            #expect(outcome.refusedNonEmptyContext, "non-empty context must throw contextNotSupported")
            #expect(outcome.plainWithEmptyContextValid, "plain signature, empty context")
            #expect(!outcome.plainWithContextValid, "plain signature, non-empty context")
        }
    }

    @Test("The context forward table has one entry per stateless signature type and per registry name")
    func tableIsComplete() throws {
        let cases = ContextForwardTable.cases
        #expect(cases.count == 78)
        let names = cases.map(\.name)
        #expect(Set(names).count == names.count, "duplicate table entry")

        let prehashEntries = cases.filter(\.isPrehash)
        #expect(prehashEntries.count == 1)
        let tableNames = Set(names)
        var prehashNames = 0
        var plainNames: Set<String> = []
        for name in Registry.enabledSignatureNames {
            if Self.isPrehashName(name) {
                prehashNames += 1
                continue
            }
            plainNames.insert(name)
            #expect(tableNames.contains(name), "no table entry for \(name)")
        }
        #expect(prehashNames == 144)
        let prehashName = try #require(prehashEntries.first).name
        #expect(Self.isPrehashName(prehashName) && Registry.enabledSignatureNames.contains(prehashName))
        #expect(Registry.enabledSignatureNames.count - prehashNames + 1 == cases.count)
        // No table name that is not an enabled name.
        #expect(tableNames == plainNames.union([prehashName]), "table and registry names differ")

        // The parity registry maps every liboqs name to a typed closure and is proven complete,
        // so the table must name the same types.
        var parityPlain: Set<String> = []
        var parityPrehash = 0
        for algorithm in ParityRegistry.sigs() {
            if Self.isPrehashName(algorithm.name) { parityPrehash += 1 } else { parityPlain.insert(algorithm.name) }
        }
        #expect(parityPrehash == 144)
        #expect(parityPlain == plainNames, "parity registry and registry names differ")
        #expect(parityPlain.union([prehashName]) == tableNames, "table and parity registry names differ")
    }

    @Test("Every table entry's closures belong to its own type, by the key lengths of the generated keys",
          arguments: ContextForwardTable.cases)
    func tableEntryMatchesItsType(_ entry: ContextForwardCase) throws {
        let description = try #require(Registry.signatureDescription(named: entry.name), "\(entry.name) has no description")
        let signer = try onLargeStack { try entry.makeSigner() }
        #expect(signer.publicKeyLength == description.publicKeyLength, "public key length of \(entry.name)")
        #expect(signer.secretKeyLength == description.secretKeyLength, "secret key length of \(entry.name)")
    }

    // The names of the SLH-DSA pre-hash combinations, which share one table entry.
    private static func isPrehashName(_ name: String) -> Bool {
        name.hasPrefix("SLH_DSA_") && name.contains("_PREHASH_")
    }
}
