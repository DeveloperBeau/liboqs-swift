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
        for name in Registry.enabledSignatureNames {
            if name.hasPrefix("SLH_DSA_") && name.contains("_PREHASH_") {
                prehashNames += 1
                continue
            }
            #expect(tableNames.contains(name), "no table entry for \(name)")
        }
        #expect(prehashNames == 144)
        #expect(Registry.enabledSignatureNames.contains(try #require(prehashEntries.first).name))
        #expect(Registry.enabledSignatureNames.count - prehashNames + 1 == cases.count)

        let sources = Self.signatureSourceFiles()
        #expect(sources.count == cases.count, "table has \(cases.count) entries, sources have \(sources.count) files")
        for file in sources {
            let lines = (try String(contentsOfFile: file, encoding: .utf8)).split(whereSeparator: \.isNewline)
            let signs = lines.filter { $0.contains("public func signature(for data: Data, context: Data)") }
            let verifies = lines.filter { $0.contains("public func isValidSignature(_ signature: Data, for data: Data, context: Data)") }
            #expect(signs.count == 1 && verifies.count == 1, "\(file) needs one context sign and one context verify")
        }
    }

    // Stateless signature type files, found from this file's path.
    private static func signatureSourceFiles() -> [String] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/OQS/Signatures")
        guard let walker = FileManager.default.enumerator(atPath: root.path) else { return [] }
        var files: [String] = []
        for case let relative as String in walker where relative.hasSuffix(".swift") {
            if relative.split(separator: "/").contains("StatefulHash") { continue }
            files.append(root.appendingPathComponent(relative).path)
        }
        return files
    }
}
