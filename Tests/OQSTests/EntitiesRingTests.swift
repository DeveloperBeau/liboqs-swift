import Testing
import Foundation

// The sources are read from the checkout through #filePath. The Android
// runner copies only the test binary and Vectors/ onto the device, so the
// sources are not there. The check is a property of the source files, and it
// runs on every other platform.
#if !os(Android)

/// Ring check for the entities: the description types are plain data and
/// import nothing, and the other files in SharedTypes import only Foundation.
/// The repo-wide check of every ring is not here yet.
@Suite struct EntitiesRingTests {
    // Sources/OQS, found from this file at Tests/OQSTests.
    private static let moduleRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/OQS")

    // The plain data files, by path under Sources/OQS, and the modules each may import.
    static let entities: [(file: String, allowed: Set<String>)] = [
        ("SharedTypes/KEMDescription.swift", []),
        ("SharedTypes/SignatureDescription.swift", []),
        ("SharedTypes/StatefulSignatureDescription.swift", []),
        ("SharedTypes/OQSError.swift", []),
        ("SharedTypes/SharedSecret.swift", ["Foundation"]),
        ("SharedTypes/SharedSecretResult.swift", ["Foundation"]),
        ("SharedTypes/SecretBytes.swift", ["Foundation"]),
        ("SharedTypes/SecretMemoryManaging.swift", ["Foundation"]),
    ]

    private static func source(_ file: String) throws -> String {
        try String(contentsOf: moduleRoot.appendingPathComponent(file), encoding: .utf8)
    }

    /// The imports of `source` that `file` is not allowed. The LF and CRLF tests share this.
    private static func outwardImports(of file: String, in source: String) throws -> [String] {
        let allowed = try #require(entities.first { $0.file == file }).allowed
        return SwiftImportScanner.importedModules(in: source).filter { !allowed.contains($0) }
    }

    private static func crlf(_ source: String) -> String {
        source.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
    }

    @Test("Every entity file imports only the modules it is allowed, and the description types import nothing",
          arguments: entities.map(\.file))
    func entityImportsStayInward(file: String) throws {
        let outward = try Self.outwardImports(of: file, in: try Self.source(file))
        #expect(outward.isEmpty, "\(file) imports \(outward), which is outside the entities ring")
    }

    @Test("The same check passes on a CRLF copy of every entity file, as on a Windows checkout",
          arguments: entities.map(\.file))
    func entityImportsStayInwardWithCRLF(file: String) throws {
        let source = Self.crlf(try Self.source(file))
        #expect(source.contains("\r\n"))
        let outward = try Self.outwardImports(of: file, in: source)
        #expect(outward.isEmpty, "\(file) with CRLF imports \(outward), which is outside the entities ring")
    }

    @Test("The check still flags an outward import added to a CRLF copy of every entity file",
          arguments: entities.map(\.file))
    func crlfCheckFlagsAnOutwardImport(file: String) throws {
        let source = "import Cliboqs\r\n" + Self.crlf(try Self.source(file))
        let outward = try Self.outwardImports(of: file, in: source)
        #expect(outward == ["Cliboqs"], "\(file) with CRLF gave \(outward)")
    }

    @Test("Every Swift file in SharedTypes and every Description type file in the module is on the entity list")
    func everyEntityFileIsChecked() throws {
        let listed = Set(Self.entities.map(\.file))
        let enumerator = try #require(FileManager.default.enumerator(atPath: Self.moduleRoot.path))
        var found: [String] = []
        while let path = enumerator.nextObject() as? String {
            guard path.hasSuffix(".swift") else { continue }
            let normalized = path.replacingOccurrences(of: "\\", with: "/")
            if normalized.hasPrefix("SharedTypes/") || normalized.hasSuffix("Description.swift") {
                found.append(normalized)
            }
        }
        for file in found {
            #expect(listed.contains(file), "\(file) is not on the entity list")
        }
        // The three description types, the three older shared types and the two secret storage files.
        #expect(found.count == 8, "found \(found.sorted())")
    }

    @Test("The import scan finds imports in every form and ignores comments and lines that are not imports")
    func scannerFindsImports() {
        #expect(SwiftImportScanner.importedModules(in: "import Foundation\ninternal import Cliboqs\n") == ["Foundation", "Cliboqs"])
        #expect(SwiftImportScanner.importedModules(in: "@_implementationOnly import Cliboqs") == ["Cliboqs"])
        #expect(SwiftImportScanner.importedModules(in: "@testable @preconcurrency public import OQS") == ["OQS"])
        #expect(SwiftImportScanner.importedModules(in: "import struct Cliboqs.OQS_KEM") == ["Cliboqs"])
        #expect(SwiftImportScanner.importedModules(in: "    import\tDispatch  // why") == ["Dispatch"])
        #expect(SwiftImportScanner.importedModules(in: "import Foundation; import Cliboqs") == ["Foundation", "Cliboqs"])
        #expect(SwiftImportScanner.importedModules(in: "/// import Cliboqs\n// import Cliboqs") == [])
        #expect(SwiftImportScanner.importedModules(in: "let importance = 1\nfunc imports() {}\n#if canImport(Cliboqs)") == [])
        #expect(SwiftImportScanner.importedModules(in: "public struct X {}") == [])
    }

    @Test("The import scan reads CRLF and lone CR line ends like LF, with no line end left in a name")
    func scannerReadsEveryNewline() {
        let sources = [
            "import Foundation\r\n": ["Foundation"],
            "import Foundation\r\nimport Cliboqs\r\n": ["Foundation", "Cliboqs"],
            "import Foundation\rimport Cliboqs\r": ["Foundation", "Cliboqs"],
            "import Foundation\r\n\r\n// import Dispatch\r\n": ["Foundation"],
        ]
        for (source, expected) in sources {
            let modules = SwiftImportScanner.importedModules(in: source)
            #expect(modules == expected, "\(source.debugDescription) gave \(modules)")
            #expect(modules.allSatisfy { !$0.contains("\r") && !$0.contains("\n") })
        }
    }

    @Test("The import check flags a description file that imports Cliboqs")
    func checkFlagsAnOutwardImport() {
        let source = """
            internal import Cliboqs

            /// What liboqs reports.
            public struct KEMDescription {}
            """
        let outward = SwiftImportScanner.importedModules(in: source).filter { !Set<String>().contains($0) }
        #expect(outward == ["Cliboqs"])
    }
}

#endif
