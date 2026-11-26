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
    ]

    private static func source(_ file: String) throws -> String {
        try String(contentsOf: moduleRoot.appendingPathComponent(file), encoding: .utf8)
    }

    @Test("Every entity file imports only the modules it is allowed, and the description types import nothing",
          arguments: entities.map(\.file))
    func entityImportsStayInward(file: String) throws {
        let allowed = try #require(Self.entities.first { $0.file == file }).allowed
        let imported = SwiftImportScanner.importedModules(in: try Self.source(file))
        let outward = imported.filter { !allowed.contains($0) }
        #expect(outward.isEmpty, "\(file) imports \(outward), which is outside the entities ring")
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
        // The three description types and the three older shared types.
        #expect(found.count == 6, "found \(found.sorted())")
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
