import Testing
import Foundation

// The sources are read from the checkout through #filePath. The Android
// runner copies only the test binary and Vectors/ onto the device, so the
// sources are not there. The check is a property of the source files, and it
// runs on every other platform. The table check that needs no sources is
// ContextForwardTests.tableIsComplete.
#if !os(Android)

/// Every stateless signature type file has one context sign and one context
/// verify method. Paths are handled as URLs and path components only, because
/// a Windows path uses a backslash and not a slash.
@Suite struct ContextForwardSourceTests {
    // Sources/OQS/Signatures, found from this file at Tests/OQSTests.
    private static let signaturesRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/OQS/Signatures")

    /// The path components of `file` below `root`. If the enumerator spelled the root
    /// differently, the components after the last `Signatures` are used.
    static func relativeComponents(of file: [String], root: [String]) -> [String] {
        if file.starts(with: root) { return Array(file.dropFirst(root.count)) }
        if let marker = file.lastIndex(of: "Signatures") { return Array(file[(marker + 1)...]) }
        return file
    }

    /// Whether a file under the signatures directory belongs to a stateful hash-based type.
    static func isStatefulHash(relativeComponents: [String]) -> Bool {
        relativeComponents.dropLast().contains("StatefulHash")
    }

    static func statelessSourceFiles(under root: URL) throws -> [URL] {
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory)
        try #require(exists && isDirectory.boolValue, "the signature sources are not at \(root.lastPathComponent), the check needs the checkout")
        let walker = try #require(
            FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]))
        let rootComponents = root.pathComponents
        var files: [URL] = []
        for case let url as URL in walker where url.pathExtension == "swift" {
            let relative = relativeComponents(of: url.pathComponents, root: rootComponents)
            if isStatefulHash(relativeComponents: relative) { continue }
            files.append(url)
        }
        return files
    }

    @Test("Every stateless signature type file has one context sign and one context verify method, one file per table entry")
    func everySignatureFileHasTheContextMethods() throws {
        let sources = try Self.statelessSourceFiles(under: Self.signaturesRoot)
        let table = ContextForwardTable.cases
        #expect(sources.count == table.count, "table has \(table.count) entries, sources have \(sources.count) files")
        for file in sources {
            let lines = (try String(contentsOf: file, encoding: .utf8)).split(whereSeparator: \.isNewline)
            let signs = lines.filter { $0.contains("public func signature(for data: Data, context: Data)") }
            let verifies = lines.filter { $0.contains("public func isValidSignature(_ signature: Data, for data: Data, context: Data)") }
            #expect(signs.count == 1 && verifies.count == 1, "\(file.lastPathComponent) needs one context sign and one context verify")
        }
    }

    @Test("The stateful hash files are told apart by path components, whatever the separator of the platform")
    func statefulHashIsDecidedByComponents() {
        let root = ["/", "checkout", "Sources", "OQS", "Signatures"]
        func relative(_ components: [String]) -> [String] {
            Self.relativeComponents(of: root + components, root: root)
        }
        #expect(Self.isStatefulHash(relativeComponents: relative(["StatefulHash", "LMS.swift"])))
        #expect(Self.isStatefulHash(relativeComponents: relative(["StatefulHash", "Support", "STFLSupport.swift"])))
        #expect(!Self.isStatefulHash(relativeComponents: relative(["MAYO", "MAYO3.swift"])))
        #expect(!Self.isStatefulHash(relativeComponents: relative(["StatefulHash.swift"])))
        // A root that is spelled differently by the enumerator.
        let other = ["/", "private", "checkout", "Sources", "OQS", "Signatures", "StatefulHash", "XMSS.swift"]
        #expect(Self.isStatefulHash(relativeComponents: Self.relativeComponents(of: other, root: root)))
        // The same file as a URL, as the enumerator hands it out.
        let url = URL(fileURLWithPath: "/checkout/Sources/OQS/Signatures").appendingPathComponent("StatefulHash").appendingPathComponent("LMS.swift")
        #expect(Self.isStatefulHash(relativeComponents: Self.relativeComponents(of: url.pathComponents, root: Array(root))))
    }

    @Test("The file list has the stateless count and no stateful hash file")
    func fileListExcludesStatefulHash() throws {
        let files = try Self.statelessSourceFiles(under: Self.signaturesRoot)
        #expect(files.count == 78)
        #expect(!files.contains { $0.pathComponents.contains("StatefulHash") })
        #expect(!files.contains { ["LMS.swift", "XMSS.swift", "XMSSMT.swift", "STFLSupport.swift"].contains($0.lastPathComponent) })
    }
}

#endif
