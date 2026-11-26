import Foundation

/// Finds the modules a Swift source file imports.
///
/// It splits the source on any newline (`\n`, `\r\n` or a lone `\r`), so a
/// CRLF checkout reads the same as an LF one. It reads each line, drops a `//`
/// comment, and looks for an `import` keyword after any attributes (`@testable`, `@_implementationOnly`,
/// `@preconcurrency`) and access level (`public`, `internal` and the others).
/// An import of one declaration (`import struct M.T`) counts as an import of
/// its module `M`. Several statements on one line, split by semicolons, are each
/// read. Block comments are not parsed, so an import inside one is reported,
/// which errs on the side of a failing check.
enum SwiftImportScanner {
    private static let accessLevels: Set<String> = ["public", "package", "internal", "fileprivate", "private", "open"]
    private static let declarationKinds: Set<String> = ["struct", "class", "enum", "protocol", "typealias", "func", "var", "let", "actor"]

    /// The imported module names of `source`, in the order they appear.
    static func importedModules(in source: String) -> [String] {
        var modules: [String] = []
        for rawLine in source.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var line = Substring(rawLine)
            if let comment = line.range(of: "//") { line = line[..<comment.lowerBound] }
            for statement in line.split(separator: ";") {
                if let module = module(inStatement: statement) { modules.append(module) }
            }
        }
        return modules
    }

    private static func module(inStatement statement: Substring) -> String? {
        var tokens = statement.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" })[...]
        while let first = tokens.first, first.hasPrefix("@") || accessLevels.contains(String(first)) {
            tokens = tokens.dropFirst()
        }
        guard tokens.first == "import" else { return nil }
        tokens = tokens.dropFirst()
        if let kind = tokens.first, declarationKinds.contains(String(kind)) { tokens = tokens.dropFirst() }
        guard let path = tokens.first else { return nil }
        return String(path.split(separator: ".").first ?? path).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
