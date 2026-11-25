import Foundation

/// Pure helpers for the parity snapshot format shared with the Rust and Zig
/// ports: one `NAME digest\n` line per algorithm, lines sorted by name in byte
/// order, digest = SHA-256 over the field bytes sorted by field name.
enum SnapshotFormat {
    private static func byteLess(_ a: String, _ b: String) -> Bool {
        a.utf8.lexicographicallyPrecedes(b.utf8)
    }

    /// SHA-256 hex digest of the concatenated field bytes in field-name byte order.
    static func digest(_ fields: [(String, Data)]) -> String {
        var blob = Data()
        for (_, bytes) in fields.sorted(by: { byteLess($0.0, $1.0) }) { blob.append(bytes) }
        return KAT.sha256Hex(blob)
    }

    /// Snapshot file text: lines sorted by name in byte order, newline after every line.
    static func text(_ digests: [(String, String)]) -> String {
        digests.sorted(by: { byteLess($0.0, $1.0) }).map { "\($0.0) \($0.1)\n" }.joined()
    }

    /// Converts CRLF and lone CR line endings to LF. Swift treats "\r\n" as one
    /// Character, so CRLF checkouts (Windows) must be normalized before splitting.
    static func normalizeNewlines(_ text: String) -> String {
        text.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
    }

    /// Parses snapshot text into name-to-digest pairs (blank lines ignored).
    static func parse(_ text: String) -> [String: String] {
        var table: [String: String] = [:]
        for line in normalizeNewlines(text).split(separator: "\n") {
            let parts = line.split(separator: " ")
            if parts.count == 2 { table[String(parts[0])] = String(parts[1]) }
        }
        return table
    }

    /// Human-readable differences: names missing from `actual`, extra in `actual`, or with a changed digest.
    static func differences(expected: String, actual: String) -> [String] {
        let e = parse(expected), a = parse(actual)
        var out: [String] = []
        for name in e.keys.sorted(by: byteLess) {
            if a[name] == nil { out.append("missing: \(name)") }
            else if a[name] != e[name] { out.append("changed digest: \(name)") }
        }
        for name in a.keys.sorted(by: byteLess) where e[name] == nil { out.append("extra: \(name)") }
        return out
    }
}
