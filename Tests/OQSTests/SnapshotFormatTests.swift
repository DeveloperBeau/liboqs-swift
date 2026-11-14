import Testing
import Foundation

/// Always-on checks of the parity snapshot format, with hand-written expected
/// values (never computed by the code under test).
struct SnapshotFormatTests {
    @Test("SHA-256 helper matches the FIPS 180 test vectors")
    func sha256Vectors() {
        #expect(KAT.sha256Hex(Data("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(KAT.sha256Hex(Data()) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("Digest concatenates fields in field-name order")
    func fieldSortedDigest() {
        let d = SnapshotFormat.digest([("sk", Data("b".utf8)), ("pk", Data("a".utf8))])
        #expect(d == "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603")
    }

    @Test("Snapshot text sorts names in byte order and ends with a newline")
    func textByteOrder() {
        let text = SnapshotFormat.text([("cross", "03"), ("ML-KEM-512", "02"), ("Kyber", "01")])
        #expect(text == "Kyber 01\nML-KEM-512 02\ncross 03\n")
    }

    @Test("Frozen snapshot file is well formed")
    func frozenFile() throws {
        let url = try #require(Bundle.module.url(forResource: "parity_snapshot", withExtension: "txt", subdirectory: "Vectors"))
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(text.hasSuffix("\n"))
        let lines = text.dropLast().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.count == 262)
        var names: [String] = []
        for line in lines {
            let parts = line.split(separator: " ", omittingEmptySubsequences: false)
            #expect(parts.count == 2, "bad line: \(line)")
            guard parts.count == 2 else { continue }
            names.append(String(parts[0]))
            #expect(parts[1].count == 64 && parts[1].allSatisfy { "0123456789abcdef".contains($0) }, "bad digest: \(line)")
        }
        for (a, b) in zip(names, names.dropFirst()) {
            #expect(a.utf8.lexicographicallyPrecedes(b.utf8), "not sorted or duplicate: \(a), \(b)")
        }
    }
}
