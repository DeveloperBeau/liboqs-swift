import Testing
@testable import OQS

/// Unit tests of the one helper that matches names the way liboqs does.
@Suite struct AlgorithmNameMatchingTests {
    @Test("Names that differ only in the case of ASCII letters match")
    func asciiLetterCaseIsIgnored() {
        #expect(AlgorithmNameMatching.namesMatch("ml-kem-768", "ML-KEM-768"))
        #expect(AlgorithmNameMatching.namesMatch("ML-KEM-768", "ml-kem-768"))
        #expect(AlgorithmNameMatching.namesMatch("mL-kEm-768", "ML-KEM-768"))
        #expect(AlgorithmNameMatching.namesMatch("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
        #expect(AlgorithmNameMatching.namesMatch("", ""))
    }

    @Test("Names of different lengths never match, so a prefix or an extension fails")
    func lengthsMustBeEqual() {
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-76", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-7680", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-768", ""))
    }

    @Test("A NUL byte is compared like any other byte, so it never ends the name early")
    func nulByteIsNotAnEnd() {
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-768\0", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-768\0X", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-76\0", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("\0", ""))
    }

    @Test("Bytes that are not letters are not folded, even when they are 0x20 apart")
    func onlyLettersFold() {
        // '-' is 0x2D and '\r' is 0x0D. '7' is 0x37 and 0x17 is a control byte.
        #expect(!AlgorithmNameMatching.namesMatch("ML\rKEM-768", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-KEM-\u{17}68", "ML-KEM-768"))
        // '@' (0x40) and '`' (0x60), '[' (0x5B) and '{' (0x7B) sit next to the letters.
        #expect(!AlgorithmNameMatching.namesMatch("@", "`"))
        #expect(!AlgorithmNameMatching.namesMatch("[", "{"))
        #expect(!AlgorithmNameMatching.namesMatch("_", "\u{7F}"))
    }

    @Test("A non-ASCII character never matches an ASCII letter, even when Unicode case mapping would make them equal")
    func nonASCIINeverFolds() {
        // KELVIN SIGN lowercases to "k". LATIN SMALL LETTER DOTLESS I uppercases
        // to "I". LATIN SMALL LETTER LONG S uppercases to "S".
        #expect(!AlgorithmNameMatching.namesMatch("ML-\u{212A}EM-768", "ML-KEM-768"))
        #expect(!AlgorithmNameMatching.namesMatch("OV-\u{131}s", "OV-Is"))
        #expect(!AlgorithmNameMatching.namesMatch("ML-D\u{17F}A-65", "ML-DSA-65"))
        // FULLWIDTH LATIN CAPITAL LETTER M.
        #expect(!AlgorithmNameMatching.namesMatch("\u{FF2D}L-KEM-768", "ML-KEM-768"))
    }

    @Test("Composed and decomposed forms are different bytes, so they do not match")
    func comparesBytesNotCharacters() {
        // Swift's == treats these as equal. liboqs compares bytes, and so does the helper.
        #expect("\u{E9}" == "e\u{301}")
        #expect(!AlgorithmNameMatching.namesMatch("\u{E9}", "e\u{301}"))
    }

    @Test("The listed name comes back in its listed spelling, and nil comes back when nothing matches")
    func listedNameReturnsTheListedSpelling() {
        let listed = ["BIKE-L1", "ML-KEM-768", "cross-rsdp-128-balanced"]
        #expect(AlgorithmNameMatching.listedName(matching: "ml-kem-768", in: listed) == "ML-KEM-768")
        #expect(AlgorithmNameMatching.listedName(matching: "CROSS-RSDP-128-BALANCED", in: listed) == "cross-rsdp-128-balanced")
        #expect(AlgorithmNameMatching.listedName(matching: "bike-l1", in: listed) == "BIKE-L1")
        #expect(AlgorithmNameMatching.listedName(matching: "ML-KEM-512", in: listed) == nil)
        #expect(AlgorithmNameMatching.listedName(matching: "", in: listed) == nil)
        #expect(AlgorithmNameMatching.listedName(matching: "ML-KEM-768", in: []) == nil)
    }
}
