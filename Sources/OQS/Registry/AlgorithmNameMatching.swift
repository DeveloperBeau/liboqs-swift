/// Matches a caller's algorithm name against liboqs names the way liboqs does.
///
/// liboqs 0.16.0 compares names with `strcasecmp` (`_stricmp` on Windows).
/// That ignores case for the ASCII letters A to Z only. Every other byte must
/// be equal, and the lengths must be equal. The bytes compared here are the
/// UTF-8 bytes of the Swift strings, so a non-ASCII character never folds.
///
/// A Swift string can hold a NUL byte. C would stop reading at that byte and
/// see a shorter name. Here every byte is compared, and no liboqs name holds a
/// NUL byte, so a name with one never matches.
enum AlgorithmNameMatching {
    /// The listed name that `name` matches, or nil.
    ///
    /// The listed name is returned, not `name`, so liboqs is always given its own spelling.
    static func listedName(matching name: String, in listed: [String]) -> String? {
        listed.first { namesMatch(name, $0) }
    }

    /// Whether `name` equals `listed` when the case of the ASCII letters A to Z is ignored.
    static func namesMatch(_ name: String, _ listed: String) -> Bool {
        let a = name.utf8
        let b = listed.utf8
        guard a.count == b.count else { return false }
        for (x, y) in zip(a, b) where folded(x) != folded(y) {
            return false
        }
        return true
    }

    // Maps A to Z onto a to z and leaves every other byte as it is.
    private static func folded(_ byte: UInt8) -> UInt8 {
        byte >= 0x41 && byte <= 0x5A ? byte | 0x20 : byte
    }
}
