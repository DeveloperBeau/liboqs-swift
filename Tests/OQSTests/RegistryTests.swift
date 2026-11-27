import Testing
@testable import OQS

/// Behaviour of ``Registry``: the enabled name lists, the enabled checks and
/// the description lookup. Every expected value is written out by hand from
/// the liboqs 0.16.0 headers and algorithm sources, not read back from the
/// registry. No test here generates a key.
@Suite struct RegistryTests {

    // MARK: - Lists

    @Test("This build enables 41 KEMs, 221 signatures and 70 stateful signatures, 262 stateless in all")
    func enabledCounts() {
        // OQS_KEM_algs_length is 41, OQS_SIG_algs_length is 65 + 156 and
        // OQS_SIG_STFL_algs_length is 70 in the 0.16.0 headers.
        #expect(Registry.enabledKEMNames.count == 41)
        #expect(Registry.enabledSignatureNames.count == 221)
        #expect(Registry.enabledStatefulSignatureNames.count == 70)
        #expect(Registry.enabledKEMNames.count + Registry.enabledSignatureNames.count == 262)
    }

    @Test("Each name list is in liboqs order, from the first to the last identifier of its C array")
    func listsAreInLiboqsOrder() {
        // The first, second and last entries of the identifier arrays in
        // src/kem/kem.c, src/sig/sig.c and src/sig_stfl/sig_stfl.c.
        let kems = Registry.enabledKEMNames
        #expect(Array(kems.prefix(2)) == ["BIKE-L1", "BIKE-L3"])
        #expect(kems.last == "eFrodoKEM-1344-SHAKE")
        let sigs = Registry.enabledSignatureNames
        #expect(Array(sigs.prefix(2)) == ["ML-DSA-44", "ML-DSA-65"])
        #expect(sigs.last == "SLH_DSA_SHAKE_256_PREHASH_SHAKE_256F")
        let stateful = Registry.enabledStatefulSignatureNames
        #expect(Array(stateful.prefix(2)) == ["XMSS-SHA2_10_256", "XMSS-SHA2_16_256"])
        #expect(stateful.last == "LMS_SHA256_H20_W8_H20_W8")
    }

    @Test("Every name is listed once, and no name is in two kinds, ignoring ASCII case")
    func namesAreUnique() {
        let all = Registry.enabledKEMNames + Registry.enabledSignatureNames + Registry.enabledStatefulSignatureNames
        #expect(all.count == 332)
        // Lowercased ASCII names, so a clash that only differs in case is found too.
        #expect(Set(all.map { $0.lowercased() }).count == 332)
    }

    @Test("The list builder keeps only the names liboqs reports as enabled, in order, and stops at the count")
    func listBuilderSkipsDisabledNames() {
        // Stand-ins for the liboqs list functions. Every liboqs identifier is
        // enabled in this build, so only a stand-in can show that a disabled
        // name is left out.
        let identifiers = ["First-1", "Off-2", "Middle-3", "Off-4", "Last-5", "Past-6"]
        let names = Registry.enabledNames(
            count: 5,
            identifierAt: { identifiers[$0] },
            isEnabled: { !$0.hasPrefix("Off-") })
        #expect(names == ["First-1", "Middle-3", "Last-5"])
    }

    @Test("The list builder gives nothing for an empty list and skips a missing identifier")
    func listBuilderEdgeCases() {
        #expect(Registry.enabledNames(count: 0, identifierAt: { _ in "A" }, isEnabled: { _ in true }).isEmpty)
        let names = Registry.enabledNames(
            count: 3,
            identifierAt: { $0 == 1 ? nil : "N-\($0)" },
            isEnabled: { _ in true })
        #expect(names == ["N-0", "N-2"])
    }

    // MARK: - Descriptions, hand-written from the liboqs sources

    @Test("ML-KEM-768 description matches the liboqs 0.16.0 values")
    func mlkem768Description() throws {
        let d = try #require(Registry.kemDescription(named: "ML-KEM-768"))
        // kem_ml_kem.h and kem_ml_kem_768.c.
        #expect(d.name == "ML-KEM-768")
        #expect(d.algorithmVersion == "FIPS203")
        #expect(d.claimedNISTLevel == 3)
        #expect(d.isINDCCASecure)
        #expect(d.publicKeyLength == 1184)
        #expect(d.secretKeyLength == 2400)
        #expect(d.ciphertextLength == 1088)
        #expect(d.sharedSecretLength == 32)
        #expect(d.keyPairSeedLength == 64)
        #expect(d.encapsulationSeedLength == 32)
    }

    @Test("BIKE-L1 description reports IND-CPA only, level 1 and no seed lengths")
    func bikeL1Description() throws {
        let d = try #require(Registry.kemDescription(named: "BIKE-L1"))
        // kem_bike.h and kem_bike.c.
        #expect(d.name == "BIKE-L1")
        #expect(d.algorithmVersion == "Additional - 01/27/2023")
        #expect(d.claimedNISTLevel == 1)
        #expect(!d.isINDCCASecure)
        #expect(d.publicKeyLength == 1541)
        #expect(d.secretKeyLength == 5223)
        #expect(d.ciphertextLength == 1573)
        #expect(d.sharedSecretLength == 32)
        #expect(d.keyPairSeedLength == 0)
        #expect(d.encapsulationSeedLength == 0)
    }

    @Test("ML-DSA-65 description matches the liboqs 0.16.0 values and supports a context")
    func mldsa65Description() throws {
        let d = try #require(Registry.signatureDescription(named: "ML-DSA-65"))
        // sig_ml_dsa.h and sig_ml_dsa_65.c.
        #expect(d.name == "ML-DSA-65")
        #expect(d.algorithmVersion == "FIPS204")
        #expect(d.claimedNISTLevel == 3)
        #expect(d.isEUFCMASecure)
        #expect(d.isSUFCMASecure)
        #expect(d.supportsContext)
        #expect(d.publicKeyLength == 1952)
        #expect(d.secretKeyLength == 4032)
        #expect(d.signatureLength == 3309)
    }

    @Test("Falcon-512 description reports no context support and no SUF-CMA")
    func falcon512Description() throws {
        let d = try #require(Registry.signatureDescription(named: "Falcon-512"))
        // sig_falcon.h and sig_falcon_512.c.
        #expect(d.name == "Falcon-512")
        #expect(d.algorithmVersion == "20211101 with PQClean patches")
        #expect(d.claimedNISTLevel == 1)
        #expect(d.isEUFCMASecure)
        #expect(!d.isSUFCMASecure)
        #expect(!d.supportsContext)
        #expect(d.publicKeyLength == 897)
        #expect(d.secretKeyLength == 1281)
        #expect(d.signatureLength == 752)
    }

    @Test("LMS_SHA256_H5_W8 description matches the liboqs 0.16.0 values")
    func lmsH5W8Description() throws {
        let d = try #require(Registry.statefulSignatureDescription(named: "LMS_SHA256_H5_W8"))
        // OQS_LMS_ID_sha256_h5_w8 and the lengths in sig_stfl_lms.h, the rest in sig_stfl_lms.c.
        #expect(d.objectIdentifier == 0x0154)
        #expect(d.name == "LMS_SHA256_H5_W8")
        #expect(d.algorithmVersion == "https://datatracker.ietf.org/doc/html/rfc8554")
        #expect(d.isEUFCMASecure)
        #expect(!d.isSUFCMASecure)
        #expect(d.publicKeyLength == 60)
        #expect(d.secretKeyLength == 64)
        #expect(d.signatureLength == 1296)
    }

    @Test("XMSS-SHA2_10_256 description matches the liboqs 0.16.0 values")
    func xmssSHA2_10_256Description() throws {
        let d = try #require(Registry.statefulSignatureDescription(named: "XMSS-SHA2_10_256"))
        // sig_stfl_xmss.h: OID 0x01, public key 64 + 4, secret key 1373 + 4, signature 2500.
        #expect(d.objectIdentifier == 0x01)
        #expect(d.name == "XMSS-SHA2_10_256")
        #expect(d.algorithmVersion == "https://datatracker.ietf.org/doc/html/rfc8391")
        #expect(d.isEUFCMASecure)
        #expect(!d.isSUFCMASecure)
        #expect(d.publicKeyLength == 68)
        #expect(d.secretKeyLength == 1377)
        #expect(d.signatureLength == 2500)
    }

    @Test("A lookup miss gives nil for each kind")
    func lookupMiss() {
        #expect(Registry.kemDescription(named: "ML-KEM-769") == nil)
        #expect(Registry.signatureDescription(named: "ML-DSA-66") == nil)
        #expect(Registry.statefulSignatureDescription(named: "LMS_SHA256_H5_W9") == nil)
    }

    // MARK: - Enabled checks

    @Test("The enabled checks are true for an enabled name of their own kind")
    func enabledChecksTrue() {
        #expect(Registry.isKEMEnabled("ML-KEM-768"))
        #expect(Registry.isSignatureEnabled("ML-DSA-65"))
        #expect(Registry.isStatefulSignatureEnabled("LMS_SHA256_H5_W8"))
    }

    @Test("The enabled checks are false for another kind, an unknown name and an empty name")
    func enabledChecksFalse() {
        #expect(!Registry.isKEMEnabled("ML-DSA-65"))
        #expect(!Registry.isKEMEnabled("LMS_SHA256_H5_W8"))
        #expect(!Registry.isSignatureEnabled("ML-KEM-768"))
        #expect(!Registry.isSignatureEnabled("XMSS-SHA2_10_256"))
        #expect(!Registry.isStatefulSignatureEnabled("ML-DSA-65"))
        #expect(!Registry.isStatefulSignatureEnabled("ML-KEM-768"))
        #expect(!Registry.isKEMEnabled("ML-KEM-769"))
        #expect(!Registry.isSignatureEnabled(""))
        #expect(!Registry.isStatefulSignatureEnabled(""))
    }

    // MARK: - Case

    @Test("A lookup ignores ASCII case, and the description carries the liboqs name, not the spelling asked for")
    func lookupIgnoresASCIICase() throws {
        #expect(Registry.isKEMEnabled("ml-kem-768"))
        #expect(try #require(Registry.kemDescription(named: "ml-kem-768")).name == "ML-KEM-768")
        #expect(Registry.isSignatureEnabled("Ml-Dsa-65"))
        #expect(try #require(Registry.signatureDescription(named: "Ml-Dsa-65")).name == "ML-DSA-65")
        #expect(Registry.isStatefulSignatureEnabled("lms_Sha256_h5_W8"))
        #expect(try #require(Registry.statefulSignatureDescription(named: "lms_Sha256_h5_W8")).name == "LMS_SHA256_H5_W8")
        // A name that liboqs writes in lowercase, asked for in uppercase.
        #expect(Registry.isSignatureEnabled("CROSS-RSDP-128-BALANCED"))
        #expect(try #require(Registry.signatureDescription(named: "CROSS-RSDP-128-BALANCED")).name == "cross-rsdp-128-balanced")
    }

    @Test("A name in another case gives the same description as the liboqs name")
    func caseVariantsGiveEqualDescriptions() {
        #expect(Registry.kemDescription(named: "ml-kem-768") == Registry.kemDescription(named: "ML-KEM-768"))
        #expect(Registry.signatureDescription(named: "falcon-512") == Registry.signatureDescription(named: "Falcon-512"))
        #expect(Registry.statefulSignatureDescription(named: "xmss-sha2_10_256")
            == Registry.statefulSignatureDescription(named: "XMSS-SHA2_10_256"))
    }

    // MARK: - Misuse

    // Every family liboqs 0.16.0 defines is enabled in this build, and the
    // enabled counts equal the liboqs list lengths (41, 221 and 70). So no
    // name exists that liboqs knows and this build leaves out, and there is
    // no such case to test here. The list builder test shows the filter.
    static let misuses: [(kem: String, sig: String, stateful: String)] = [
        // Empty.
        ("", "", ""),
        // Trailing space.
        ("ML-KEM-768 ", "ML-DSA-65 ", "LMS_SHA256_H5_W8 "),
        // Leading space.
        (" ML-KEM-768", " ML-DSA-65", " LMS_SHA256_H5_W8"),
        // Lowercase with a trailing space. Case is ignored, the space is not.
        ("ml-kem-768 ", "ml-dsa-65 ", "lms_sha256_h5_w8 "),
        // A prefix of an enabled name.
        ("ML-KEM-76", "ML-DSA-6", "LMS_SHA256_H5_W"),
        // A mixed-case prefix of an enabled name.
        ("ml-KEM-76", "Ml-dSa-6", "lms_SHA256_h5_w"),
        // An enabled name with a NUL byte and more after it, which C would cut off.
        ("ML-KEM-768\0X", "ML-DSA-65\0ML-DSA-65", "LMS_SHA256_H5_W8\0x"),
        ("ml-kem-768\0X", "ml-dsa-65\0ml-dsa-65", "lms_sha256_h5_w8\0x"),
        // A NUL byte at the end, or at the start.
        ("ML-KEM-768\0", "ML-DSA-65\0", "LMS_SHA256_H5_W8\0"),
        ("\0ML-KEM-768", "\0ml-dsa-65", "\0LMS_SHA256_H5_W8"),
        // A digit or punctuation byte off by 0x20, the bit that ASCII case
        // changes for letters. Only letters are folded.
        ("ML\rKEM-768", "ML-DSA\r65", "LMS\u{7F}SHA256_H5_W8"),
        ("ML-KEM-\u{17}\u{16}\u{18}", "ML-DSA-\u{16}\u{15}", "LMS_SHA256_H\u{15}_W\u{18}"),
        // A non-ASCII character that Unicode case mapping turns into an ASCII
        // letter of an enabled name: KELVIN SIGN, DOTLESS I, LONG S.
        ("ML-\u{212A}EM-768", "OV-\u{131}s", "XM\u{17F}S-SHA2_10_256"),
        ("ml-\u{212A}em-768", "ML-D\u{17F}A-65", "LM\u{17F}_SHA256_H5_W8"),
        // Fullwidth letters and digits.
        ("\u{FF2D}L-KEM-768", "ML-DSA-\u{FF16}5", "LMS_SHA256_H5_W\u{FF18}"),
        // A name of another kind.
        ("ML-DSA-65", "ML-KEM-768", "ML-DSA-65"),
        ("XMSS-SHA2_10_256", "LMS_SHA256_H5_W8", "ML-KEM-768"),
    ]

    @Test("Lookup and the enabled check give nil and false for an empty, padded, truncated, NUL-holding, wrongly folded, non-ASCII or other-kind name",
          arguments: misuses.indices)
    func misuseNeverMatches(index: Int) {
        let m = Self.misuses[index]
        #expect(Registry.kemDescription(named: m.kem) == nil, "KEM \(Array(m.kem.utf8))")
        #expect(!Registry.isKEMEnabled(m.kem), "KEM \(Array(m.kem.utf8))")
        #expect(Registry.signatureDescription(named: m.sig) == nil, "signature \(Array(m.sig.utf8))")
        #expect(!Registry.isSignatureEnabled(m.sig), "signature \(Array(m.sig.utf8))")
        #expect(Registry.statefulSignatureDescription(named: m.stateful) == nil, "stateful \(Array(m.stateful.utf8))")
        #expect(!Registry.isStatefulSignatureEnabled(m.stateful), "stateful \(Array(m.stateful.utf8))")
    }

    @Test("The names the misuse cases are built from are enabled, so each miss comes from the change made to the name")
    func misuseBasesAreEnabled() {
        #expect(Registry.isKEMEnabled("ML-KEM-768"))
        #expect(Registry.isSignatureEnabled("ML-DSA-65"))
        #expect(Registry.isSignatureEnabled("OV-Is"))
        #expect(Registry.isStatefulSignatureEnabled("LMS_SHA256_H5_W8"))
        #expect(Registry.isStatefulSignatureEnabled("XMSS-SHA2_10_256"))
    }
}
