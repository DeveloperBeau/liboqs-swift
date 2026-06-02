import Testing
import Foundation
@testable import OQS

@Suite(.serialized) struct AlgorithmTests {

    // MARK: - KEM key generation

    @Test("ML-KEM-512 keygen")
    func mlkem512() throws { _ = try MLKEM512.PrivateKey() }

    @Test("ML-KEM-768 keygen")
    func mlkem768() throws { _ = try MLKEM768.PrivateKey() }

    @Test("ML-KEM-1024 keygen")
    func mlkem1024() throws { _ = try MLKEM1024.PrivateKey() }

    @Test("HQC-128 keygen")
    func hqc128() throws { _ = try HQC128.PrivateKey() }

    @Test("HQC-192 keygen")
    func hqc192() throws { _ = try HQC192.PrivateKey() }

    @Test("HQC-256 keygen")
    func hqc256() throws { _ = try HQC256.PrivateKey() }

    @Test("Classic McEliece 348864 keygen")
    func classicMcEliece348864() throws { _ = try ClassicMcEliece348864.PrivateKey() }

    @Test("Classic McEliece 348864f keygen")
    func classicMcEliece348864f() throws { _ = try ClassicMcEliece348864f.PrivateKey() }

    // Classic McEliece 460896+ variants (including the f-variants) require too much
    // memory for CI keygen. Their types compile and share the same internal path as 348864.

    // MARK: - KEM key generation: FrodoKEM

    @Test("FrodoKEM-640-AES keygen")
    func frodo640AES() throws { _ = try FrodoKEM640AES.PrivateKey() }
    @Test("FrodoKEM-640-SHAKE keygen")
    func frodo640SHAKE() throws { _ = try FrodoKEM640SHAKE.PrivateKey() }
    @Test("FrodoKEM-976-AES keygen")
    func frodo976AES() throws { _ = try FrodoKEM976AES.PrivateKey() }
    @Test("FrodoKEM-976-SHAKE keygen")
    func frodo976SHAKE() throws { _ = try FrodoKEM976SHAKE.PrivateKey() }
    @Test("FrodoKEM-1344-AES keygen")
    func frodo1344AES() throws { _ = try FrodoKEM1344AES.PrivateKey() }
    @Test("FrodoKEM-1344-SHAKE keygen")
    func frodo1344SHAKE() throws { _ = try FrodoKEM1344SHAKE.PrivateKey() }

    // MARK: - KEM key generation: NTRU

    @Test("NTRU-HPS-2048-509 keygen")
    func ntruHPS2048509() throws { _ = try NTRUHPS2048509.PrivateKey() }
    @Test("NTRU-HPS-2048-677 keygen")
    func ntruHPS2048677() throws { _ = try NTRUHPS2048677.PrivateKey() }
    @Test("NTRU-HPS-4096-821 keygen")
    func ntruHPS4096821() throws { _ = try NTRUHPS4096821.PrivateKey() }
    @Test("NTRU-HPS-4096-1229 keygen")
    func ntruHPS40961229() throws { _ = try NTRUHPS40961229.PrivateKey() }
    @Test("NTRU-HRSS-701 keygen")
    func ntruHRSS701() throws { _ = try NTRUHRSS701.PrivateKey() }
    @Test("NTRU-HRSS-1373 keygen")
    func ntruHRSS1373() throws { _ = try NTRUHRSS1373.PrivateKey() }

    // MARK: - KEM key generation: NTRU Prime

    @Test("sntrup761 keygen")
    func sntrup761() throws { _ = try SNTRUP761.PrivateKey() }

    // MARK: - KEM key generation: BIKE

    @Test("BIKE-L1 keygen")
    func bikeL1() throws { _ = try BIKEL1.PrivateKey() }
    @Test("BIKE-L3 keygen")
    func bikeL3() throws { _ = try BIKEL3.PrivateKey() }
    @Test("BIKE-L5 keygen")
    func bikeL5() throws { _ = try BIKEL5.PrivateKey() }

    // MARK: - Signature key generation: Falcon

    @Test("Falcon-512 keygen")
    func falcon512() throws { _ = try Falcon512.PrivateKey() }

    @Test("Falcon-1024 keygen")
    func falcon1024() throws { _ = try Falcon1024.PrivateKey() }

    @Test("FalconPadded-512 keygen")
    func falconPadded512() throws { _ = try FalconPadded512.PrivateKey() }

    @Test("FalconPadded-1024 keygen")
    func falconPadded1024() throws { _ = try FalconPadded1024.PrivateKey() }

    // MARK: - Signature key generation: SPHINCS+

    @Test("SPHINCS+-SHA2-128f-simple keygen")
    func sphincsSHA2128f() throws { _ = try SPHINCSSHA2128fSimple.PrivateKey() }

    @Test("SPHINCS+-SHA2-128s-simple keygen")
    func sphincsSHA2128s() throws { _ = try SPHINCSSHA2128sSimple.PrivateKey() }

    @Test("SPHINCS+-SHA2-192f-simple keygen")
    func sphincsSHA2192f() throws { _ = try SPHINCSSHA2192fSimple.PrivateKey() }

    @Test("SPHINCS+-SHA2-192s-simple keygen")
    func sphincsSHA2192s() throws { _ = try SPHINCSSHA2192sSimple.PrivateKey() }

    @Test("SPHINCS+-SHA2-256f-simple keygen")
    func sphincsSHA2256f() throws { _ = try SPHINCSSHA2256fSimple.PrivateKey() }

    @Test("SPHINCS+-SHA2-256s-simple keygen")
    func sphincsSHA2256s() throws { _ = try SPHINCSSHA2256sSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-128f-simple keygen")
    func sphincsSHAKE128f() throws { _ = try SPHINCSSHAKE128fSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-128s-simple keygen")
    func sphincsSHAKE128s() throws { _ = try SPHINCSSHAKE128sSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-192f-simple keygen")
    func sphincsSHAKE192f() throws { _ = try SPHINCSSHAKE192fSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-192s-simple keygen")
    func sphincsSHAKE192s() throws { _ = try SPHINCSSHAKE192sSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-256f-simple keygen")
    func sphincsSHAKE256f() throws { _ = try SPHINCSSHAKE256fSimple.PrivateKey() }

    @Test("SPHINCS+-SHAKE-256s-simple keygen")
    func sphincsSHAKE256s() throws { _ = try SPHINCSSHAKE256sSimple.PrivateKey() }

    // MARK: - Signature key generation: CROSS

    @Test("CROSS-RSDP-128-Balanced keygen")
    func crossRSDP128Balanced() throws { _ = try CrossRSDP128Balanced.PrivateKey() }

    @Test("CROSS-RSDP-128-Fast keygen")
    func crossRSDP128Fast() throws { _ = try CrossRSDP128Fast.PrivateKey() }

    @Test("CROSS-RSDP-128-Small keygen")
    func crossRSDP128Small() throws { _ = try CrossRSDP128Small.PrivateKey() }

    @Test("CROSS-RSDP-192-Balanced keygen")
    func crossRSDP192Balanced() throws { _ = try CrossRSDP192Balanced.PrivateKey() }

    @Test("CROSS-RSDP-192-Fast keygen")
    func crossRSDP192Fast() throws { _ = try CrossRSDP192Fast.PrivateKey() }

    @Test("CROSS-RSDP-192-Small keygen")
    func crossRSDP192Small() throws { _ = try CrossRSDP192Small.PrivateKey() }

    @Test("CROSS-RSDP-256-Balanced keygen")
    func crossRSDP256Balanced() throws { _ = try CrossRSDP256Balanced.PrivateKey() }

    @Test("CROSS-RSDP-256-Fast keygen")
    func crossRSDP256Fast() throws { _ = try CrossRSDP256Fast.PrivateKey() }

    @Test("CROSS-RSDP-256-Small keygen")
    func crossRSDP256Small() throws { _ = try CrossRSDP256Small.PrivateKey() }

    @Test("CROSS-RSDPG-128-Balanced keygen")
    func crossRSDPG128Balanced() throws { _ = try CrossRSDPG128Balanced.PrivateKey() }

    @Test("CROSS-RSDPG-128-Fast keygen")
    func crossRSDPG128Fast() throws { _ = try CrossRSDPG128Fast.PrivateKey() }

    @Test("CROSS-RSDPG-128-Small keygen")
    func crossRSDPG128Small() throws { _ = try CrossRSDPG128Small.PrivateKey() }

    @Test("CROSS-RSDPG-192-Balanced keygen")
    func crossRSDPG192Balanced() throws { _ = try CrossRSDPG192Balanced.PrivateKey() }

    @Test("CROSS-RSDPG-192-Fast keygen")
    func crossRSDPG192Fast() throws { _ = try CrossRSDPG192Fast.PrivateKey() }

    @Test("CROSS-RSDPG-192-Small keygen")
    func crossRSDPG192Small() throws { _ = try CrossRSDPG192Small.PrivateKey() }

    @Test("CROSS-RSDPG-256-Balanced keygen")
    func crossRSDPG256Balanced() throws { _ = try CrossRSDPG256Balanced.PrivateKey() }

    @Test("CROSS-RSDPG-256-Fast keygen")
    func crossRSDPG256Fast() throws { _ = try CrossRSDPG256Fast.PrivateKey() }

    @Test("CROSS-RSDPG-256-Small keygen")
    func crossRSDPG256Small() throws { _ = try CrossRSDPG256Small.PrivateKey() }

    // MARK: - Signature key generation: SLH-DSA

    @Test("SLH-DSA-Pure-SHA2-128s keygen")
    func slhDSAPureSHA2128s() throws { _ = try SLHDSAPureSHA2128s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHA2-128f keygen")
    func slhDSAPureSHA2128f() throws { _ = try SLHDSAPureSHA2128f.PrivateKey() }

    @Test("SLH-DSA-Pure-SHA2-192s keygen")
    func slhDSAPureSHA2192s() throws { _ = try SLHDSAPureSHA2192s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHA2-192f keygen")
    func slhDSAPureSHA2192f() throws { _ = try SLHDSAPureSHA2192f.PrivateKey() }

    @Test("SLH-DSA-Pure-SHA2-256s keygen")
    func slhDSAPureSHA2256s() throws { _ = try SLHDSAPureSHA2256s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHA2-256f keygen")
    func slhDSAPureSHA2256f() throws { _ = try SLHDSAPureSHA2256f.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-128s keygen")
    func slhDSAPureSHAKE128s() throws { _ = try SLHDSAPureSHAKE128s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-128f keygen")
    func slhDSAPureSHAKE128f() throws { _ = try SLHDSAPureSHAKE128f.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-192s keygen")
    func slhDSAPureSHAKE192s() throws { _ = try SLHDSAPureSHAKE192s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-192f keygen")
    func slhDSAPureSHAKE192f() throws { _ = try SLHDSAPureSHAKE192f.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-256s keygen")
    func slhDSAPureSHAKE256s() throws { _ = try SLHDSAPureSHAKE256s.PrivateKey() }

    @Test("SLH-DSA-Pure-SHAKE-256f keygen")
    func slhDSAPureSHAKE256f() throws { _ = try SLHDSAPureSHAKE256f.PrivateKey() }

    // MARK: - Signature key generation: ML-DSA

    @Test("ML-DSA-44 keygen")
    func mldsa44() throws { _ = try MLDSA44.PrivateKey() }
    @Test("ML-DSA-65 keygen")
    func mldsa65() throws { _ = try MLDSA65.PrivateKey() }
    @Test("ML-DSA-87 keygen")
    func mldsa87() throws { _ = try MLDSA87.PrivateKey() }

    // MARK: - Signature key generation: SNOVA

    // SNOVA's larger parameter sets allocate very large on-stack buffers and
    // crash (uncatchable SIGBUS) on the default swift-testing worker-thread stack:
    //   - keygen crashers (4), excluded from CI keygen tests below:
    //     SNOVA_37_8_4, SNOVA_49_11_3, SNOVA_56_25_2, SNOVA_60_10_4.
    //   - sign-only crashers (2), keygen-tested below but NOT sign-roundtrip-tested:
    //     SNOVA_24_5_5, SNOVA_29_6_5 (rank-5; keygen fits the stack, signing does not).
    // All 12 types compile and are name-resolution-tested in SNOVAResolveTests; the
    // 6 crash-prone variants carry a doc warning about the large-thread-stack
    // requirement (keygen-specific for the four, sign-specific for the two).

    @Test("SNOVA_24_5_4 keygen")
    func snova2454() throws { _ = try SNOVA24_5_4.PrivateKey() }
    @Test("SNOVA_24_5_4_SHAKE keygen")
    func snova2454SHAKE() throws { _ = try SNOVA24_5_4_SHAKE.PrivateKey() }
    @Test("SNOVA_24_5_4_esk keygen")
    func snova2454esk() throws { _ = try SNOVA24_5_4_esk.PrivateKey() }
    @Test("SNOVA_24_5_4_SHAKE_esk keygen")
    func snova2454SHAKEesk() throws { _ = try SNOVA24_5_4_SHAKE_esk.PrivateKey() }
    @Test("SNOVA_24_5_5 keygen")
    func snova2455() throws { _ = try SNOVA24_5_5.PrivateKey() }
    @Test("SNOVA_25_8_3 keygen")
    func snova2583() throws { _ = try SNOVA25_8_3.PrivateKey() }
    @Test("SNOVA_29_6_5 keygen")
    func snova2965() throws { _ = try SNOVA29_6_5.PrivateKey() }
    @Test("SNOVA_37_17_2 keygen")
    func snova37172() throws { _ = try SNOVA37_17_2.PrivateKey() }

    // MARK: - Signature key generation: MAYO

    // MAYO-5's largest parameter set allocates very large on-stack buffers and
    // crashes (uncatchable SIGBUS) on the default swift-testing worker-thread
    // stack during key generation. It is verified to work on a large stack
    // (32 MB) but is excluded here and from sign-roundtrip tests; the type
    // compiles and is name-resolution-tested in MAYOResolveTests, and carries a
    // doc warning about the large-thread-stack requirement.

    @Test("MAYO-1 keygen")
    func mayo1() throws { _ = try MAYO1.PrivateKey() }
    @Test("MAYO-2 keygen")
    func mayo2() throws { _ = try MAYO2.PrivateKey() }
    @Test("MAYO-3 keygen")
    func mayo3() throws { _ = try MAYO3.PrivateKey() }

    // MARK: - Signature key generation: UOV

    @Test("OV-Is keygen")
    func ovIs() throws { _ = try OVIs.PrivateKey() }
    @Test("OV-Ip keygen")
    func ovIp() throws { _ = try OVIp.PrivateKey() }
    @Test("OV-III keygen")
    func ovIII() throws { _ = try OVIII.PrivateKey() }
    @Test("OV-V keygen")
    func ovV() throws { _ = try OVV.PrivateKey() }
    @Test("OV-Is-pkc keygen")
    func ovIsPKC() throws { _ = try OVIsPKC.PrivateKey() }
    @Test("OV-Ip-pkc keygen")
    func ovIpPKC() throws { _ = try OVIpPKC.PrivateKey() }
    @Test("OV-III-pkc keygen")
    func ovIIIPKC() throws { _ = try OVIIIPKC.PrivateKey() }
    @Test("OV-V-pkc keygen")
    func ovVPKC() throws { _ = try OVVPKC.PrivateKey() }
    @Test("OV-Is-pkc-skc keygen")
    func ovIsPKCSKC() throws { _ = try OVIsPKCSKC.PrivateKey() }
    @Test("OV-Ip-pkc-skc keygen")
    func ovIpPKCSKC() throws { _ = try OVIpPKCSKC.PrivateKey() }
    @Test("OV-III-pkc-skc keygen")
    func ovIIIPKCSKC() throws { _ = try OVIIIPKCSKC.PrivateKey() }
    @Test("OV-V-pkc-skc keygen")
    func ovVPKCSKC() throws { _ = try OVVPKCSKC.PrivateKey() }

    // MARK: - KEM key generation: Kyber (deprecated)

    @available(*, deprecated, message: "Exercises deprecated Kyber on purpose")
    @Test("Kyber512 keygen")
    func kyber512() throws { _ = try Kyber512.PrivateKey() }
    @available(*, deprecated, message: "Exercises deprecated Kyber on purpose")
    @Test("Kyber768 keygen")
    func kyber768() throws { _ = try Kyber768.PrivateKey() }
    @available(*, deprecated, message: "Exercises deprecated Kyber on purpose")
    @Test("Kyber1024 keygen")
    func kyber1024() throws { _ = try Kyber1024.PrivateKey() }

    // MARK: - Error descriptions

    // MARK: - Stateful hash signature keygen (feasible variants only)
    //
    // Stateful keygen builds a hash tree whose cost grows with tree height H.
    // We smoke only the small/feasible sets. Larger sets are
    // name-resolution-tested in STFLResolveTests and carry DocC `- Warning`s for
    // keygen cost. Empirically excluded as infeasible/too slow for CI:
    //   - XMSS h16, h20
    //   - XMSSMT h40/*, h60/*
    //   - LMS H15*, H20*, H25*, and 2-level chains topping h15/h20
    // (XMSS h10 ~3.4s, XMSSMT 20/2 ~6.7s, LMS h10 ~5s; all measured locally.)

    @Test("XMSS-SHA2_10_256 keygen")
    func xmssSha2H10() throws { _ = try XMSS.PrivateKey(.sha2_10_256) }
    @Test("XMSS-SHAKE_10_256 keygen")
    func xmssShake128H10() throws { _ = try XMSS.PrivateKey(.shake128_10_256) }
    @Test("XMSS-SHA2_10_192 keygen")
    func xmssSha2H10_192() throws { _ = try XMSS.PrivateKey(.sha2_10_192) }

    @Test("XMSSMT-SHA2_20/2_256 keygen")
    func xmssmtSha2H20_2() throws { _ = try XMSSMT.PrivateKey(.sha2_h20_2) }

    @Test("LMS H5/W1 keygen")
    func lmsH5W1() throws { _ = try LMS.PrivateKey(.sha256_h5_w1) }
    @Test("LMS H5/W8 keygen")
    func lmsH5W8() throws { _ = try LMS.PrivateKey(.sha256_h5_w8) }
    @Test("LMS H10/W8 keygen")
    func lmsH10W8() throws { _ = try LMS.PrivateKey(.sha256_h10_w8) }
    @Test("LMS H5/W8_H5/W8 two-level keygen")
    func lmsH5W8H5W8() throws { _ = try LMS.PrivateKey(.sha256_h5_w8_h5_w8) }

    @Test("All OQSError cases produce non-empty descriptions")
    func errorDescriptionsNonEmpty() {
        let cases: [OQSError] = [
            .algorithmNotAvailable("test"),
            .keyGenerationFailed,
            .encapsulationFailed,
            .decapsulationFailed,
            .signFailed,
            .verifyFailed,
            .invalidKeySize(expected: 32, actual: 16),
        ]
        for error in cases {
            #expect(!error.description.isEmpty)
        }
    }

    @Test("invalidKeySize description includes both sizes")
    func invalidKeySizeDescription() {
        let error = OQSError.invalidKeySize(expected: 128, actual: 64)
        #expect(error.description.contains("128"))
        #expect(error.description.contains("64"))
    }

    @Test("algorithmNotAvailable description includes name")
    func algorithmNotAvailableDescription() {
        let error = OQSError.algorithmNotAvailable("FakeAlgo-999")
        #expect(error.description.contains("FakeAlgo-999"))
    }
}
