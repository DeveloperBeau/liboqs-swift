import Foundation
@testable import OQS

// Generated from the stateless signature list in ParityRegistry. Each entry holds the
// liboqs name and closures over that type's typed methods. SLHDSA.Prehash is one entry
// because its context forwards live in one file shared by all 144 combinations.

enum ContextForwardTable {
    /// The Prehash combination used for the Prehash entry. One is enough because the
    /// context forwards are one pair of methods in one file.
    static let prehashFunction = SLHDSA.Prehash.Function.sha2_256
    static let prehashParamSet = SLHDSA.Prehash.ParamSet.sha2_128f

    static let cases: [ContextForwardCase] = [
        .prehash(SLHDSA.Prehash.algorithmName(prehashFunction, prehashParamSet)) {
            try SLHDSA.Prehash.PrivateKey(prehash: prehashFunction, paramSet: prehashParamSet)
        },
        .typed(CrossRSDP128Balanced.algorithmName, CrossRSDP128Balanced.PrivateKey.init),
        .typed(CrossRSDP128Fast.algorithmName, CrossRSDP128Fast.PrivateKey.init),
        .typed(CrossRSDP128Small.algorithmName, CrossRSDP128Small.PrivateKey.init),
        .typed(CrossRSDP192Balanced.algorithmName, CrossRSDP192Balanced.PrivateKey.init),
        .typed(CrossRSDP192Fast.algorithmName, CrossRSDP192Fast.PrivateKey.init),
        .typed(CrossRSDP192Small.algorithmName, CrossRSDP192Small.PrivateKey.init),
        .typed(CrossRSDP256Balanced.algorithmName, CrossRSDP256Balanced.PrivateKey.init),
        .typed(CrossRSDP256Fast.algorithmName, CrossRSDP256Fast.PrivateKey.init),
        .typed(CrossRSDP256Small.algorithmName, CrossRSDP256Small.PrivateKey.init),
        .typed(CrossRSDPG128Balanced.algorithmName, CrossRSDPG128Balanced.PrivateKey.init),
        .typed(CrossRSDPG128Fast.algorithmName, CrossRSDPG128Fast.PrivateKey.init),
        .typed(CrossRSDPG128Small.algorithmName, CrossRSDPG128Small.PrivateKey.init),
        .typed(CrossRSDPG192Balanced.algorithmName, CrossRSDPG192Balanced.PrivateKey.init),
        .typed(CrossRSDPG192Fast.algorithmName, CrossRSDPG192Fast.PrivateKey.init),
        .typed(CrossRSDPG192Small.algorithmName, CrossRSDPG192Small.PrivateKey.init),
        .typed(CrossRSDPG256Balanced.algorithmName, CrossRSDPG256Balanced.PrivateKey.init),
        .typed(CrossRSDPG256Fast.algorithmName, CrossRSDPG256Fast.PrivateKey.init),
        .typed(CrossRSDPG256Small.algorithmName, CrossRSDPG256Small.PrivateKey.init),
        .typed(Falcon1024.algorithmName, Falcon1024.PrivateKey.init),
        .typed(Falcon512.algorithmName, Falcon512.PrivateKey.init),
        .typed(FalconPadded1024.algorithmName, FalconPadded1024.PrivateKey.init),
        .typed(FalconPadded512.algorithmName, FalconPadded512.PrivateKey.init),
        .typed(MAYO1.algorithmName, MAYO1.PrivateKey.init),
        .typed(MAYO2.algorithmName, MAYO2.PrivateKey.init),
        .typed(MAYO3.algorithmName, MAYO3.PrivateKey.init),
        .typed(MAYO5.algorithmName, MAYO5.PrivateKey.init),
        .typed(MLDSA44.algorithmName, MLDSA44.PrivateKey.init),
        .typed(MLDSA65.algorithmName, MLDSA65.PrivateKey.init),
        .typed(MLDSA87.algorithmName, MLDSA87.PrivateKey.init),
        .typed(MQOM2Cat1GF16FastR3.algorithmName, MQOM2Cat1GF16FastR3.PrivateKey.init),
        .typed(MQOM2Cat1GF16FastR5.algorithmName, MQOM2Cat1GF16FastR5.PrivateKey.init),
        .typed(MQOM2Cat1GF16ShortR3.algorithmName, MQOM2Cat1GF16ShortR3.PrivateKey.init),
        .typed(MQOM2Cat1GF16ShortR5.algorithmName, MQOM2Cat1GF16ShortR5.PrivateKey.init),
        .typed(MQOM2Cat3GF16FastR3.algorithmName, MQOM2Cat3GF16FastR3.PrivateKey.init),
        .typed(MQOM2Cat3GF16FastR5.algorithmName, MQOM2Cat3GF16FastR5.PrivateKey.init),
        .typed(MQOM2Cat3GF16ShortR3.algorithmName, MQOM2Cat3GF16ShortR3.PrivateKey.init),
        .typed(MQOM2Cat3GF16ShortR5.algorithmName, MQOM2Cat3GF16ShortR5.PrivateKey.init),
        .typed(MQOM2Cat5GF16FastR3.algorithmName, MQOM2Cat5GF16FastR3.PrivateKey.init),
        .typed(MQOM2Cat5GF16FastR5.algorithmName, MQOM2Cat5GF16FastR5.PrivateKey.init),
        .typed(MQOM2Cat5GF16ShortR3.algorithmName, MQOM2Cat5GF16ShortR3.PrivateKey.init),
        .typed(MQOM2Cat5GF16ShortR5.algorithmName, MQOM2Cat5GF16ShortR5.PrivateKey.init),
        .typed(OVIII.algorithmName, OVIII.PrivateKey.init),
        .typed(OVIIIPKC.algorithmName, OVIIIPKC.PrivateKey.init),
        .typed(OVIIIPKCSKC.algorithmName, OVIIIPKCSKC.PrivateKey.init),
        .typed(OVIp.algorithmName, OVIp.PrivateKey.init),
        .typed(OVIpPKC.algorithmName, OVIpPKC.PrivateKey.init),
        .typed(OVIpPKCSKC.algorithmName, OVIpPKCSKC.PrivateKey.init),
        .typed(OVIs.algorithmName, OVIs.PrivateKey.init),
        .typed(OVIsPKC.algorithmName, OVIsPKC.PrivateKey.init),
        .typed(OVIsPKCSKC.algorithmName, OVIsPKCSKC.PrivateKey.init),
        .typed(OVV.algorithmName, OVV.PrivateKey.init),
        .typed(OVVPKC.algorithmName, OVVPKC.PrivateKey.init),
        .typed(OVVPKCSKC.algorithmName, OVVPKCSKC.PrivateKey.init),
        .typed(SLHDSAPureSHA2128f.algorithmName, SLHDSAPureSHA2128f.PrivateKey.init),
        .typed(SLHDSAPureSHA2128s.algorithmName, SLHDSAPureSHA2128s.PrivateKey.init),
        .typed(SLHDSAPureSHA2192f.algorithmName, SLHDSAPureSHA2192f.PrivateKey.init),
        .typed(SLHDSAPureSHA2192s.algorithmName, SLHDSAPureSHA2192s.PrivateKey.init),
        .typed(SLHDSAPureSHA2256f.algorithmName, SLHDSAPureSHA2256f.PrivateKey.init),
        .typed(SLHDSAPureSHA2256s.algorithmName, SLHDSAPureSHA2256s.PrivateKey.init),
        .typed(SLHDSAPureSHAKE128f.algorithmName, SLHDSAPureSHAKE128f.PrivateKey.init),
        .typed(SLHDSAPureSHAKE128s.algorithmName, SLHDSAPureSHAKE128s.PrivateKey.init),
        .typed(SLHDSAPureSHAKE192f.algorithmName, SLHDSAPureSHAKE192f.PrivateKey.init),
        .typed(SLHDSAPureSHAKE192s.algorithmName, SLHDSAPureSHAKE192s.PrivateKey.init),
        .typed(SLHDSAPureSHAKE256f.algorithmName, SLHDSAPureSHAKE256f.PrivateKey.init),
        .typed(SLHDSAPureSHAKE256s.algorithmName, SLHDSAPureSHAKE256s.PrivateKey.init),
        .typed(SNOVA24_5_4.algorithmName, SNOVA24_5_4.PrivateKey.init),
        .typed(SNOVA24_5_4_SHAKE.algorithmName, SNOVA24_5_4_SHAKE.PrivateKey.init),
        .typed(SNOVA24_5_4_SHAKE_esk.algorithmName, SNOVA24_5_4_SHAKE_esk.PrivateKey.init),
        .typed(SNOVA24_5_4_esk.algorithmName, SNOVA24_5_4_esk.PrivateKey.init),
        .typed(SNOVA24_5_5.algorithmName, SNOVA24_5_5.PrivateKey.init),
        .typed(SNOVA25_8_3.algorithmName, SNOVA25_8_3.PrivateKey.init),
        .typed(SNOVA29_6_5.algorithmName, SNOVA29_6_5.PrivateKey.init),
        .typed(SNOVA37_17_2.algorithmName, SNOVA37_17_2.PrivateKey.init),
        .typed(SNOVA37_8_4.algorithmName, SNOVA37_8_4.PrivateKey.init),
        .typed(SNOVA49_11_3.algorithmName, SNOVA49_11_3.PrivateKey.init),
        .typed(SNOVA56_25_2.algorithmName, SNOVA56_25_2.PrivateKey.init),
        .typed(SNOVA60_10_4.algorithmName, SNOVA60_10_4.PrivateKey.init),
    ]
}

extension CrossRSDP128Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP128Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDP128Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP128Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDP128Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP128Small.PublicKey: ContextSigPublicKey {}
extension CrossRSDP192Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP192Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDP192Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP192Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDP192Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP192Small.PublicKey: ContextSigPublicKey {}
extension CrossRSDP256Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP256Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDP256Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP256Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDP256Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDP256Small.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG128Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG128Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG128Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG128Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG128Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG128Small.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG192Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG192Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG192Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG192Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG192Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG192Small.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG256Balanced.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG256Balanced.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG256Fast.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG256Fast.PublicKey: ContextSigPublicKey {}
extension CrossRSDPG256Small.PrivateKey: ContextSigPrivateKey {}
extension CrossRSDPG256Small.PublicKey: ContextSigPublicKey {}
extension Falcon1024.PrivateKey: ContextSigPrivateKey {}
extension Falcon1024.PublicKey: ContextSigPublicKey {}
extension Falcon512.PrivateKey: ContextSigPrivateKey {}
extension Falcon512.PublicKey: ContextSigPublicKey {}
extension FalconPadded1024.PrivateKey: ContextSigPrivateKey {}
extension FalconPadded1024.PublicKey: ContextSigPublicKey {}
extension FalconPadded512.PrivateKey: ContextSigPrivateKey {}
extension FalconPadded512.PublicKey: ContextSigPublicKey {}
extension MAYO1.PrivateKey: ContextSigPrivateKey {}
extension MAYO1.PublicKey: ContextSigPublicKey {}
extension MAYO2.PrivateKey: ContextSigPrivateKey {}
extension MAYO2.PublicKey: ContextSigPublicKey {}
extension MAYO3.PrivateKey: ContextSigPrivateKey {}
extension MAYO3.PublicKey: ContextSigPublicKey {}
extension MAYO5.PrivateKey: ContextSigPrivateKey {}
extension MAYO5.PublicKey: ContextSigPublicKey {}
extension MLDSA44.PrivateKey: ContextSigPrivateKey {}
extension MLDSA44.PublicKey: ContextSigPublicKey {}
extension MLDSA65.PrivateKey: ContextSigPrivateKey {}
extension MLDSA65.PublicKey: ContextSigPublicKey {}
extension MLDSA87.PrivateKey: ContextSigPrivateKey {}
extension MLDSA87.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat1GF16FastR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat1GF16FastR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat1GF16FastR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat1GF16FastR5.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat1GF16ShortR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat1GF16ShortR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat1GF16ShortR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat1GF16ShortR5.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat3GF16FastR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat3GF16FastR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat3GF16FastR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat3GF16FastR5.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat3GF16ShortR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat3GF16ShortR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat3GF16ShortR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat3GF16ShortR5.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat5GF16FastR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat5GF16FastR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat5GF16FastR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat5GF16FastR5.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat5GF16ShortR3.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat5GF16ShortR3.PublicKey: ContextSigPublicKey {}
extension MQOM2Cat5GF16ShortR5.PrivateKey: ContextSigPrivateKey {}
extension MQOM2Cat5GF16ShortR5.PublicKey: ContextSigPublicKey {}
extension OVIII.PrivateKey: ContextSigPrivateKey {}
extension OVIII.PublicKey: ContextSigPublicKey {}
extension OVIIIPKC.PrivateKey: ContextSigPrivateKey {}
extension OVIIIPKC.PublicKey: ContextSigPublicKey {}
extension OVIIIPKCSKC.PrivateKey: ContextSigPrivateKey {}
extension OVIIIPKCSKC.PublicKey: ContextSigPublicKey {}
extension OVIp.PrivateKey: ContextSigPrivateKey {}
extension OVIp.PublicKey: ContextSigPublicKey {}
extension OVIpPKC.PrivateKey: ContextSigPrivateKey {}
extension OVIpPKC.PublicKey: ContextSigPublicKey {}
extension OVIpPKCSKC.PrivateKey: ContextSigPrivateKey {}
extension OVIpPKCSKC.PublicKey: ContextSigPublicKey {}
extension OVIs.PrivateKey: ContextSigPrivateKey {}
extension OVIs.PublicKey: ContextSigPublicKey {}
extension OVIsPKC.PrivateKey: ContextSigPrivateKey {}
extension OVIsPKC.PublicKey: ContextSigPublicKey {}
extension OVIsPKCSKC.PrivateKey: ContextSigPrivateKey {}
extension OVIsPKCSKC.PublicKey: ContextSigPublicKey {}
extension OVV.PrivateKey: ContextSigPrivateKey {}
extension OVV.PublicKey: ContextSigPublicKey {}
extension OVVPKC.PrivateKey: ContextSigPrivateKey {}
extension OVVPKC.PublicKey: ContextSigPublicKey {}
extension OVVPKCSKC.PrivateKey: ContextSigPrivateKey {}
extension OVVPKCSKC.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2128f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2128f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2128s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2128s.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2192f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2192f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2192s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2192s.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2256f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2256f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHA2256s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHA2256s.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE128f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE128f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE128s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE128s.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE192f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE192f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE192s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE192s.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE256f.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE256f.PublicKey: ContextSigPublicKey {}
extension SLHDSAPureSHAKE256s.PrivateKey: ContextSigPrivateKey {}
extension SLHDSAPureSHAKE256s.PublicKey: ContextSigPublicKey {}
extension SNOVA24_5_4.PrivateKey: ContextSigPrivateKey {}
extension SNOVA24_5_4.PublicKey: ContextSigPublicKey {}
extension SNOVA24_5_4_SHAKE.PrivateKey: ContextSigPrivateKey {}
extension SNOVA24_5_4_SHAKE.PublicKey: ContextSigPublicKey {}
extension SNOVA24_5_4_SHAKE_esk.PrivateKey: ContextSigPrivateKey {}
extension SNOVA24_5_4_SHAKE_esk.PublicKey: ContextSigPublicKey {}
extension SNOVA24_5_4_esk.PrivateKey: ContextSigPrivateKey {}
extension SNOVA24_5_4_esk.PublicKey: ContextSigPublicKey {}
extension SNOVA24_5_5.PrivateKey: ContextSigPrivateKey {}
extension SNOVA24_5_5.PublicKey: ContextSigPublicKey {}
extension SNOVA25_8_3.PrivateKey: ContextSigPrivateKey {}
extension SNOVA25_8_3.PublicKey: ContextSigPublicKey {}
extension SNOVA29_6_5.PrivateKey: ContextSigPrivateKey {}
extension SNOVA29_6_5.PublicKey: ContextSigPublicKey {}
extension SNOVA37_17_2.PrivateKey: ContextSigPrivateKey {}
extension SNOVA37_17_2.PublicKey: ContextSigPublicKey {}
extension SNOVA37_8_4.PrivateKey: ContextSigPrivateKey {}
extension SNOVA37_8_4.PublicKey: ContextSigPublicKey {}
extension SNOVA49_11_3.PrivateKey: ContextSigPrivateKey {}
extension SNOVA49_11_3.PublicKey: ContextSigPublicKey {}
extension SNOVA56_25_2.PrivateKey: ContextSigPrivateKey {}
extension SNOVA56_25_2.PublicKey: ContextSigPublicKey {}
extension SNOVA60_10_4.PrivateKey: ContextSigPrivateKey {}
extension SNOVA60_10_4.PublicKey: ContextSigPublicKey {}
extension SLHDSA.Prehash.PrivateKey: ContextSigPrivateKey {}
extension SLHDSA.Prehash.PublicKey: ContextSigPublicKey {}
