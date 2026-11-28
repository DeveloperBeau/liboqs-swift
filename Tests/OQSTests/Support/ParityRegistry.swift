import Foundation
@testable import OQS

/// Maps every liboqs KEM and stateless signature name to a closure that runs
/// the base case through the algorithm's public Swift type, the way a caller
/// would. The raw C API stays the reference in ParityTests. The names come from
/// each type's own `algorithmName`, so ParityRegistryTests can prove that the
/// types and liboqs agree on the set of algorithms.
enum ParityRegistry {
    static let message = Data("the quick brown fox".utf8)

    /// Every enabled liboqs KEM and stateless signature name, in liboqs order.
    static func enabledNames() -> (kems: [String], sigs: [String]) {
        (Registry.enabledKEMNames, Registry.enabledSignatureNames)
    }

    // KEM base case: keygen, reseed, encapsulate, decapsulate.
    private static func kem<K: ParityKEMPrivateKey>(
        _ name: String, _ make: @escaping @Sendable () throws -> K
    ) -> ParityAlgorithm {
        ParityAlgorithm(name: name, run: {
            KAT.seedDeterministicRNG()
            let key = try make()
            KAT.seedDeterministicRNG()
            let enc = try key.publicKey.generateSharedSecret()
            let ss2 = try key.decryptSharedSecret(enc.ciphertext)
            return [
                ("pk", key.publicKey.rawRepresentation), ("sk", key.rawRepresentation),
                ("ct", enc.ciphertext), ("ss", enc.sharedSecret.rawRepresentation),
                ("ss2", ss2.rawRepresentation),
            ]
        }, typedLengths: { try TypedLengths.kem(K.self) })
    }

    // Signature base case: keygen, reseed, sign `message`.
    private static func sig<K: ParitySigPrivateKey>(
        _ name: String, _ make: @escaping @Sendable () throws -> K,
        typedLengths: @escaping @Sendable () throws -> TypedLengths
    ) -> ParityAlgorithm {
        ParityAlgorithm(name: name, run: {
            KAT.seedDeterministicRNG()
            let key = try make()
            KAT.seedDeterministicRNG()
            let sg = try key.signature(for: message)
            return [("pk", key.publicKey.rawRepresentation), ("sk", key.rawRepresentation), ("sig", sg)]
        }, typedLengths: typedLengths, signed: {
            let key = try make()
            let pub = key.publicKey
            return SignedSample(
                message: message, publicKey: pub.rawRepresentation,
                signature: try key.signature(for: message),
                verify: { try pub.isValidSignature($0, for: message) })
        })
    }

    private static func sig<K: ParityImportableSigPrivateKey>(
        _ name: String, _ make: @escaping @Sendable () throws -> K
    ) -> ParityAlgorithm {
        sig(name, make, typedLengths: { try TypedLengths.signature(K.self, name: name) })
    }

    static func kems() -> [ParityAlgorithm] {
        [
            kem(BIKEL1.algorithmName, BIKEL1.PrivateKey.init),
            kem(BIKEL3.algorithmName, BIKEL3.PrivateKey.init),
            kem(BIKEL5.algorithmName, BIKEL5.PrivateKey.init),
            kem(ClassicMcEliece348864.algorithmName, ClassicMcEliece348864.PrivateKey.init),
            kem(ClassicMcEliece348864f.algorithmName, ClassicMcEliece348864f.PrivateKey.init),
            kem(ClassicMcEliece460896.algorithmName, ClassicMcEliece460896.PrivateKey.init),
            kem(ClassicMcEliece460896f.algorithmName, ClassicMcEliece460896f.PrivateKey.init),
            kem(ClassicMcEliece6688128.algorithmName, ClassicMcEliece6688128.PrivateKey.init),
            kem(ClassicMcEliece6688128f.algorithmName, ClassicMcEliece6688128f.PrivateKey.init),
            kem(ClassicMcEliece6960119.algorithmName, ClassicMcEliece6960119.PrivateKey.init),
            kem(ClassicMcEliece6960119f.algorithmName, ClassicMcEliece6960119f.PrivateKey.init),
            kem(ClassicMcEliece8192128.algorithmName, ClassicMcEliece8192128.PrivateKey.init),
            kem(ClassicMcEliece8192128f.algorithmName, ClassicMcEliece8192128f.PrivateKey.init),
            kem(EFrodoKEM1344AES.algorithmName, EFrodoKEM1344AES.PrivateKey.init),
            kem(EFrodoKEM1344SHAKE.algorithmName, EFrodoKEM1344SHAKE.PrivateKey.init),
            kem(EFrodoKEM640AES.algorithmName, EFrodoKEM640AES.PrivateKey.init),
            kem(EFrodoKEM640SHAKE.algorithmName, EFrodoKEM640SHAKE.PrivateKey.init),
            kem(EFrodoKEM976AES.algorithmName, EFrodoKEM976AES.PrivateKey.init),
            kem(EFrodoKEM976SHAKE.algorithmName, EFrodoKEM976SHAKE.PrivateKey.init),
            kem(FrodoKEM1344AES.algorithmName, FrodoKEM1344AES.PrivateKey.init),
            kem(FrodoKEM1344SHAKE.algorithmName, FrodoKEM1344SHAKE.PrivateKey.init),
            kem(FrodoKEM640AES.algorithmName, FrodoKEM640AES.PrivateKey.init),
            kem(FrodoKEM640SHAKE.algorithmName, FrodoKEM640SHAKE.PrivateKey.init),
            kem(FrodoKEM976AES.algorithmName, FrodoKEM976AES.PrivateKey.init),
            kem(FrodoKEM976SHAKE.algorithmName, FrodoKEM976SHAKE.PrivateKey.init),
            kem(HQC1.algorithmName, HQC1.PrivateKey.init),
            kem(HQC3.algorithmName, HQC3.PrivateKey.init),
            kem(HQC5.algorithmName, HQC5.PrivateKey.init),
            kem(Kyber1024.algorithmName, Kyber1024.PrivateKey.init),
            kem(Kyber512.algorithmName, Kyber512.PrivateKey.init),
            kem(Kyber768.algorithmName, Kyber768.PrivateKey.init),
            kem(MLKEM1024.algorithmName, MLKEM1024.PrivateKey.init),
            kem(MLKEM512.algorithmName, MLKEM512.PrivateKey.init),
            kem(MLKEM768.algorithmName, MLKEM768.PrivateKey.init),
            kem(NTRUHPS2048509.algorithmName, NTRUHPS2048509.PrivateKey.init),
            kem(NTRUHPS2048677.algorithmName, NTRUHPS2048677.PrivateKey.init),
            kem(NTRUHPS40961229.algorithmName, NTRUHPS40961229.PrivateKey.init),
            kem(NTRUHPS4096821.algorithmName, NTRUHPS4096821.PrivateKey.init),
            kem(NTRUHRSS1373.algorithmName, NTRUHRSS1373.PrivateKey.init),
            kem(NTRUHRSS701.algorithmName, NTRUHRSS701.PrivateKey.init),
            kem(SNTRUP761.algorithmName, SNTRUP761.PrivateKey.init),
        ]
    }

    static func sigs() -> [ParityAlgorithm] {
        // SLH-DSA pre-hash is parameterized: 12 functions x 12 parameter sets.
        let prehash = SLHDSA.Prehash.Function.allCases.flatMap { fn in
            SLHDSA.Prehash.ParamSet.allCases.map { ps in
                sig(
                    SLHDSA.Prehash.algorithmName(fn, ps),
                    { try SLHDSA.Prehash.PrivateKey(prehash: fn, paramSet: ps) },
                    typedLengths: { try TypedLengths.prehash(fn, ps) })
            }
        }
        return prehash + [
            sig(CrossRSDP128Balanced.algorithmName, CrossRSDP128Balanced.PrivateKey.init),
            sig(CrossRSDP128Fast.algorithmName, CrossRSDP128Fast.PrivateKey.init),
            sig(CrossRSDP128Small.algorithmName, CrossRSDP128Small.PrivateKey.init),
            sig(CrossRSDP192Balanced.algorithmName, CrossRSDP192Balanced.PrivateKey.init),
            sig(CrossRSDP192Fast.algorithmName, CrossRSDP192Fast.PrivateKey.init),
            sig(CrossRSDP192Small.algorithmName, CrossRSDP192Small.PrivateKey.init),
            sig(CrossRSDP256Balanced.algorithmName, CrossRSDP256Balanced.PrivateKey.init),
            sig(CrossRSDP256Fast.algorithmName, CrossRSDP256Fast.PrivateKey.init),
            sig(CrossRSDP256Small.algorithmName, CrossRSDP256Small.PrivateKey.init),
            sig(CrossRSDPG128Balanced.algorithmName, CrossRSDPG128Balanced.PrivateKey.init),
            sig(CrossRSDPG128Fast.algorithmName, CrossRSDPG128Fast.PrivateKey.init),
            sig(CrossRSDPG128Small.algorithmName, CrossRSDPG128Small.PrivateKey.init),
            sig(CrossRSDPG192Balanced.algorithmName, CrossRSDPG192Balanced.PrivateKey.init),
            sig(CrossRSDPG192Fast.algorithmName, CrossRSDPG192Fast.PrivateKey.init),
            sig(CrossRSDPG192Small.algorithmName, CrossRSDPG192Small.PrivateKey.init),
            sig(CrossRSDPG256Balanced.algorithmName, CrossRSDPG256Balanced.PrivateKey.init),
            sig(CrossRSDPG256Fast.algorithmName, CrossRSDPG256Fast.PrivateKey.init),
            sig(CrossRSDPG256Small.algorithmName, CrossRSDPG256Small.PrivateKey.init),
            sig(Falcon1024.algorithmName, Falcon1024.PrivateKey.init),
            sig(Falcon512.algorithmName, Falcon512.PrivateKey.init),
            sig(FalconPadded1024.algorithmName, FalconPadded1024.PrivateKey.init),
            sig(FalconPadded512.algorithmName, FalconPadded512.PrivateKey.init),
            sig(MAYO1.algorithmName, MAYO1.PrivateKey.init),
            sig(MAYO2.algorithmName, MAYO2.PrivateKey.init),
            sig(MAYO3.algorithmName, MAYO3.PrivateKey.init),
            sig(MAYO5.algorithmName, MAYO5.PrivateKey.init),
            sig(MLDSA44.algorithmName, MLDSA44.PrivateKey.init),
            sig(MLDSA65.algorithmName, MLDSA65.PrivateKey.init),
            sig(MLDSA87.algorithmName, MLDSA87.PrivateKey.init),
            sig(MQOM2Cat1GF16FastR3.algorithmName, MQOM2Cat1GF16FastR3.PrivateKey.init),
            sig(MQOM2Cat1GF16FastR5.algorithmName, MQOM2Cat1GF16FastR5.PrivateKey.init),
            sig(MQOM2Cat1GF16ShortR3.algorithmName, MQOM2Cat1GF16ShortR3.PrivateKey.init),
            sig(MQOM2Cat1GF16ShortR5.algorithmName, MQOM2Cat1GF16ShortR5.PrivateKey.init),
            sig(MQOM2Cat3GF16FastR3.algorithmName, MQOM2Cat3GF16FastR3.PrivateKey.init),
            sig(MQOM2Cat3GF16FastR5.algorithmName, MQOM2Cat3GF16FastR5.PrivateKey.init),
            sig(MQOM2Cat3GF16ShortR3.algorithmName, MQOM2Cat3GF16ShortR3.PrivateKey.init),
            sig(MQOM2Cat3GF16ShortR5.algorithmName, MQOM2Cat3GF16ShortR5.PrivateKey.init),
            sig(MQOM2Cat5GF16FastR3.algorithmName, MQOM2Cat5GF16FastR3.PrivateKey.init),
            sig(MQOM2Cat5GF16FastR5.algorithmName, MQOM2Cat5GF16FastR5.PrivateKey.init),
            sig(MQOM2Cat5GF16ShortR3.algorithmName, MQOM2Cat5GF16ShortR3.PrivateKey.init),
            sig(MQOM2Cat5GF16ShortR5.algorithmName, MQOM2Cat5GF16ShortR5.PrivateKey.init),
            sig(SLHDSAPureSHA2128f.algorithmName, SLHDSAPureSHA2128f.PrivateKey.init),
            sig(SLHDSAPureSHA2128s.algorithmName, SLHDSAPureSHA2128s.PrivateKey.init),
            sig(SLHDSAPureSHA2192f.algorithmName, SLHDSAPureSHA2192f.PrivateKey.init),
            sig(SLHDSAPureSHA2192s.algorithmName, SLHDSAPureSHA2192s.PrivateKey.init),
            sig(SLHDSAPureSHA2256f.algorithmName, SLHDSAPureSHA2256f.PrivateKey.init),
            sig(SLHDSAPureSHA2256s.algorithmName, SLHDSAPureSHA2256s.PrivateKey.init),
            sig(SLHDSAPureSHAKE128f.algorithmName, SLHDSAPureSHAKE128f.PrivateKey.init),
            sig(SLHDSAPureSHAKE128s.algorithmName, SLHDSAPureSHAKE128s.PrivateKey.init),
            sig(SLHDSAPureSHAKE192f.algorithmName, SLHDSAPureSHAKE192f.PrivateKey.init),
            sig(SLHDSAPureSHAKE192s.algorithmName, SLHDSAPureSHAKE192s.PrivateKey.init),
            sig(SLHDSAPureSHAKE256f.algorithmName, SLHDSAPureSHAKE256f.PrivateKey.init),
            sig(SLHDSAPureSHAKE256s.algorithmName, SLHDSAPureSHAKE256s.PrivateKey.init),
            sig(SNOVA24_5_4.algorithmName, SNOVA24_5_4.PrivateKey.init),
            sig(SNOVA24_5_4_SHAKE.algorithmName, SNOVA24_5_4_SHAKE.PrivateKey.init),
            sig(SNOVA24_5_4_SHAKE_esk.algorithmName, SNOVA24_5_4_SHAKE_esk.PrivateKey.init),
            sig(SNOVA24_5_4_esk.algorithmName, SNOVA24_5_4_esk.PrivateKey.init),
            sig(SNOVA24_5_5.algorithmName, SNOVA24_5_5.PrivateKey.init),
            sig(SNOVA25_8_3.algorithmName, SNOVA25_8_3.PrivateKey.init),
            sig(SNOVA29_6_5.algorithmName, SNOVA29_6_5.PrivateKey.init),
            sig(SNOVA37_17_2.algorithmName, SNOVA37_17_2.PrivateKey.init),
            sig(SNOVA37_8_4.algorithmName, SNOVA37_8_4.PrivateKey.init),
            sig(SNOVA49_11_3.algorithmName, SNOVA49_11_3.PrivateKey.init),
            sig(SNOVA56_25_2.algorithmName, SNOVA56_25_2.PrivateKey.init),
            sig(SNOVA60_10_4.algorithmName, SNOVA60_10_4.PrivateKey.init),
            sig(OVIII.algorithmName, OVIII.PrivateKey.init),
            sig(OVIIIPKC.algorithmName, OVIIIPKC.PrivateKey.init),
            sig(OVIIIPKCSKC.algorithmName, OVIIIPKCSKC.PrivateKey.init),
            sig(OVIp.algorithmName, OVIp.PrivateKey.init),
            sig(OVIpPKC.algorithmName, OVIpPKC.PrivateKey.init),
            sig(OVIpPKCSKC.algorithmName, OVIpPKCSKC.PrivateKey.init),
            sig(OVIs.algorithmName, OVIs.PrivateKey.init),
            sig(OVIsPKC.algorithmName, OVIsPKC.PrivateKey.init),
            sig(OVIsPKCSKC.algorithmName, OVIsPKCSKC.PrivateKey.init),
            sig(OVV.algorithmName, OVV.PrivateKey.init),
            sig(OVVPKC.algorithmName, OVVPKC.PrivateKey.init),
            sig(OVVPKCSKC.algorithmName, OVVPKCSKC.PrivateKey.init),
        ]
    }
}
