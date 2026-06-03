// swift-tools-version: 6.3

import PackageDescription

let experimentalFeatures: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableExperimentalFeature("StrictConcurrency"),
    .enableExperimentalFeature("AccessLevelOnImport"),
    .enableExperimentalFeature("BitwiseCopyable"),
    .enableExperimentalFeature("MoveOnlyTypes"),
    .enableExperimentalFeature("LifetimeDependence"),
]

// Platform-specific optimized implementations excluded from the portable build.
// Only reference/portable C implementations are compiled.
let cliboqsExclude: [String] = [
    // Platform-specific common files
    "src/common/aes/aes128_ni.c",
    "src/common/aes/aes256_ni.c",
    "src/common/aes/aes128_armv8.c",
    "src/common/aes/aes256_armv8.c",
    "src/common/aes/aes_ossl.c",
    "src/common/sha2/sha2_armv8.c",

    // AVX2/AVX512/x86_64 optimized
    "src/common/sha3/avx512vl_low",
    "src/common/sha3/avx512vl_sha3.c",
    "src/common/sha3/avx512vl_sha3x4.c",
    "src/common/sha3/xkcp_low/KeccakP-1600/avx2",
    "src/common/sha3/xkcp_low/KeccakP-1600times4/avx2",
    "src/kem/classic_mceliece/pqclean_mceliece348864_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece348864f_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece460896_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece460896f_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece6688128_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece6688128f_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece6960119_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece6960119f_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece8192128_avx2",
    "src/kem/classic_mceliece/pqclean_mceliece8192128f_avx2",
    "src/kem/kyber/pqcrystals-kyber_kyber512_avx2",
    "src/kem/kyber/pqcrystals-kyber_kyber768_avx2",
    "src/kem/kyber/pqcrystals-kyber_kyber1024_avx2",
    "src/kem/ml_kem/mlkem-native_ml-kem-512_x86_64",
    "src/kem/ml_kem/mlkem-native_ml-kem-768_x86_64",
    "src/kem/ml_kem/mlkem-native_ml-kem-1024_x86_64",
    "src/kem/ntru/pqclean_ntruhps2048509_avx2",
    "src/kem/ntru/pqclean_ntruhps2048677_avx2",
    "src/kem/ntru/pqclean_ntruhps4096821_avx2",
    "src/kem/ntru/pqclean_ntruhrss701_avx2",
    "src/kem/ntruprime/pqclean_sntrup761_avx2",
    "src/sig/cross/upcross_cross-rsdp-128-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdp-128-fast_avx2",
    "src/sig/cross/upcross_cross-rsdp-128-small_avx2",
    "src/sig/cross/upcross_cross-rsdp-192-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdp-192-fast_avx2",
    "src/sig/cross/upcross_cross-rsdp-192-small_avx2",
    "src/sig/cross/upcross_cross-rsdp-256-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdp-256-fast_avx2",
    "src/sig/cross/upcross_cross-rsdp-256-small_avx2",
    "src/sig/cross/upcross_cross-rsdpg-128-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdpg-128-fast_avx2",
    "src/sig/cross/upcross_cross-rsdpg-128-small_avx2",
    "src/sig/cross/upcross_cross-rsdpg-192-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdpg-192-fast_avx2",
    "src/sig/cross/upcross_cross-rsdpg-192-small_avx2",
    "src/sig/cross/upcross_cross-rsdpg-256-balanced_avx2",
    "src/sig/cross/upcross_cross-rsdpg-256-fast_avx2",
    "src/sig/cross/upcross_cross-rsdpg-256-small_avx2",
    "src/sig/falcon/pqclean_falcon-512_avx2",
    "src/sig/falcon/pqclean_falcon-1024_avx2",
    "src/sig/falcon/pqclean_falcon-padded-512_avx2",
    "src/sig/falcon/pqclean_falcon-padded-1024_avx2",
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-44_avx2",
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_avx2",
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-87_avx2",
    "src/sig/snova/snova_SNOVA_24_5_4_avx2",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_avx2",
    "src/sig/snova/snova_SNOVA_24_5_4_esk_avx2",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_esk_avx2",
    "src/sig/snova/snova_SNOVA_24_5_5_avx2",
    "src/sig/snova/snova_SNOVA_25_8_3_avx2",
    "src/sig/snova/snova_SNOVA_29_6_5_avx2",
    "src/sig/snova/snova_SNOVA_37_17_2_avx2",
    "src/sig/snova/snova_SNOVA_37_8_4_avx2",
    "src/sig/snova/snova_SNOVA_49_11_3_avx2",
    "src/sig/snova/snova_SNOVA_56_25_2_avx2",
    "src/sig/snova/snova_SNOVA_60_10_4_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-128f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-128s-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-192f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-192s-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-256f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-sha2-256s-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-128f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-128s-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-192f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-192s-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-256f-simple_avx2",
    "src/sig/sphincs/pqclean_sphincs-shake-256s-simple_avx2",
    // AArch64/NEON optimized
    "src/kem/kyber/oldpqclean_kyber512_aarch64",
    "src/kem/kyber/oldpqclean_kyber768_aarch64",
    "src/kem/kyber/oldpqclean_kyber1024_aarch64",
    "src/kem/ml_kem/mlkem-native_ml-kem-512_aarch64",
    "src/kem/ml_kem/mlkem-native_ml-kem-768_aarch64",
    "src/kem/ml_kem/mlkem-native_ml-kem-1024_aarch64",
    "src/sig/falcon/pqclean_falcon-512_aarch64",
    "src/sig/falcon/pqclean_falcon-1024_aarch64",
    "src/sig/falcon/pqclean_falcon-padded-512_aarch64",
    "src/sig/falcon/pqclean_falcon-padded-1024_aarch64",
    "src/sig/snova/snova_SNOVA_24_5_4_neon",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_neon",
    "src/sig/snova/snova_SNOVA_24_5_4_esk_neon",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_esk_neon",
    "src/sig/snova/snova_SNOVA_24_5_5_neon",
    "src/sig/snova/snova_SNOVA_25_8_3_neon",
    "src/sig/snova/snova_SNOVA_29_6_5_neon",
    "src/sig/snova/snova_SNOVA_37_17_2_neon",
    "src/sig/snova/snova_SNOVA_37_8_4_neon",
    "src/sig/snova/snova_SNOVA_49_11_3_neon",
    "src/sig/snova/snova_SNOVA_56_25_2_neon",
    "src/sig/snova/snova_SNOVA_60_10_4_neon",
    // SNOVA: each _opt dir is compiled via its generated unity TU; the
    // sig_snova_SNOVA_*.c glue compiles normally.
    "src/sig/snova/snova_SNOVA_24_5_4_opt",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_opt",
    "src/sig/snova/snova_SNOVA_24_5_4_esk_opt",
    "src/sig/snova/snova_SNOVA_24_5_4_SHAKE_esk_opt",
    "src/sig/snova/snova_SNOVA_24_5_5_opt",
    "src/sig/snova/snova_SNOVA_25_8_3_opt",
    "src/sig/snova/snova_SNOVA_29_6_5_opt",
    "src/sig/snova/snova_SNOVA_37_8_4_opt",
    "src/sig/snova/snova_SNOVA_37_17_2_opt",
    "src/sig/snova/snova_SNOVA_49_11_3_opt",
    "src/sig/snova/snova_SNOVA_56_25_2_opt",
    "src/sig/snova/snova_SNOVA_60_10_4_opt",

    // ML-DSA: each _ref dir is compiled via its generated unity TU. Excluding
    // a dir stops SPM compiling its .c as separate TUs; the files stay on disk
    // so the unity #include reaches them. The sig_ml_dsa_*.c glue compiles
    // normally (sig.c references each variant's _new() under #ifdef).
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-44_ref",
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref",
    "src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-87_ref",

    // UOV: each _ref dir is compiled via its generated unity TU (which bakes in
    // the param triple + backend + _UTILS_OQS_ defines); the raw variant dirs
    // are excluded so SPM does not compile their .c as separate TUs, and the
    // avx2/neon dirs are unused. The sig_uov_ov_*.c glue compiles normally.
    "src/sig/uov/pqov_ov_Is_ref",
    "src/sig/uov/pqov_ov_Is_avx2",
    "src/sig/uov/pqov_ov_Is_neon",
    "src/sig/uov/pqov_ov_Ip_ref",
    "src/sig/uov/pqov_ov_Ip_avx2",
    "src/sig/uov/pqov_ov_Ip_neon",
    "src/sig/uov/pqov_ov_III_ref",
    "src/sig/uov/pqov_ov_III_avx2",
    "src/sig/uov/pqov_ov_III_neon",
    "src/sig/uov/pqov_ov_V_ref",
    "src/sig/uov/pqov_ov_V_avx2",
    "src/sig/uov/pqov_ov_V_neon",
    "src/sig/uov/pqov_ov_Is_pkc_ref",
    "src/sig/uov/pqov_ov_Is_pkc_avx2",
    "src/sig/uov/pqov_ov_Is_pkc_neon",
    "src/sig/uov/pqov_ov_Ip_pkc_ref",
    "src/sig/uov/pqov_ov_Ip_pkc_avx2",
    "src/sig/uov/pqov_ov_Ip_pkc_neon",
    "src/sig/uov/pqov_ov_III_pkc_ref",
    "src/sig/uov/pqov_ov_III_pkc_avx2",
    "src/sig/uov/pqov_ov_III_pkc_neon",
    "src/sig/uov/pqov_ov_V_pkc_ref",
    "src/sig/uov/pqov_ov_V_pkc_avx2",
    "src/sig/uov/pqov_ov_V_pkc_neon",
    "src/sig/uov/pqov_ov_Is_pkc_skc_ref",
    "src/sig/uov/pqov_ov_Is_pkc_skc_avx2",
    "src/sig/uov/pqov_ov_Is_pkc_skc_neon",
    "src/sig/uov/pqov_ov_Ip_pkc_skc_ref",
    "src/sig/uov/pqov_ov_Ip_pkc_skc_avx2",
    "src/sig/uov/pqov_ov_Ip_pkc_skc_neon",
    "src/sig/uov/pqov_ov_III_pkc_skc_ref",
    "src/sig/uov/pqov_ov_III_pkc_skc_avx2",
    "src/sig/uov/pqov_ov_III_pkc_skc_neon",
    "src/sig/uov/pqov_ov_V_pkc_skc_ref",
    "src/sig/uov/pqov_ov_V_pkc_skc_avx2",
    "src/sig/uov/pqov_ov_V_pkc_skc_neon",

    // MAYO opt variants build as their own SPM sub-targets (CliboqsMAYO{1,2,3,5})
    // so each variant's angle-included variant-local headers (mayo.h, api.h,
    // params.h, ...) resolve against its OWN directory. Excluded here so the main
    // Cliboqs target does not also compile them (SPM requires a dir be owned by
    // exactly one target); the avx2/neon dirs are unused.
    "src/sig/mayo/pqmayo_mayo-1_opt",
    "src/sig/mayo/pqmayo_mayo-2_opt",
    "src/sig/mayo/pqmayo_mayo-3_opt",
    "src/sig/mayo/pqmayo_mayo-5_opt",
    "src/sig/mayo/pqmayo_mayo-1_avx2",
    "src/sig/mayo/pqmayo_mayo-2_avx2",
    "src/sig/mayo/pqmayo_mayo-3_avx2",
    "src/sig/mayo/pqmayo_mayo-5_avx2",
    "src/sig/mayo/pqmayo_mayo-1_neon",
    "src/sig/mayo/pqmayo_mayo-2_neon",
    "src/sig/mayo/pqmayo_mayo-3_neon",
    "src/sig/mayo/pqmayo_mayo-5_neon",

    // CUDA/Icicle GPU
    "src/kem/ml_kem/cupqc_ml-kem-512_cuda",
    "src/kem/ml_kem/cupqc_ml-kem-768_cuda",
    "src/kem/ml_kem/cupqc_ml-kem-1024_cuda",
    "src/kem/ml_kem/icicle_ml-kem-512_icicle_cuda",
    "src/kem/ml_kem/icicle_ml-kem-768_icicle_cuda",
    "src/kem/ml_kem/icicle_ml-kem-1024_icicle_cuda",

    // BIKE: raw sources compiled via per-level unity TUs (unity_bike_l*.c);
    // exclude the raw dir so SPM does not compile its files separately.
    "src/kem/bike/additional_r4",

    // FrodoKEM: files that are textually #included by other .c files
    "src/kem/frodokem/external/noise.c",
    "src/kem/frodokem/external/util.c",
    "src/kem/frodokem/external/kem.c",
    "src/kem/frodokem/external/frodo_macrify_aes_portable.c",
    "src/kem/frodokem/external/frodo_macrify_aes_avx2.c",
    "src/kem/frodokem/external/frodo_macrify_shake_portable.c",
    "src/kem/frodokem/external/frodo_macrify_shake_avx2.c",
    "src/kem/frodokem/external/frodo_macrify_optimized.c",
    "src/kem/frodokem/external/frodo_macrify_reference.c",
    "src/kem/frodokem/external/frodo_macrify_as_plus_e.c",
    // FrodoKEM AVX2 variants
    "src/kem/frodokem/external/frodo640aes_avx2.c",
    "src/kem/frodokem/external/frodo640shake_avx2.c",
    "src/kem/frodokem/external/frodo976aes_avx2.c",
    "src/kem/frodokem/external/frodo976shake_avx2.c",
    "src/kem/frodokem/external/frodo1344aes_avx2.c",
    "src/kem/frodokem/external/frodo1344shake_avx2.c",

    // Kyber: each _ref dir is compiled via its generated unity TU; the
    // kem_kyber_*.c glue compiles normally. Non-portable variants (libjade,
    // oldpqclean aarch64, avx2) are excluded. (avx2 + oldpqclean aarch64 dirs
    // are also listed in the SIMD/AArch64 blocks above.)
    "src/kem/kyber/pqcrystals-kyber_kyber512_ref",
    "src/kem/kyber/pqcrystals-kyber_kyber768_ref",
    "src/kem/kyber/pqcrystals-kyber_kyber1024_ref",
    "src/kem/kyber/libjade_kyber512_ref",
    "src/kem/kyber/libjade_kyber768_ref",
    "src/kem/kyber/libjade_kyber512_avx2",
    "src/kem/kyber/libjade_kyber768_avx2",

    // Libjade
    "src/common/libjade_shims",

    // Stateful signatures (XMSS/XMSSMT/LMS).
    //
    // XMSS/XMSSMT: each variant is compiled via a generated per-variant unity TU
    // (unity_sig_stfl_xmss_*.c / unity_sig_stfl_xmssmt_*.c) that bakes in the
    // variant's XMSS_PARAMS_NAMESPACE + HASH (extracted from upstream CMake) and
    // #includes its variant file, sig_stfl_xmss[mt]_functions.c, and the shared
    // external/ sources. The shared external sources, the namespaced functions.c
    // files, and the macro-only sig_stfl_xmss_xmssmt.c are excluded here so SPM
    // does not compile them as separate TUs (they have no fixed namespace on
    // their own). sig_stfl_xmss_secret_key_functions.c is NOT namespaced and
    // compiles once normally; the top-level glue (sig_stfl.c) compiles normally.
    "src/sig_stfl/xmss/external",
    "src/sig_stfl/xmss/sig_stfl_xmss_functions.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_functions.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_xmssmt.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h10_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h16_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h16.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h20_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h20.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha512_h10.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha512_h16.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha512_h20.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake128_h10.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake128_h16.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake128_h20.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h10_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h10_256.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h10.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h16_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h16_256.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h16.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h20_192.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h20_256.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_shake256_h20.c",
    "src/sig_stfl/xmss/sig_stfl_xmss_sha256_h10.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h20_2.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h20_4.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h40_2.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h40_4.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h40_8.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h60_12.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h60_3.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_sha256_h60_6.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h20_2.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h20_4.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h40_2.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h40_4.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h40_8.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h60_12.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h60_3.c",
    "src/sig_stfl/xmss/sig_stfl_xmssmt_shake128_h60_6.c",

    // LMS: 33 variants are runtime-selected from one object set (no per-variant
    // compile flags), so the whole lms/ dir compiles normally. Only exclude
    // hss_thread_pthread.c — it is the pthread thread backend NOT in upstream's
    // CMake SRCS (which uses hss_thread_single.c); compiling both would define
    // duplicate hss_thread_* symbols.
    "src/sig_stfl/lms/external/hss_thread_pthread.c",
]

// Each MAYO opt variant is compiled as its own C target so that the variant's
// angle-included, variant-local headers (mayo.h, api.h, params.h, ...) resolve
// against its OWN directory (".") instead of colliding on a shared flat include
// path — different variants ship api.h/params.h with different parameter sizes.
// The per-variant -D parameter set + header search path mirror what liboqs's
// CMake supplies, re-rooted relative to the variant dir. This keeps the upstream
// MAYO sources byte-pristine (no include rewriting). MAYO-2 is the only variant
// that omits HAVE_STACKEFFICIENT. Paths: from pqmayo_mayo-N_opt, ../../.. = src,
// ../../../.. = Sources/Cliboqs, ../../../../include = Sources/Cliboqs/include.
func mayoTarget(name: String, variantDir: String, variantMacro: String, stackEfficient: Bool) -> Target {
    var defines: [CSetting] = [
        .define("MAYO_VARIANT", to: variantMacro),
        .define("MAYO_BUILD_TYPE_OPT"),
        .define("HAVE_RANDOMBYTES_NORETVAL"),
    ]
    if stackEfficient {
        defines.append(.define("HAVE_STACKEFFICIENT"))
    }
    return .target(
        name: name,
        path: "Sources/Cliboqs/src/sig/mayo/\(variantDir)",
        // The glue (sig_mayo_*.c) calls into each variant via `extern` decls, not
        // via these headers, so nothing imports these as Clang modules. "." is
        // only here to satisfy SPM's C-target requirement; it cannot be an empty
        // subdir (would break the pristine diff) or a path outside the target.
        publicHeadersPath: ".",
        cSettings: defines + [
            // pqclean_shims first (its aes.h/fips202.h/randombytes.h shims must
            // win over the internal common ones), then "." so this variant's own
            // mayo.h/api.h/params.h resolve before anything else.
            .headerSearchPath("../../../common/pqclean_shims"),
            .headerSearchPath("."),
            .headerSearchPath("../../.."),                 // src/
            .headerSearchPath("../../../common"),
            .headerSearchPath("../../../common/sha3"),
            .headerSearchPath("../../../common/sha3/xkcp_low/KeccakP-1600/plain-64bits"),
            .headerSearchPath("../../../common/rand"),
            .headerSearchPath("../../../../include"),       // Sources/Cliboqs/include for <oqs/...>
        ]
    )
}

let package = Package(
    name: "liboqs-swift",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "OQS", targets: ["OQS"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
    ],
    targets: [
        .target(
            name: "Cliboqs",
            dependencies: [
                "CliboqsMAYO1",
                "CliboqsMAYO2",
                "CliboqsMAYO3",
                "CliboqsMAYO5",
            ],
            path: "Sources/Cliboqs",
            exclude: cliboqsExclude,
            publicHeadersPath: "include",
            cSettings: [
                .define("OQS_DIST_BUILD", to: "1"),
                .define("OQS_HAVE_POSIX_MEMALIGN", to: "1", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .linux, .android])),
                .define("SNOVA_LIBOQS", to: "1"),
                // NOTE: the stateful-signature opt-in macros
                // (OQS_ALLOW_{STFL,XMSS,LMS}_KEY_AND_SIG_GEN) are defined in
                // oqsconfig.h, NOT here — sig_stfl.h gates the OQS_SIG_STFL struct
                // layout on OQS_ALLOW_STFL_KEY_AND_SIG_GEN, so the macro must be
                // visible to the Swift clang importer (which does not see C-target
                // -D flags), otherwise the importer parses a stub struct and reads
                // length_* fields at the wrong offsets.
                // pqclean_shims must come first so its sha2.h/sha3.h shims
                // are found before the internal common/sha2/sha2.h etc.
                .headerSearchPath("src/common/pqclean_shims"),
                .headerSearchPath("src"),
                .headerSearchPath("src/common"),
                .headerSearchPath("src/common/aes"),
                .headerSearchPath("src/common/sha2"),
                .headerSearchPath("src/common/sha3"),
                .headerSearchPath("src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits"),
                .headerSearchPath("src/common/sha3/xkcp_low/KeccakP-1600times4/serial"),
                .headerSearchPath("src/common/rand"),
                .headerSearchPath("src/kem"),
                .headerSearchPath("src/sig"),
                .headerSearchPath("src/sig_stfl"),
                .headerSearchPath("include"),
            ]
        ),
        mayoTarget(name: "CliboqsMAYO1", variantDir: "pqmayo_mayo-1_opt", variantMacro: "MAYO_1", stackEfficient: true),
        mayoTarget(name: "CliboqsMAYO2", variantDir: "pqmayo_mayo-2_opt", variantMacro: "MAYO_2", stackEfficient: false),
        mayoTarget(name: "CliboqsMAYO3", variantDir: "pqmayo_mayo-3_opt", variantMacro: "MAYO_3", stackEfficient: true),
        mayoTarget(name: "CliboqsMAYO5", variantDir: "pqmayo_mayo-5_opt", variantMacro: "MAYO_5", stackEfficient: true),
        .target(
            name: "OQS",
            dependencies: ["Cliboqs"],
            swiftSettings: experimentalFeatures
        ),
        .testTarget(
            name: "OQSTests",
            dependencies: ["OQS"],
            resources: [.copy("Vectors")],
            swiftSettings: experimentalFeatures
        ),
    ]
)
