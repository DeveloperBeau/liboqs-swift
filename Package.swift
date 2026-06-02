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

    // UOV (requires OpenSSL, disabled)
    "src/sig/uov",

    // MAYO (each variant needs different compile-time params, incompatible with SPM)
    "src/sig/mayo",

    // CUDA/Icicle GPU
    "src/kem/ml_kem/cupqc_ml-kem-512_cuda",
    "src/kem/ml_kem/cupqc_ml-kem-768_cuda",
    "src/kem/ml_kem/cupqc_ml-kem-1024_cuda",
    "src/kem/ml_kem/icicle_ml-kem-512_icicle_cuda",
    "src/kem/ml_kem/icicle_ml-kem-768_icicle_cuda",
    "src/kem/ml_kem/icicle_ml-kem-1024_icicle_cuda",

    // BIKE disabled in oqsconfig.h (per-level compile defs)
    "src/kem/bike",

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

    // Stateful signatures (disabled)
    "src/sig_stfl",
]

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
            path: "Sources/Cliboqs",
            exclude: cliboqsExclude,
            publicHeadersPath: "include",
            cSettings: [
                .define("OQS_DIST_BUILD", to: "1"),
                .define("OQS_HAVE_POSIX_MEMALIGN", to: "1", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .linux, .android])),
                .define("SNOVA_LIBOQS", to: "1"),
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
