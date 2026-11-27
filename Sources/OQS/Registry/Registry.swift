internal import Cliboqs

/// The algorithms this build of liboqs enables, with their names and what liboqs reports about each one.
///
/// Every name list comes from the liboqs identifier list of its kind, filtered
/// by the liboqs enabled check, in liboqs order.
///
/// Name matching follows liboqs. Case is ignored for the ASCII letters A to Z
/// only. Every other byte must be equal, and the lengths must be equal. So
/// `ml-kem-768` matches `ML-KEM-768`, and `ML-KEM-768 ` does not. A
/// non-ASCII character never matches an ASCII letter. A name that holds a NUL
/// byte never matches.
///
/// ```swift
/// for name in Registry.enabledKEMNames {
///     print(name)
/// }
/// if let kem = Registry.kemDescription(named: "ml-kem-768") {
///     print(kem.name, kem.ciphertextLength)   // ML-KEM-768 1088
/// }
/// ```
public enum Registry {
    /// The names of the key encapsulation mechanisms this build enables, in liboqs order.
    public static let enabledKEMNames: [String] = {
        ensureInitialized()
        return enabledNames(
            count: Int(OQS_KEM_alg_count()),
            identifierAt: { OQS_KEM_alg_identifier($0).map { String(cString: $0) } },
            isEnabled: { OQS_KEM_alg_is_enabled($0) == 1 })
    }()

    /// The names of the stateless signature schemes this build enables, in liboqs order.
    public static let enabledSignatureNames: [String] = {
        ensureInitialized()
        return enabledNames(
            count: Int(OQS_SIG_alg_count()),
            identifierAt: { OQS_SIG_alg_identifier($0).map { String(cString: $0) } },
            isEnabled: { OQS_SIG_alg_is_enabled($0) == 1 })
    }()

    /// The names of the stateful signature schemes (XMSS, XMSS^MT and LMS) this build enables, in liboqs order.
    public static let enabledStatefulSignatureNames: [String] = {
        ensureInitialized()
        return enabledNames(
            count: Int(OQS_SIG_STFL_alg_count()),
            identifierAt: { OQS_SIG_STFL_alg_identifier($0).map { String(cString: $0) } },
            isEnabled: { OQS_SIG_STFL_alg_is_enabled($0) == 1 })
    }()

    /// Whether `name` is the liboqs name of a key encapsulation mechanism this build enables, ignoring ASCII case.
    public static func isKEMEnabled(_ name: String) -> Bool {
        AlgorithmNameMatching.listedName(matching: name, in: enabledKEMNames) != nil
    }

    /// Whether `name` is the liboqs name of a stateless signature scheme this build enables, ignoring ASCII case.
    public static func isSignatureEnabled(_ name: String) -> Bool {
        AlgorithmNameMatching.listedName(matching: name, in: enabledSignatureNames) != nil
    }

    /// Whether `name` is the liboqs name of a stateful signature scheme this build enables, ignoring ASCII case.
    public static func isStatefulSignatureEnabled(_ name: String) -> Bool {
        AlgorithmNameMatching.listedName(matching: name, in: enabledStatefulSignatureNames) != nil
    }

    /// What liboqs reports about the key encapsulation mechanism named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns nil when `name` is not the name of an enabled
    /// mechanism, or when liboqs cannot allocate its algorithm object.
    public static func kemDescription(named name: String) -> KEMDescription? {
        guard let listed = AlgorithmNameMatching.listedName(matching: name, in: enabledKEMNames) else { return nil }
        ensureInitialized()
        guard let kem = OQS_KEM_new(listed) else { return nil }
        defer { OQS_KEM_free(kem) }
        let k = kem.pointee
        return KEMDescription(
            name: String(cString: k.method_name),
            algorithmVersion: String(cString: k.alg_version),
            claimedNISTLevel: Int(k.claimed_nist_level),
            isINDCCASecure: k.ind_cca,
            publicKeyLength: Int(k.length_public_key),
            secretKeyLength: Int(k.length_secret_key),
            ciphertextLength: Int(k.length_ciphertext),
            sharedSecretLength: Int(k.length_shared_secret),
            keyPairSeedLength: Int(k.length_keypair_seed),
            encapsulationSeedLength: Int(k.length_encaps_seed))
    }

    /// What liboqs reports about the stateless signature scheme named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns nil when `name` is not the name of an enabled
    /// scheme, or when liboqs cannot allocate its algorithm object.
    public static func signatureDescription(named name: String) -> SignatureDescription? {
        guard let listed = AlgorithmNameMatching.listedName(matching: name, in: enabledSignatureNames) else { return nil }
        ensureInitialized()
        guard let sig = OQS_SIG_new(listed) else { return nil }
        defer { OQS_SIG_free(sig) }
        let s = sig.pointee
        return SignatureDescription(
            name: String(cString: s.method_name),
            algorithmVersion: String(cString: s.alg_version),
            claimedNISTLevel: Int(s.claimed_nist_level),
            isEUFCMASecure: s.euf_cma,
            isSUFCMASecure: s.suf_cma,
            supportsContext: sigSupportsContext(sig),
            publicKeyLength: Int(s.length_public_key),
            secretKeyLength: Int(s.length_secret_key),
            signatureLength: Int(s.length_signature))
    }

    /// What liboqs reports about the stateful signature scheme named `name`.
    ///
    /// `name` matches ignoring ASCII case, and the description carries the
    /// liboqs name. Returns nil when `name` is not the name of an enabled
    /// scheme, or when liboqs cannot allocate its algorithm object.
    public static func statefulSignatureDescription(named name: String) -> StatefulSignatureDescription? {
        guard let listed = AlgorithmNameMatching.listedName(matching: name, in: enabledStatefulSignatureNames) else { return nil }
        ensureInitialized()
        guard let sig = OQS_SIG_STFL_new(listed) else { return nil }
        defer { OQS_SIG_STFL_free(sig) }
        let s = sig.pointee
        return StatefulSignatureDescription(
            objectIdentifier: s.oid,
            name: String(cString: s.method_name),
            algorithmVersion: String(cString: s.alg_version),
            isEUFCMASecure: s.euf_cma,
            isSUFCMASecure: s.suf_cma,
            publicKeyLength: Int(s.length_public_key),
            secretKeyLength: Int(s.length_secret_key),
            signatureLength: Int(s.length_signature))
    }

    /// The identifiers at positions 0 to `count - 1` that `isEnabled` accepts, in order.
    ///
    /// The liboqs list functions are passed in, so a test can show with
    /// stand-ins that a disabled name is left out. Every liboqs name is
    /// enabled in this build, so the real lists cannot show that.
    static func enabledNames(
        count: Int,
        identifierAt: (Int) -> String?,
        isEnabled: (String) -> Bool
    ) -> [String] {
        (0..<count).compactMap(identifierAt).filter(isEnabled)
    }
}
