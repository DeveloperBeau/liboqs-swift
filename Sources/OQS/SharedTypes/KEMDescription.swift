/// What liboqs reports about one key encapsulation mechanism.
///
/// Get one from ``Registry/kemDescription(named:)``. The values come from the
/// liboqs `OQS_KEM` object of the mechanism. The two strings are copies of the
/// static strings liboqs sets for it.
public struct KEMDescription: Sendable, Equatable, Hashable {
    /// The liboqs name of the mechanism, such as `ML-KEM-768`.
    ///
    /// This is always the name liboqs uses, whatever case the lookup was given.
    public let name: String
    /// The version of the implementation that liboqs reports, such as `FIPS203`.
    public let algorithmVersion: String
    /// The NIST security level, 1 to 5, that the original submission claims.
    public let claimedNISTLevel: Int
    /// Whether the mechanism is IND-CCA secure.
    ///
    /// When this is false the mechanism is only IND-CPA secure.
    public let isINDCCASecure: Bool
    /// The length of a public key in bytes.
    public let publicKeyLength: Int
    /// The length of a secret key in bytes.
    public let secretKeyLength: Int
    /// The length of a ciphertext in bytes.
    public let ciphertextLength: Int
    /// The length of a shared secret in bytes.
    public let sharedSecretLength: Int
    /// The length in bytes of the seed for seeded key pair generation.
    ///
    /// This is 0 when the mechanism has no seeded key pair generation.
    public let keyPairSeedLength: Int
    /// The length in bytes of the seed for seeded encapsulation.
    ///
    /// This is 0 when the mechanism has no seeded encapsulation.
    public let encapsulationSeedLength: Int
}
