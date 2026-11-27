/// What liboqs reports about one stateless signature scheme.
///
/// Get one from ``Registry/signatureDescription(named:)``. The values come
/// from the liboqs `OQS_SIG` object of the scheme. The two strings are copies
/// of the static strings liboqs sets for it.
public struct SignatureDescription: Sendable, Equatable, Hashable {
    /// The liboqs name of the scheme, such as `ML-DSA-65`.
    ///
    /// This is always the name liboqs uses, whatever case the lookup was given.
    public let name: String
    /// The version of the implementation that liboqs reports, such as `FIPS204`.
    public let algorithmVersion: String
    /// The NIST security level, 1 to 5, that the original submission claims.
    public let claimedNISTLevel: Int
    /// Whether the scheme is EUF-CMA secure.
    public let isEUFCMASecure: Bool
    /// Whether the scheme is SUF-CMA secure.
    public let isSUFCMASecure: Bool
    /// Whether liboqs signs and verifies with a caller-given context string for this scheme.
    public let supportsContext: Bool
    /// The length of a public key in bytes.
    public let publicKeyLength: Int
    /// The length of a secret key in bytes.
    public let secretKeyLength: Int
    /// The largest length of a signature in bytes.
    ///
    /// Some schemes make shorter signatures. This is the size liboqs reserves for one.
    public let signatureLength: Int
}
