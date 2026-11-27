/// What liboqs reports about one stateful hash-based signature scheme (XMSS, XMSS^MT or LMS).
///
/// Get one from ``Registry/statefulSignatureDescription(named:)``. The values
/// come from the liboqs `OQS_SIG_STFL` object of the scheme. The two strings
/// are copies of the static strings liboqs sets for it. liboqs keeps no NIST
/// level and no context support for these schemes, so there are none here.
public struct StatefulSignatureDescription: Sendable, Equatable, Hashable {
    /// The numeric identifier liboqs gives the parameter set.
    ///
    /// This is the XMSS or XMSS^MT OID, or the LMS type code, such as `0x0154` for `LMS_SHA256_H5_W8`.
    public let objectIdentifier: UInt32
    /// The liboqs name of the scheme, such as `LMS_SHA256_H5_W8`.
    ///
    /// This is always the name liboqs uses, whatever case the lookup was given.
    public let name: String
    /// The version of the implementation that liboqs reports, which for these schemes is the address of the RFC.
    public let algorithmVersion: String
    /// Whether the scheme is EUF-CMA secure.
    public let isEUFCMASecure: Bool
    /// Whether the scheme is SUF-CMA secure.
    public let isSUFCMASecure: Bool
    /// The length of a public key in bytes.
    public let publicKeyLength: Int
    /// The length of a secret key in bytes, in the form liboqs stores it.
    ///
    /// The `serializedSecretKey` of the typed private keys is longer, because it starts with the public key.
    public let secretKeyLength: Int
    /// The length of a signature in bytes.
    public let signatureLength: Int
}
