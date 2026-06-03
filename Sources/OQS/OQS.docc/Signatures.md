# Digital Signatures

Sign and verify messages using post-quantum signature algorithms.

## Overview

All signature algorithms follow the same pattern:

```swift
// Generate a signing key
let signingKey = try Falcon512.PrivateKey()

// Sign
let signature = try signingKey.signature(for: messageData)

// Verify
let valid = try signingKey.publicKey.isValidSignature(signature, for: messageData)
```

## Topics

### ML-DSA (FIPS 204)

- ``MLDSA44``
- ``MLDSA65``
- ``MLDSA87``

### Falcon

- ``Falcon512``
- ``Falcon1024``
- ``FalconPadded512``
- ``FalconPadded1024``

### SPHINCS+

- ``SPHINCSSHA2128fSimple``
- ``SPHINCSSHA2128sSimple``
- ``SPHINCSSHA2192fSimple``
- ``SPHINCSSHA2192sSimple``
- ``SPHINCSSHA2256fSimple``
- ``SPHINCSSHA2256sSimple``
- ``SPHINCSSHAKE128fSimple``
- ``SPHINCSSHAKE128sSimple``
- ``SPHINCSSHAKE192fSimple``
- ``SPHINCSSHAKE192sSimple``
- ``SPHINCSSHAKE256fSimple``
- ``SPHINCSSHAKE256sSimple``

### CROSS

- ``CrossRSDP128Balanced``
- ``CrossRSDP128Fast``
- ``CrossRSDP128Small``
- ``CrossRSDP192Balanced``
- ``CrossRSDP192Fast``
- ``CrossRSDP192Small``
- ``CrossRSDP256Balanced``
- ``CrossRSDP256Fast``
- ``CrossRSDP256Small``
- ``CrossRSDPG128Balanced``
- ``CrossRSDPG128Fast``
- ``CrossRSDPG128Small``
- ``CrossRSDPG192Balanced``
- ``CrossRSDPG192Fast``
- ``CrossRSDPG192Small``
- ``CrossRSDPG256Balanced``
- ``CrossRSDPG256Fast``
- ``CrossRSDPG256Small``

### SLH-DSA

- ``SLHDSAPureSHA2128s``
- ``SLHDSAPureSHA2128f``
- ``SLHDSAPureSHA2192s``
- ``SLHDSAPureSHA2192f``
- ``SLHDSAPureSHA2256s``
- ``SLHDSAPureSHA2256f``
- ``SLHDSAPureSHAKE128s``
- ``SLHDSAPureSHAKE128f``
- ``SLHDSAPureSHAKE192s``
- ``SLHDSAPureSHAKE192f``
- ``SLHDSAPureSHAKE256s``
- ``SLHDSAPureSHAKE256f``

### SLH-DSA Pre-Hash (FIPS 205)

For signing a message digest rather than the message itself, the ``SLHDSA``
namespace provides a single parameterized `SLHDSA.Prehash` type. Its
`PrivateKey(prehash:paramSet:)` initializer selects one of the 144 combinations
of pre-hash function (SHA2 / SHA3 / SHAKE) and SLH-DSA parameter set:

```swift
let signer = try SLHDSA.Prehash.PrivateKey(prehash: .sha2_256, paramSet: .sha2_128f)
```

- ``SLHDSA``

### MAYO

- ``MAYO1``
- ``MAYO2``
- ``MAYO3``
- ``MAYO5``

> ``MAYO5`` key generation allocates very large stack buffers and needs a
> thread with a multi-megabyte stack. Avoid generating it on a small-stack
> background thread.

### SNOVA

- ``SNOVA24_5_4``
- ``SNOVA24_5_4_SHAKE``
- ``SNOVA24_5_4_esk``
- ``SNOVA24_5_4_SHAKE_esk``
- ``SNOVA24_5_5``
- ``SNOVA25_8_3``
- ``SNOVA29_6_5``
- ``SNOVA37_8_4``
- ``SNOVA37_17_2``
- ``SNOVA49_11_3``
- ``SNOVA56_25_2``
- ``SNOVA60_10_4``

### UOV

- ``OVIs``
- ``OVIp``
- ``OVIII``
- ``OVV``
- ``OVIsPKC``
- ``OVIpPKC``
- ``OVIIIPKC``
- ``OVVPKC``
- ``OVIsPKCSKC``
- ``OVIpPKCSKC``
- ``OVIIIPKCSKC``
- ``OVVPKCSKC``

### Stateful Hash-Based Signatures

Stateful schemes (XMSS, XMSS^MT, LMS) consume a one-time key index on every
signature; reusing an index breaks security. Their `PrivateKey` is a reference
type that owns mutable key state, and signing takes a persist closure — a
signature is returned only once the advanced state has been durably stored. See
each type's docs for the full pattern and the keygen-cost warnings on large
parameter sets.

- ``XMSS``
- ``XMSSMT``
- ``LMS``
