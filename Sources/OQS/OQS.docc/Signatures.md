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
