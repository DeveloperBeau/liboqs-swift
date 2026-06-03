# ``OQS``

Post-quantum cryptography for Swift.

## Overview

Encryption that won't break when quantum computers arrive. Each algorithm is its own type with `PrivateKey` and `PublicKey`. Pick one and go.

### Key exchange

Two parties agree on a shared secret without ever sending it:

```swift
// Alice makes a key pair, shares her public key
let aliceKey = try MLKEM768.PrivateKey()

// Bob generates a shared secret locked to Alice's public key
let result = try alicePublicKey.generateSharedSecret()
// Bob keeps result.sharedSecret, sends result.ciphertext to Alice

// Alice unlocks it
let secret = try aliceKey.decryptSharedSecret(result.ciphertext)
// Both sides now have the same 32-byte secret
```

### Signatures

Prove a message came from you:

```swift
let signingKey = try Falcon512.PrivateKey()
let signature = try signingKey.signature(for: message)
let legit = try signingKey.publicKey.isValidSignature(signature, for: message)
```

## Why post-quantum?

RSA and elliptic curve encryption will break once quantum computers are powerful enough. Someone can record your traffic today and decrypt it later. That's called **harvest now, decrypt later**. If your data still matters in 10 years, it's already at risk.

The algorithms here use math that quantum computers can't crack. NIST picked them after 8 years of public evaluation.

## Why shared secrets?

Post-quantum keys are big and the algorithms are slow. You wouldn't want to encrypt a video stream with them.

So you do what TLS, Signal, and SSH all do: use a KEM to agree on a shared secret (32 bytes), then use that as an AES or ChaCha20 key. Symmetric encryption is fast and already quantum-safe. Best of both worlds.

## Topics

### Key Encapsulation

- ``MLKEM512``
- ``MLKEM768``
- ``MLKEM1024``
- ``FrodoKEM640AES``
- ``FrodoKEM976AES``
- ``FrodoKEM1344AES``
- ``NTRUHPS2048509``
- ``NTRUHRSS701``
- ``SNTRUP761``
- ``ClassicMcEliece348864``
- ``ClassicMcEliece460896``
- ``ClassicMcEliece6688128``
- ``ClassicMcEliece6960119``
- ``ClassicMcEliece8192128``
- ``HQC128``
- ``HQC192``
- ``HQC256``
- ``BIKEL1``
- ``BIKEL3``
- ``BIKEL5``

### Digital Signatures

- ``MLDSA44``
- ``MLDSA65``
- ``MLDSA87``
- ``Falcon512``
- ``Falcon1024``
- ``FalconPadded512``
- ``FalconPadded1024``
- ``SPHINCSSHA2128fSimple``
- ``SPHINCSSHA2256fSimple``
- ``SLHDSAPureSHA2128f``
- ``SLHDSA``
- ``CrossRSDP128Fast``
- ``MAYO1``
- ``SNOVA24_5_4``
- ``OVIs``

### Stateful Signatures

- ``XMSS``
- ``XMSSMT``
- ``LMS``

### Shared Types

- ``SharedSecret``
- ``SharedSecretResult``
- ``OQSError``
