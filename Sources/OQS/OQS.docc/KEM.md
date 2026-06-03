# Key Encapsulation

Establish shared secrets using post-quantum key encapsulation mechanisms.

## Overview

Key Encapsulation Mechanisms (KEMs) allow two parties to establish a shared secret. One party generates a key pair, the other generates a shared secret using the public key, and the first party decrypts it with their private key.

All KEM algorithms follow the same pattern:

```swift
// Generate a key pair
let privateKey = try MLKEM768.PrivateKey()

// Generate shared secret (sender side)
let result = try privateKey.publicKey.generateSharedSecret()
// result.ciphertext - send this to the key pair owner
// result.sharedSecret - the established secret

// Decrypt shared secret (receiver side)
let secret = try privateKey.decryptSharedSecret(result.ciphertext)
// secret == result.sharedSecret
```

### Using the Shared Secret

The shared secret is a cryptographic key that both parties now hold. Common uses:

- **Encrypt messages:** Use it as an AES-GCM or ChaCha20 key to encrypt data between the parties.
- **Derive multiple keys:** Feed it into a key derivation function (like HKDF) to create
  separate keys for encryption, authentication, etc.
- **Establish a secure channel:** Use it as the session key for an encrypted communication protocol.

```swift
// Example: Use the shared secret as an AES-GCM key
let symmetricKey = SymmetricKey(data: sharedSecret.rawRepresentation)
let encrypted = try AES.GCM.seal(plaintext, using: symmetricKey)
```

> The shared secret should be used immediately or stored securely.
> Never transmit it. The entire point of key encapsulation is that
> both parties derive it independently.

### Key Import and Export

Keys can be exported and imported using raw byte representations:

```swift
// Export
let keyData = privateKey.rawRepresentation
let pubData = privateKey.publicKey.rawRepresentation

// Import
let imported = try MLKEM768.PrivateKey(
    rawRepresentation: keyData,
    publicKeyRepresentation: pubData
)
let importedPub = try MLKEM768.PublicKey(rawRepresentation: pubData)
```

## Topics

### ML-KEM (FIPS 203)

- ``MLKEM512``
- ``MLKEM768``
- ``MLKEM1024``

### FrodoKEM

- ``FrodoKEM640AES``
- ``FrodoKEM640SHAKE``
- ``FrodoKEM976AES``
- ``FrodoKEM976SHAKE``
- ``FrodoKEM1344AES``
- ``FrodoKEM1344SHAKE``

### NTRU

- ``NTRUHPS2048509``
- ``NTRUHPS2048677``
- ``NTRUHPS4096821``
- ``NTRUHPS40961229``
- ``NTRUHRSS701``
- ``NTRUHRSS1373``

### NTRU Prime

- ``SNTRUP761``

### HQC

- ``HQC128``
- ``HQC192``
- ``HQC256``

### Classic McEliece

The `…f` variants use the same parameters with faster key generation.

- ``ClassicMcEliece348864``
- ``ClassicMcEliece348864f``
- ``ClassicMcEliece460896``
- ``ClassicMcEliece460896f``
- ``ClassicMcEliece6688128``
- ``ClassicMcEliece6688128f``
- ``ClassicMcEliece6960119``
- ``ClassicMcEliece6960119f``
- ``ClassicMcEliece8192128``
- ``ClassicMcEliece8192128f``

### BIKE

- ``BIKEL1``
- ``BIKEL3``
- ``BIKEL5``

### Kyber (Deprecated)

Kyber predates the final ML-KEM standard and is deprecated. Use the ``MLKEM512`` / ``MLKEM768`` / ``MLKEM1024`` types instead.

- ``Kyber512``
- ``Kyber768``
- ``Kyber1024``
