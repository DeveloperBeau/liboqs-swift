# liboqs-swift

[![CI](https://github.com/DeveloperBeau/liboqs-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/DeveloperBeau/liboqs-swift/actions/workflows/ci.yml)

Post-quantum cryptography for Swift, powered by [liboqs](https://github.com/open-quantum-safe/liboqs).

## Features

- Type-safe Swift API for key encapsulation and digital signatures
- Vendored liboqs C source, no system dependencies. Just add the package
- Swift 6 strict concurrency (`Sendable` throughout)
- macOS, Linux, Windows, and Android

## Why post-quantum?

Most encryption today (RSA, elliptic curves) will break once quantum computers get powerful enough. That's not science fiction. It's a question of when, not if.

The real problem is **harvest now, decrypt later**. Someone can record your encrypted traffic today and just wait. Once they have a quantum computer, they decrypt everything. If your data matters in 10 years, it's already at risk.

The algorithms in this library are built on math that quantum computers can't crack:

| Family | What makes it hard | Used for |
|---|---|---|
| **ML-KEM** | Lattice problems | Key exchange |
| **Classic McEliece** | Error-correcting codes (studied for 50+ years) | Key exchange |
| **HQC** | Error-correcting codes | Key exchange |
| **Falcon** | Lattice problems | Signatures |
| **SPHINCS+ / SLH-DSA** | Just hash functions, no fancy math to break | Signatures |
| **CROSS** | Error-correcting codes | Signatures |

NIST picked these after 8 years of public evaluation. They're the real deal.

## Why shared secrets?

You might wonder: if we have quantum-safe algorithms, why not encrypt data directly with them?

Because they're slow and their keys are huge. ML-KEM-768 public keys are 1,184 bytes. Classic McEliece keys are over 200KB. You don't want to encrypt a video call with that.

Instead, the pattern every secure protocol uses (TLS, Signal, SSH) is:

1. **Use a KEM to agree on a shared secret.** Both sides end up with the same 32 bytes, without ever sending those bytes over the wire.
2. **Use that secret as an AES or ChaCha20 key.** Symmetric encryption is fast, and it's already quantum-safe (AES-256 still gives 128-bit security against quantum attacks).

That's what this library does. The KEM replaces the old Diffie-Hellman key exchange with a quantum-safe version. Everything else in your stack stays the same.

## Requirements

- Swift 6.3+
- macOS 13+ / iOS 16+ / tvOS 16+ / watchOS 9+ / Linux / Windows / Android

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/DeveloperBeau/liboqs-swift.git", from: "2.0.0"),
]
```

Add `"OQS"` to your target:

```swift
.target(name: "MyApp", dependencies: ["OQS"]),
```

## Usage

### Key exchange

```swift
import OQS

// Alice generates a key pair
let aliceKey = try MLKEM768.PrivateKey()

// Bob gets Alice's public key and generates a shared secret
let alicePub = try MLKEM768.PublicKey(rawRepresentation: alicePublicKeyData)
let result = try alicePub.generateSharedSecret()
// Bob has: result.sharedSecret
// Bob sends: result.ciphertext to Alice

// Alice decrypts the shared secret
let secret = try aliceKey.decryptSharedSecret(ciphertext)
// secret == result.sharedSecret. Both sides now have matching keys

// Use it for symmetric encryption
let symmetricKey = SymmetricKey(data: secret.rawRepresentation)
```

### Signatures

```swift
import OQS

let signingKey = try Falcon512.PrivateKey()
let message = Data("Transfer $100 to Bob".utf8)
let signature = try signingKey.signature(for: message)

// Anyone with the public key can verify
let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
```

## Algorithms

### Key encapsulation

| Family | Types |
|---|---|
| ML-KEM | `MLKEM512`, `MLKEM768`, `MLKEM1024` |
| Classic McEliece | `ClassicMcEliece348864`, `ClassicMcEliece460896`, `ClassicMcEliece6688128`, `ClassicMcEliece6960119`, `ClassicMcEliece8192128` |
| HQC | `HQC128`, `HQC192`, `HQC256` |

### Signatures

| Family | Types |
|---|---|
| Falcon | `Falcon512`, `Falcon1024`, `FalconPadded512`, `FalconPadded1024` |
| SPHINCS+ | SHA2 and SHAKE variants at 128/192/256-bit security |
| CROSS | RSDP and RSDPG variants at 128/192/256-bit security |
| SLH-DSA | Pure SHA2 and SHAKE variants at 128/192/256-bit security |

### Not yet available

Some liboqs algorithms don't compile cleanly with SPM's build model:

- **ML-DSA** (Dilithium): duplicate filenames across parameter sets
- **BIKE:** same issue
- **FrodoKEM:** textually-included C files

These can be enabled with manual `oqsconfig.h` and `Package.swift` changes if you need them.

## Vendored liboqs

liboqs **0.15.0** is vendored as C source. No pre-built binaries, no system installs.

A GitHub Action checks for new liboqs releases weekly and opens a PR automatically. To update manually:

```bash
echo "0.16.0" > LIBOQS_VERSION
./scripts/vendor-liboqs.sh
swift build && swift test
```

## License

MIT. See [LICENSE](LICENSE).

liboqs is also [MIT licensed](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt).
