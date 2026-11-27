# liboqs-swift

[![CI](https://github.com/DeveloperBeau/liboqs-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/DeveloperBeau/liboqs-swift/actions/workflows/ci.yml)

Post-quantum cryptography for Swift, powered by [liboqs](https://github.com/open-quantum-safe/liboqs).

## Features

- Type-safe Swift API for key encapsulation and digital signatures
- Full liboqs algorithm coverage: ML-KEM, FrodoKEM/eFrodoKEM, NTRU, Classic McEliece, HQC, BIKE; ML-DSA, Falcon, SLH-DSA, CROSS, MAYO, SNOVA, UOV, MQOM2, and stateful XMSS/LMS
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
| **SLH-DSA** | Just hash functions, no fancy math to break | Signatures |
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

- Swift 6.4+
- macOS 13+ / iOS 16+ / tvOS 16+ / watchOS 9+ / Linux / Windows / Android

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/DeveloperBeau/liboqs-swift.git", from: "0.2.0"),
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

### Seeded key generation

ML-KEM can also derive a key pair or an encapsulation from a seed. The same seed always gives the same output.

```swift
// A 64 byte seed gives a key pair, a 32 byte seed gives an encapsulation
let key = try MLKEM768.PrivateKey(seed: keyPairSeed)
let result = try key.publicKey.generateSharedSecret(seed: encapsulationSeed)
```

Only `MLKEM512`, `MLKEM768` and `MLKEM1024` have this form, because liboqs 0.16.0 offers seeded operations for no other algorithm. A seed of the wrong length throws `OQSError.invalidKeySize`. Seeds are secret, so wipe your copy when you are done. The package does not keep one.

### Signatures

```swift
import OQS

let signingKey = try Falcon512.PrivateKey()
let message = Data("Transfer $100 to Bob".utf8)
let signature = try signingKey.signature(for: message)

// Anyone with the public key can verify
let valid = try signingKey.publicKey.isValidSignature(signature, for: message)
```

### Algorithm lookup

`Registry` lists the algorithms this build enables and reports what liboqs knows about each one. The lists are in liboqs order. A lookup ignores the case of ASCII letters, as liboqs does, and the description always carries the liboqs name.

```swift
import OQS

print(Registry.enabledKEMNames.count)               // 41
print(Registry.isSignatureEnabled("ml-dsa-65"))     // true

if let kem = Registry.kemDescription(named: "ml-kem-768") {
    print(kem.name)                // ML-KEM-768
    print(kem.claimedNISTLevel)    // 3
    print(kem.ciphertextLength)    // 1088
}

let lms = Registry.statefulSignatureDescription(named: "LMS_SHA256_H5_W8")
print(lms?.signatureLength ?? 0)   // 1296
```

A name that is not enabled gives `nil` and `false`. The values come from the vendored liboqs, which is still pinned at 0.16.0.

## Algorithms

Every liboqs 0.16.0 algorithm has its own Swift type with a `PrivateKey` and `PublicKey`.

### Key encapsulation

| Family | Types |
|---|---|
| ML-KEM (FIPS 203) | `MLKEM512`, `MLKEM768`, `MLKEM1024` |
| FrodoKEM (salted) | `FrodoKEM640AES`, `FrodoKEM640SHAKE`, `FrodoKEM976AES`, `FrodoKEM976SHAKE`, `FrodoKEM1344AES`, `FrodoKEM1344SHAKE` |
| eFrodoKEM (ephemeral, the pre-0.16.0 FrodoKEM) | `EFrodoKEM640AES`, `EFrodoKEM640SHAKE`, `EFrodoKEM976AES`, `EFrodoKEM976SHAKE`, `EFrodoKEM1344AES`, `EFrodoKEM1344SHAKE` |
| NTRU | `NTRUHPS2048509`, `NTRUHPS2048677`, `NTRUHPS4096821`, `NTRUHPS40961229`, `NTRUHRSS701`, `NTRUHRSS1373` |
| NTRU Prime | `SNTRUP761` |
| Classic McEliece | `ClassicMcEliece348864`, `ClassicMcEliece460896`, `ClassicMcEliece6688128`, `ClassicMcEliece6960119`, `ClassicMcEliece8192128`, plus the fast-keygen `…f` variants (`ClassicMcEliece348864f`, etc.) |
| HQC (20250822 spec) | `HQC1`, `HQC3`, `HQC5` |
| BIKE | `BIKEL1`, `BIKEL3`, `BIKEL5` |
| Kyber (**deprecated**) | `Kyber512`, `Kyber768`, `Kyber1024`. Superseded by ML-KEM; reach for the `MLKEM*` types instead |

### Signatures

| Family | Types |
|---|---|
| ML-DSA (FIPS 204) | `MLDSA44`, `MLDSA65`, `MLDSA87` |
| Falcon | `Falcon512`, `Falcon1024`, `FalconPadded512`, `FalconPadded1024` |
| SLH-DSA (FIPS 205) | 12 pure SHA2/SHAKE variants (`SLHDSAPureSHA2128s`, etc.), plus a parameterized `SLHDSA.Prehash` covering all 144 pre-hash function × parameter-set combinations |
| CROSS | 18 RSDP and RSDPG Balanced/Fast/Small variants at 128/192/256-bit security |
| MAYO | `MAYO1`, `MAYO2`, `MAYO3`, `MAYO5` |
| SNOVA | 12 parameter sets (`SNOVA24_5_4`, …, including SHAKE and `_esk` variants) |
| UOV | 12 parameter sets (`OVIs`, `OVIp`, `OVIII`, `OVV`, plus their `PKC` / `PKCSKC` variants) |
| MQOM2 | 12 parameter sets (`MQOM2Cat1GF16FastR3`, …: cat1/3/5 × fast/short × r3/r5) |

> ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) are the NIST-standardized schemes. The other families are additional NIST round candidates and alternates.

> `MAYO5` allocates very large stack buffers during key generation and signing. Run it on a thread with a multi-megabyte stack; the small default stack of a background task or `DispatchQueue` worker is not enough.

### Stateful signatures

XMSS, XMSS^MT, and LMS are *stateful* hash-based schemes: every signature consumes a one-time key index, and reusing an index breaks the scheme. They use a different API from the rest of the library:

- `PrivateKey` is a reference type (a `final class`) that owns mutable key state and is intentionally **not** `Sendable`.
- `signature(for:persistingTo:)` hands you a signature only after your persist closure durably stores the advanced key state. If the closure throws, you get no signature.
- Verification (`isValidSignature(_:for:)`) is stateless.

```swift
import OQS

var state: Data? = nil
let key = try XMSS.PrivateKey(.sha2_10_256)
// Persist the index-0 state BEFORE the first sign.
state = try key.serializedSecretKey

let sig = try key.signature(for: message) { advanced in
    state = advanced               // durably store before this returns
}

let pub = XMSS.PublicKey(.sha2_10_256, rawRepresentation: key.publicKey.rawRepresentation)
let ok = try pub.isValidSignature(sig, for: message)
```

Large parameter sets (XMSS/XMSS^MT height-16 and height-20 trees, and the bigger LMS sets) resolve by name but take a long time to generate. Build them off the hot path.

## Vendored liboqs

liboqs **0.16.0** is vendored as C source. No pre-built binaries, no system installs.

A GitHub Action checks for new liboqs releases weekly and opens a PR automatically. To update manually:

```bash
echo "0.16.0" > LIBOQS_VERSION
./scripts/vendor-liboqs.sh
swift build && swift test
```

## Testing

Three tiers:

```bash
swift test --skip KATTests                          # functional: keygen + roundtrip per variant
swift test --no-parallel --filter KATTests          # deterministic KAT digests (global RNG, serial)
OQS_PARITY=1 swift test --no-parallel --filter ParityTests   # full differential parity (~12 min)
```

The parity sweep runs every enabled algorithm (262: 41 KEMs × 5 fields, 221 signatures × 3 fields — 868 buffers) through both the raw C API and the Swift wrapper under the deterministic KAT seed and requires byte-identical output, then checks each algorithm's digest against the frozen reference snapshot (`Tests/OQSTests/Vectors/parity_snapshot.txt`, regenerated at vendor bumps with `OQS_PARITY_WRITE_SNAPSHOT=1`). CI shards it four ways via `OQS_SHARD`/`OQS_TOTAL`.

## License

MIT. See [LICENSE](LICENSE).

liboqs is also [MIT licensed](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt).
