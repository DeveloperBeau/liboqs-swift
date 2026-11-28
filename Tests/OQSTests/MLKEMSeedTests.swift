import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// Seeded (derandomised) ML-KEM key generation and encapsulation.
@Suite struct MLKEMSeedTests {

    // MARK: - Variants

    /// One ML-KEM size reached through its public types, with hand-written expectations.
    struct Variant: Sendable, CustomTestStringConvertible {
        let name: String
        let publicKeyLength: Int
        let secretKeyLength: Int
        let ciphertextLength: Int
        /// SHA-256 digests of the seeded outputs from the independent native Rust port.
        let publicKeyDigest: String
        let secretKeyDigest: String
        let ciphertextDigest: String
        let sharedSecretDigest: String
        let makeKeyPair: @Sendable (Data) throws -> (publicKey: Data, secretKey: Data)
        let makeRandomKeyPair: @Sendable () throws -> (publicKey: Data, secretKey: Data)
        let encapsulate: @Sendable (Data, Data) throws -> (ciphertext: Data, sharedSecret: Data)
        let encapsulateRandom: @Sendable (Data) throws -> (ciphertext: Data, sharedSecret: Data)
        let decapsulate: @Sendable (Data, Data, Data) throws -> Data

        var testDescription: String { name }
    }

    static let variants: [Variant] = [
        Variant(
            name: "ML-KEM-512", publicKeyLength: 800, secretKeyLength: 1632, ciphertextLength: 768,
            publicKeyDigest: "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee",
            secretKeyDigest: "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17",
            ciphertextDigest: "81efe667826848514dcae46fc10cfd34f7b95ed6900e094f727c9e7cccc34df2",
            sharedSecretDigest: "10f3aedb1a3440f36128242e3f158ea8503f9e3b74e18e253f60c8ad0e20cac8",
            makeKeyPair: { seed in
                let key = try MLKEM512.PrivateKey(seed: seed)
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            makeRandomKeyPair: {
                let key = try MLKEM512.PrivateKey()
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            encapsulate: { publicKey, seed in
                let result = try MLKEM512.PublicKey(rawRepresentation: publicKey).generateSharedSecret(seed: seed)
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            encapsulateRandom: { publicKey in
                let result = try MLKEM512.PublicKey(rawRepresentation: publicKey).generateSharedSecret()
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            decapsulate: { secretKey, publicKey, ciphertext in
                try MLKEM512.PrivateKey(rawRepresentation: SecretBytes(copying: secretKey), publicKeyRepresentation: publicKey)
                    .decryptSharedSecret(ciphertext).rawRepresentation.makeData()
            }
        ),
        Variant(
            name: "ML-KEM-768", publicKeyLength: 1184, secretKeyLength: 2400, ciphertextLength: 1088,
            publicKeyDigest: "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
            secretKeyDigest: "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5",
            ciphertextDigest: "dbf4e9aa48b078ad46ec1c9c47bda8c2d2fec9d0e7a21bd48d2238a2abedb856",
            sharedSecretDigest: "3211693eed5183e918a272986290fdf7419bcae0f2f648533dcfb290ca670c19",
            makeKeyPair: { seed in
                let key = try MLKEM768.PrivateKey(seed: seed)
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            makeRandomKeyPair: {
                let key = try MLKEM768.PrivateKey()
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            encapsulate: { publicKey, seed in
                let result = try MLKEM768.PublicKey(rawRepresentation: publicKey).generateSharedSecret(seed: seed)
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            encapsulateRandom: { publicKey in
                let result = try MLKEM768.PublicKey(rawRepresentation: publicKey).generateSharedSecret()
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            decapsulate: { secretKey, publicKey, ciphertext in
                try MLKEM768.PrivateKey(rawRepresentation: SecretBytes(copying: secretKey), publicKeyRepresentation: publicKey)
                    .decryptSharedSecret(ciphertext).rawRepresentation.makeData()
            }
        ),
        Variant(
            name: "ML-KEM-1024", publicKeyLength: 1568, secretKeyLength: 3168, ciphertextLength: 1568,
            publicKeyDigest: "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530",
            secretKeyDigest: "3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad",
            ciphertextDigest: "7c89743960f7c3d17bb69572e49de14fe0990c9113a0706963a8f4c7b39afcdf",
            sharedSecretDigest: "0bf615778a6c71e8915a2ec482a0f5a24dbdcd15ddaa55e3c0d7c5df7a4f3910",
            makeKeyPair: { seed in
                let key = try MLKEM1024.PrivateKey(seed: seed)
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            makeRandomKeyPair: {
                let key = try MLKEM1024.PrivateKey()
                return (key.publicKey.rawRepresentation, key.rawRepresentation.makeData())
            },
            encapsulate: { publicKey, seed in
                let result = try MLKEM1024.PublicKey(rawRepresentation: publicKey).generateSharedSecret(seed: seed)
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            encapsulateRandom: { publicKey in
                let result = try MLKEM1024.PublicKey(rawRepresentation: publicKey).generateSharedSecret()
                return (result.ciphertext, result.sharedSecret.rawRepresentation.makeData())
            },
            decapsulate: { secretKey, publicKey, ciphertext in
                try MLKEM1024.PrivateKey(rawRepresentation: SecretBytes(copying: secretKey), publicKeyRepresentation: publicKey)
                    .decryptSharedSecret(ciphertext).rawRepresentation.makeData()
            }
        ),
    ]

    // MARK: - Helpers

    /// The fixed public test seed: byte `i` is `start + i`.
    static func counted(from start: UInt8, count: Int) -> Data {
        Data((0..<count).map { start &+ UInt8($0) })
    }

    static var keyPairSeed: Data { counted(from: 0, count: 64) }
    static var encapsSeed: Data { counted(from: 64, count: 32) }

    /// Seeded key pair straight from liboqs, for comparison with the Swift wrapper.
    static func rawKeyPair(_ name: String, seed: Data) -> (publicKey: Data, secretKey: Data) {
        let kem = OQS_KEM_new(name)!
        defer { OQS_KEM_free(kem) }
        var publicKey = [UInt8](repeating: 0, count: Int(kem.pointee.length_public_key))
        var secretKey = [UInt8](repeating: 0, count: Int(kem.pointee.length_secret_key))
        let seedBytes = [UInt8](seed)
        let rc = OQS_KEM_keypair_derand(kem, &publicKey, &secretKey, seedBytes)
        #expect(rc == OQS_SUCCESS)
        return (Data(publicKey), Data(secretKey))
    }

    /// Seeded encapsulation straight from liboqs, for comparison with the Swift wrapper.
    static func rawEncapsulate(_ name: String, publicKey: Data, seed: Data) -> (ciphertext: Data, sharedSecret: Data) {
        let kem = OQS_KEM_new(name)!
        defer { OQS_KEM_free(kem) }
        var ciphertext = [UInt8](repeating: 0, count: Int(kem.pointee.length_ciphertext))
        var sharedSecret = [UInt8](repeating: 0, count: Int(kem.pointee.length_shared_secret))
        let publicKeyBytes = [UInt8](publicKey)
        let seedBytes = [UInt8](seed)
        let rc = OQS_KEM_encaps_derand(kem, &ciphertext, &sharedSecret, publicKeyBytes, seedBytes)
        #expect(rc == OQS_SUCCESS)
        return (Data(ciphertext), Data(sharedSecret))
    }

    /// Names of every KEM that the C library lists and has enabled.
    static func enabledKEMNames() -> [String] {
        (0..<Int(OQS_KEM_alg_count())).compactMap { index in
            guard let cName = OQS_KEM_alg_identifier(index) else { return nil }
            let name = String(cString: cName)
            return OQS_KEM_alg_is_enabled(name) == 1 ? name : nil
        }
    }

    static let seededNames: Set<String> = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

    // MARK: - Cross-port agreement (rule 8, 13)

    @Test("Seeded key pair and encapsulation match the hand-written Rust digests", arguments: variants)
    func seededOutputsMatchRustDigests(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        #expect(pair.publicKey.count == v.publicKeyLength)
        #expect(pair.secretKey.count == v.secretKeyLength)
        #expect(KAT.sha256Hex(pair.publicKey) == v.publicKeyDigest)
        #expect(KAT.sha256Hex(pair.secretKey) == v.secretKeyDigest)

        let sealed = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        #expect(sealed.ciphertext.count == v.ciphertextLength)
        #expect(KAT.sha256Hex(sealed.ciphertext) == v.ciphertextDigest)
        #expect(KAT.sha256Hex(sealed.sharedSecret) == v.sharedSecretDigest)
    }

    @Test("Seeded key pair and encapsulation equal raw liboqs byte for byte", arguments: variants)
    func seededOutputsMatchRawC(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        let raw = Self.rawKeyPair(v.name, seed: Self.keyPairSeed)
        #expect(pair.publicKey == raw.publicKey)
        #expect(pair.secretKey == raw.secretKey)

        let sealed = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        let rawSealed = Self.rawEncapsulate(v.name, publicKey: raw.publicKey, seed: Self.encapsSeed)
        #expect(sealed.ciphertext == rawSealed.ciphertext)
        #expect(sealed.sharedSecret == rawSealed.sharedSecret)
    }

    @Test("A seeded ciphertext decapsulates to the seeded shared secret", arguments: variants)
    func seededCiphertextDecapsulatesToSeededSecret(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        let sealed = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        let opened = try v.decapsulate(pair.secretKey, pair.publicKey, sealed.ciphertext)
        #expect(KAT.sha256Hex(opened) == v.sharedSecretDigest)
    }

    // MARK: - Behaviour

    @Test("The same seed gives the same key pair and a different seed gives a different one", arguments: variants)
    func keyPairFollowsSeed(_ v: Variant) throws {
        let first = try v.makeKeyPair(Self.keyPairSeed)
        let second = try v.makeKeyPair(Self.keyPairSeed)
        let other = try v.makeKeyPair(Self.counted(from: 1, count: 64))
        #expect(first.publicKey == second.publicKey)
        #expect(first.secretKey == second.secretKey)
        #expect(first.publicKey != other.publicKey)
        #expect(first.secretKey != other.secretKey)
    }

    @Test("The same seed gives the same encapsulation and a different seed gives a different one", arguments: variants)
    func encapsulationFollowsSeed(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        let first = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        let second = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        let other = try v.encapsulate(pair.publicKey, Self.counted(from: 65, count: 32))
        #expect(first.ciphertext == second.ciphertext)
        #expect(first.sharedSecret == second.sharedSecret)
        #expect(first.ciphertext != other.ciphertext)
        #expect(first.sharedSecret != other.sharedSecret)
    }

    @Test("A seeded key pair works with random encapsulation", arguments: variants)
    func seededKeyPairOpensRandomEncapsulation(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        let sealed = try v.encapsulateRandom(pair.publicKey)
        let opened = try v.decapsulate(pair.secretKey, pair.publicKey, sealed.ciphertext)
        #expect(opened == sealed.sharedSecret)
    }

    @Test("A random key pair works with seeded encapsulation", arguments: variants)
    func randomKeyPairOpensSeededEncapsulation(_ v: Variant) throws {
        let pair = try v.makeRandomKeyPair()
        let sealed = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        let opened = try v.decapsulate(pair.secretKey, pair.publicKey, sealed.ciphertext)
        #expect(opened == sealed.sharedSecret)
    }

    @Test("A flipped ciphertext bit never opens to the seeded secret", arguments: variants)
    func tamperedSeededCiphertextGivesDifferentSecret(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        var sealed = try v.encapsulate(pair.publicKey, Self.encapsSeed)
        sealed.ciphertext[0] ^= 0x01
        let opened = try v.decapsulate(pair.secretKey, pair.publicKey, sealed.ciphertext)
        #expect(opened != sealed.sharedSecret)
    }

    // MARK: - Errors through the public API

    @Test("A key pair seed of the wrong length is rejected with the expected size", arguments: variants)
    func wrongKeyPairSeedLengthIsRejected(_ v: Variant) {
        for length in [0, 63, 65] {
            #expect(throws: OQSError.invalidKeySize(expected: 64, actual: length)) {
                _ = try v.makeKeyPair(Data(count: length))
            }
        }
    }

    @Test("An encapsulation seed of the wrong length is rejected with the expected size", arguments: variants)
    func wrongEncapsulationSeedLengthIsRejected(_ v: Variant) throws {
        let pair = try v.makeKeyPair(Self.keyPairSeed)
        for length in [0, 31, 33] {
            #expect(throws: OQSError.invalidKeySize(expected: 32, actual: length)) {
                _ = try v.encapsulate(pair.publicKey, Data(count: length))
            }
        }
    }

    @Test("A public key with out of range coefficients fails seeded encapsulation")
    func nonCanonicalPublicKeyFailsSeededEncapsulation() throws {
        let key = try MLKEM768.PublicKey(rawRepresentation: Data(repeating: 0xFF, count: 1184))
        #expect(throws: OQSError.encapsulationFailed) {
            _ = try key.generateSharedSecret(seed: Self.encapsSeed)
        }
    }

    // MARK: - Internal helpers

    @Test("The helper rejects a wrong public key length on seeded encapsulation", arguments: variants)
    func helperRejectsWrongPublicKeyLength(_ v: Variant) {
        #expect(throws: OQSError.invalidKeySize(expected: v.publicKeyLength, actual: 10)) {
            _ = try kemEncapsulate(algorithm: v.name, publicKey: Data(count: 10), seed: Self.encapsSeed)
        }
    }

    @Test("The helper checks the seed length before the public key length", arguments: variants)
    func helperChecksSeedBeforePublicKey(_ v: Variant) {
        #expect(throws: OQSError.invalidKeySize(expected: 32, actual: 5)) {
            _ = try kemEncapsulate(algorithm: v.name, publicKey: Data(count: 10), seed: Data(count: 5))
        }
    }

    @Test("The helpers report an unknown algorithm")
    func helpersRejectUnknownAlgorithm() {
        #expect(throws: OQSError.algorithmNotAvailable("No-Such-KEM")) {
            _ = try kemGenerateKeyPair(algorithm: "No-Such-KEM", seed: Data(count: 64))
        }
        #expect(throws: OQSError.algorithmNotAvailable("No-Such-KEM")) {
            _ = try kemEncapsulate(algorithm: "No-Such-KEM", publicKey: Data(), seed: Data(count: 32))
        }
    }

    @Test("Exactly the three ML-KEM sizes have seed lengths in the C library")
    func onlyMLKEMHasSeedLengths() throws {
        let names = Self.enabledKEMNames()
        #expect(names.count == 41)
        #expect(Set(names).isSuperset(of: Self.seededNames))
        var seeded: Set<String> = []
        for name in names {
            let kem = try #require(OQS_KEM_new(name))
            defer { OQS_KEM_free(kem) }
            let keyPairSeedLength = Int(kem.pointee.length_keypair_seed)
            let encapsSeedLength = Int(kem.pointee.length_encaps_seed)
            if Self.seededNames.contains(name) {
                seeded.insert(name)
                #expect(keyPairSeedLength == 64, "\(name) keypair seed length")
                #expect(encapsSeedLength == 32, "\(name) encaps seed length")
            } else {
                #expect(keyPairSeedLength == 0, "\(name) keypair seed length")
                #expect(encapsSeedLength == 0, "\(name) encaps seed length")
            }
        }
        #expect(seeded == Self.seededNames)
        #expect(names.count - seeded.count == 38)
    }

    @Test("Every other enabled KEM reports seedNotSupported even with a wrong length seed")
    func otherKEMsReportSeedNotSupported() {
        for name in Self.enabledKEMNames() where !Self.seededNames.contains(name) {
            for seedLength in [0, 5, 32, 64] {
                #expect(throws: OQSError.seedNotSupported, "\(name) key pair seed \(seedLength)") {
                    _ = try kemGenerateKeyPair(algorithm: name, seed: Data(count: seedLength))
                }
                #expect(throws: OQSError.seedNotSupported, "\(name) encaps seed \(seedLength)") {
                    _ = try kemEncapsulate(algorithm: name, publicKey: Data(), seed: Data(count: seedLength))
                }
            }
        }
    }

    // MARK: - Fuzz (rule 6)

    /// Small seeded generator so the fuzz run is repeatable and needs no dependency.
    struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        mutating func bytes(_ count: Int) -> Data {
            Data((0..<count).map { _ in UInt8(truncatingIfNeeded: next()) })
        }
    }

    /// The fuzz seed from `OQS_FUZZ_SEED` (hex), else the fixed default.
    static func fuzzSeed() -> UInt64 {
        guard var text = ProcessInfo.processInfo.environment["OQS_FUZZ_SEED"] else { return 0x5717_F022 }
        if text.hasPrefix("0x") || text.hasPrefix("0X") { text.removeFirst(2) }
        return UInt64(text, radix: 16) ?? 0x5717_F022
    }

    static let fuzzRounds = 24

    @Test("Fuzz: random seeds always round-trip, match raw liboqs and reject tampering")
    func fuzzSeededRoundTrip() throws {
        let seed = Self.fuzzSeed()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SplitMix64(state: seed)
        let v = Self.variants[0]
        for round in 0..<Self.fuzzRounds {
            let keySeed = rng.bytes(64)
            let encSeed = rng.bytes(32)
            let pair = try v.makeKeyPair(keySeed)
            let raw = Self.rawKeyPair(v.name, seed: keySeed)
            #expect(pair.publicKey == raw.publicKey && pair.secretKey == raw.secretKey, "round \(round) key pair")

            let sealed = try v.encapsulate(pair.publicKey, encSeed)
            let rawSealed = Self.rawEncapsulate(v.name, publicKey: raw.publicKey, seed: encSeed)
            #expect(sealed.ciphertext == rawSealed.ciphertext && sealed.sharedSecret == rawSealed.sharedSecret, "round \(round) encaps")

            let opened = try v.decapsulate(pair.secretKey, pair.publicKey, sealed.ciphertext)
            #expect(opened == sealed.sharedSecret, "round \(round) false negative")

            var tampered = sealed.ciphertext
            let index = Int(rng.next() % UInt64(tampered.count))
            tampered[index] ^= UInt8(1) << UInt8(rng.next() % 8)
            let rejected = try v.decapsulate(pair.secretKey, pair.publicKey, tampered)
            #expect(rejected != sealed.sharedSecret, "round \(round) false positive")
        }
    }

    @Test("Fuzz: random wrong seed lengths always throw invalidKeySize")
    func fuzzWrongSeedLengthsAreRejected() throws {
        let seed = Self.fuzzSeed()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SplitMix64(state: seed ^ 0xA5A5)
        let v = Self.variants[0]
        let pair = try v.makeKeyPair(Self.keyPairSeed)

        var keyPairLengths = [63, 65]
        var encapsLengths = [31, 33]
        for _ in 0..<Self.fuzzRounds {
            keyPairLengths.append(Int(rng.next() % 300))
            encapsLengths.append(Int(rng.next() % 300))
        }
        for length in keyPairLengths where length != 64 {
            let bad = rng.bytes(length)
            #expect(throws: OQSError.invalidKeySize(expected: 64, actual: length)) {
                _ = try v.makeKeyPair(bad)
            }
        }
        for length in encapsLengths where length != 32 {
            let bad = rng.bytes(length)
            #expect(throws: OQSError.invalidKeySize(expected: 32, actual: length)) {
                _ = try v.encapsulate(pair.publicKey, bad)
            }
        }
    }
}
