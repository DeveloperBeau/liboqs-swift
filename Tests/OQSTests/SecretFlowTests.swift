import Testing
import Foundation
@testable import OQS

/// Every stateless KEM and signature type, driven from the registry: use the
/// key, export it, rebuild it from the exported bytes, and use it again.
@Suite struct SecretFlowTests {
    static let kems = ParityRegistry.kems()
    // SLH-DSA pre-hash has 144 names that share one code path. A diagonal of
    // twelve covers every hash function and every parameter set once.
    static let sigs: [ParityAlgorithm] = {
        let all = ParityRegistry.sigs()
        let prehashCount = SLHDSA.Prehash.Function.allCases.count * SLHDSA.Prehash.ParamSet.allCases.count
        let prehash = all.prefix(prehashCount).enumerated().filter { $0.offset % 13 == 0 }.map(\.element)
        return prehash + all.dropFirst(prehashCount)
    }()

    // Some algorithms need far more C stack than a test worker thread has.
    private static func flow(_ list: [ParityAlgorithm], _ name: String) throws -> SecretFlow {
        let algorithm = try #require(list.first { $0.name == name })
        return try onLargeStack { try algorithm.secretFlow() }
    }

    private static let mlKEMNames: Set<String> = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

    @Test("Every KEM: both sides hold equal secrets of the liboqs length, a rebuilt key opens the same secret, a tampered ciphertext never gives the same secret, and a key one byte short is rejected without showing the key",
          .timeLimit(.minutes(10)), arguments: kems.map(\.name))
    func kemFlow(name: String) throws {
        let flow = try Self.flow(Self.kems, name)
        #expect(flow.original, "\(name): the two shared secrets differ")
        #expect(flow.rebuilt, "\(name): the rebuilt key opens a different secret")
        let description = try #require(Registry.kemDescription(named: name))
        #expect(flow.secretLength == description.sharedSecretLength, "\(name)")

        print("tamper \(name): \(String(describing: flow.tampered))")
        #expect(flow.tampered != .same, "\(name): a tampered ciphertext gave the same secret")
        if Self.mlKEMNames.contains(name) {
            #expect(flow.tampered == .differs, "\(name): ML-KEM must give a different secret without a throw")
        }

        let length = description.secretKeyLength
        #expect(flow.wrongLengthError == .invalidKeySize(expected: length, actual: length - 1), "\(name)")
        #expect(!flow.errorShowsKey, "\(name): the error shows key bytes")
    }

    @Test("Every signature: the signature verifies, a rebuilt key signs signatures that verify, and a key one byte short is rejected without showing the key",
          .timeLimit(.minutes(10)), arguments: sigs.map(\.name))
    func signatureFlow(name: String) throws {
        let flow = try Self.flow(Self.sigs, name)
        #expect(flow.original, "\(name): the signature does not verify")
        #expect(flow.rebuilt, "\(name): the rebuilt key signs a signature that does not verify")
        let length = try #require(Registry.signatureDescription(named: name)).secretKeyLength
        #expect(flow.wrongLengthError == .invalidKeySize(expected: length, actual: length - 1), "\(name)")
        #expect(!flow.errorShowsKey, "\(name): the error shows key bytes")
    }

    @Test("Fuzz with a seed: across ML-KEM-512, 768 and 1024 a flipped ciphertext bit never gives an equal secret and an untouched one always does")
    func fuzzTamper() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SeededGenerator(seed: seed)
        let keys: [(name: String, key: any ParityKEMPrivateKey)] = [
            ("ML-KEM-512", try MLKEM512.PrivateKey()), ("ML-KEM-768", try MLKEM768.PrivateKey()),
            ("ML-KEM-1024", try MLKEM1024.PrivateKey()),
        ]
        for round in 0..<30 {
            for (name, key) in keys {
                let sealed = try key.publicKey.generateSharedSecret()
                let context = "seed 0x\(String(seed, radix: 16)), round \(round), \(name)"
                #expect(try key.decryptSharedSecret(sealed.ciphertext) == sealed.sharedSecret, "false negative: \(context)")
                var bad = sealed.ciphertext
                let index = Int.random(in: 0..<bad.count, using: &rng)
                bad[bad.startIndex + index] ^= UInt8(1) << UInt8.random(in: 0..<8, using: &rng)
                #expect(try key.decryptSharedSecret(bad) != sealed.sharedSecret, "false positive: \(context), byte \(index)")
            }
        }
    }
}
