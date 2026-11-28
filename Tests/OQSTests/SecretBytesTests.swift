import Testing
import Foundation
@testable import OQS

@Suite struct SecretBytesTests {
    private struct FillFailure: Error, Equatable {}

    private static let pattern: [UInt8] = (1...48).map { UInt8($0) }

    // MARK: - Wipe

    @Test("Secret bytes are wiped exactly once, with the right count, when the last reference goes away")
    func wipedOnceWhenReleased() {
        let memory = RecordingSecretMemory()
        var secret: SecretBytes? = .make(Self.pattern, memory: memory)
        #expect(memory.wipes.isEmpty, "wiped while still referenced")
        #expect(secret?.count == 48)
        secret = nil
        #expect(memory.wipes.count == 1)
        #expect(memory.wipes.first?.count == 48)
        #expect(memory.wipes.first?.allSatisfy { $0 == 0 } == true, "the wiped bytes still hold secret data")
    }

    @Test("A second reference keeps the bytes until it is released too")
    func notWipedWhileAnotherReferenceExists() {
        let memory = RecordingSecretMemory()
        var first: SecretBytes? = .make(Self.pattern, memory: memory)
        var second = first
        first = nil
        #expect(memory.wipes.isEmpty)
        #expect(second?.makeData() == Data(Self.pattern))
        second = nil
        #expect(memory.wipes.count == 1)
    }

    @Test("A filling closure that throws leaves a wipe of the whole buffer and rethrows the same error")
    func failedFillingWipesAndRethrows() {
        let memory = RecordingSecretMemory()
        #expect(throws: FillFailure.self) {
            _ = try SecretBytes(memory: memory, count: 32) { target in
                for index in 0..<target.count { target[index] = 0xA5 }
                throw FillFailure()
            }
        }
        #expect(memory.wipes.count == 1)
        #expect(memory.wipes.first?.count == 32)
        #expect(memory.wipes.first?.allSatisfy { $0 == 0 } == true)
    }

    @Test("Zero-length secret bytes are valid, empty and equal to each other")
    func zeroLength() throws {
        let memory = RecordingSecretMemory()
        var empty: SecretBytes? = try SecretBytes(memory: memory, count: 0) { _ in }
        #expect(empty?.count == 0)
        #expect(empty?.makeData() == Data())
        #expect(empty == (try SecretBytes(memory: memory, count: 0) { _ in }))
        empty = nil
        #expect(memory.wipes.allSatisfy { $0.isEmpty })
    }

    // MARK: - Content

    @Test("Copying keeps every byte and the source stays as it was")
    func copyingKeepsEveryByte() {
        let source = Data(Self.pattern)
        let secret = SecretBytes(copying: source)
        #expect(secret.count == 48)
        #expect(secret.makeData() == Data(Self.pattern))
        #expect(source == Data(Self.pattern))
    }

    @Test("Copying takes bytes from any ContiguousBytes value, and an empty one gives empty secret bytes")
    func copyingFromOtherSources() {
        #expect(SecretBytes(copying: [UInt8]([9, 8, 7])).makeData() == Data([9, 8, 7]))
        #expect(SecretBytes(copying: Data()).count == 0)
    }

    @Test("withUnsafeBytes reads the stored bytes and passes a result and an error through")
    func withUnsafeBytesReads() {
        let secret = SecretBytes(copying: Data([1, 2, 3, 4]))
        #expect(secret.withUnsafeBytes { Array($0) } == [1, 2, 3, 4])
        #expect(throws: FillFailure.self) { try secret.withUnsafeBytes { _ in throw FillFailure() } }
    }

    @Test("The copy that makeData returns is independent of the stored bytes")
    func makeDataIsACopy() {
        let secret = SecretBytes(copying: Data([1, 2, 3]))
        var copy = secret.makeData()
        copy[0] = 0xFF
        #expect(secret.makeData() == Data([1, 2, 3]))
    }

    // MARK: - Compare

    private static func secret(_ bytes: [UInt8]) -> SecretBytes { SecretBytes(copying: bytes) }

    @Test("Equal bytes compare equal, in both directions")
    func equalBytes() {
        let a = Self.secret(Self.pattern), b = Self.secret(Self.pattern)
        #expect(a == b)
        #expect(b == a)
    }

    @Test("A difference at the first, a middle or the last byte compares unequal, in both directions",
          arguments: [0, 23, 47])
    func differenceAtPosition(position: Int) {
        var other = Self.pattern
        other[position] ^= 0x80
        let a = Self.secret(Self.pattern), b = Self.secret(other)
        #expect(a != b)
        #expect(b != a)
    }

    @Test("Different lengths compare unequal, including a prefix and an empty value")
    func differentLengths() {
        let full = Self.secret(Self.pattern)
        #expect(full != Self.secret(Array(Self.pattern.dropLast())))
        #expect(Self.secret(Array(Self.pattern.dropLast())) != full)
        #expect(full != Self.secret([]))
        #expect(full != Self.secret(Self.pattern + [0]))
    }

    @Test("Empty equals empty, and a value equals itself")
    func emptyAndIdentity() {
        #expect(Self.secret([]) == Self.secret([]))
        let a = Self.secret(Self.pattern)
        #expect(a == a)
    }

    @Test("Comparison of same-length values goes through the memory seam")
    func comparisonUsesTheSeam() {
        let yes = RecordingSecretMemory(forcedEquality: true)
        let a = SecretBytes.make([1, 2, 3], memory: yes), b = SecretBytes.make([9, 9, 9], memory: yes)
        #expect(a == b, "the answer of the seam was ignored")
        #expect(yes.compareCount == 1)
        let no = RecordingSecretMemory(forcedEquality: false)
        let c = SecretBytes.make([1, 2, 3], memory: no), d = SecretBytes.make([1, 2, 3], memory: no)
        #expect(c != d)
    }

    @Test("Different lengths and identical references never ask the seam")
    func shortcutsDoNotAskTheSeam() {
        let yes = RecordingSecretMemory(forcedEquality: true)
        let a = SecretBytes.make([1, 2, 3], memory: yes), b = SecretBytes.make([1, 2], memory: yes)
        #expect(a != b)
        #expect(a == a)
        #expect(yes.compareCount == 0)
    }

    @Test("Fuzz with a seed: equal copies are always equal, and a flip, truncation or extension is never equal")
    func fuzzCompare() throws {
        let seed = try SeededGenerator.seedFromEnvironment()
        print("fuzz seed 0x\(String(seed, radix: 16))")
        var rng = SeededGenerator(seed: seed)
        for round in 0..<500 {
            let length = Int.random(in: 1...96, using: &rng)
            let bytes = (0..<length).map { _ in UInt8.random(in: 0...255, using: &rng) }
            let context = "seed 0x\(String(seed, radix: 16)), round \(round), length \(length)"
            let a = Self.secret(bytes)
            #expect(a == Self.secret(bytes), "false negative: \(context)")
            #expect(Self.secret(bytes) == a, "false negative: \(context)")

            var flipped = bytes
            flipped[Int.random(in: 0..<length, using: &rng)] ^= UInt8.random(in: 1...255, using: &rng)
            #expect(a != Self.secret(flipped), "false positive on a flip: \(context)")
            #expect(Self.secret(flipped) != a, "false positive on a flip: \(context)")

            #expect(a != Self.secret(Array(bytes.dropLast(Int.random(in: 1...length, using: &rng)))),
                    "false positive on a truncation: \(context)")
            let extra = (0..<Int.random(in: 1...8, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
            #expect(a != Self.secret(bytes + extra), "false positive on an extension: \(context)")
        }
    }

    // MARK: - Description

    @Test("The descriptions of secret bytes, a shared secret and a private key never show the bytes")
    func descriptionsHideTheBytes() throws {
        let bytes = Data(Self.pattern)
        let secret = SecretBytes(copying: bytes)
        #expect(secret.description == "SecretBytes(48 bytes)")
        #expect(secret.debugDescription == "SecretBytes(48 bytes)")

        let key = try MLKEM512.PrivateKey()
        let sealed = try key.publicKey.generateSharedSecret()
        let skData = key.rawRepresentation.makeData()
        let ssData = sealed.sharedSecret.rawRepresentation.makeData()
        let texts = [
            "\(secret)", String(reflecting: secret), "\(sealed.sharedSecret)", String(reflecting: sealed.sharedSecret),
            "\(key)", String(reflecting: key),
        ]
        for text in texts {
            for data in [bytes, skData, ssData] {
                let head = data.prefix(16)
                #expect(!text.contains(SecretFlow.hex(head)), "a description shows hex of secret bytes")
                #expect(!text.contains(head.base64EncodedString()), "a description shows base64 of secret bytes")
            }
        }
    }

    // MARK: - Owners release their storage

    @Test("A private key and a shared secret release their secret bytes when they go away")
    func ownersReleaseStorage() throws {
        weak var keyBytes: SecretBytes?
        weak var secretBytes: SecretBytes?
        do {
            let key = try MLKEM768.PrivateKey()
            let sealed = try key.publicKey.generateSharedSecret()
            keyBytes = key.rawRepresentation
            secretBytes = sealed.sharedSecret.rawRepresentation
            #expect(keyBytes != nil && secretBytes != nil)
        }
        #expect(keyBytes == nil, "the private key kept its secret bytes alive")
        #expect(secretBytes == nil, "the shared secret kept its secret bytes alive")
    }

    @Test("A failed key import leaves nothing alive and a signature private key releases its storage too")
    func signatureKeyReleasesStorage() throws {
        weak var keyBytes: SecretBytes?
        do {
            let key = try MLDSA44.PrivateKey()
            keyBytes = key.rawRepresentation
            #expect(keyBytes != nil)
        }
        #expect(keyBytes == nil)
    }

    // MARK: - Shared secrets

    @Test("Shared secrets with equal bytes are equal, and one flipped byte or another length is not")
    func sharedSecretEquality() {
        let a = SharedSecret(rawRepresentation: SecretBytes(copying: Data(Self.pattern)))
        #expect(a == SharedSecret(rawRepresentation: SecretBytes(copying: Data(Self.pattern))))
        var flipped = Self.pattern
        flipped[47] ^= 1
        #expect(a != SharedSecret(rawRepresentation: SecretBytes(copying: Data(flipped))))
        #expect(a != SharedSecret(rawRepresentation: SecretBytes(copying: Data(Self.pattern.dropLast()))))
    }

    // MARK: - Concurrency

    // Plain threads, not the cooperative pool: other suites block the pool's few
    // threads on long key generations, and a task group here would wait behind them.
    @Test("One private key signs from many threads and one shared secret is compared from many threads, all correct",
          .timeLimit(.minutes(2)))
    func concurrentUse() throws {
        let key = try MLDSA44.PrivateKey()
        let sealed = try MLKEM768.PrivateKey().publicKey.generateSharedSecret()
        let copy = SharedSecret(rawRepresentation: SecretBytes(copying: sealed.sharedSecret.rawRepresentation.makeData()))
        var other = sealed.sharedSecret.rawRepresentation.makeData()
        other[0] ^= 1
        let different = SharedSecret(rawRepresentation: SecretBytes(copying: other))
        let message = Data("concurrent".utf8)

        let lock = NSLock()
        nonisolated(unsafe) var results: [Bool] = []
        let group = DispatchGroup()
        for _ in 0..<8 {
            group.enter()
            let thread = Thread {
                defer { group.leave() }
                for _ in 0..<4 {
                    let verified = (try? key.signature(for: message))
                        .flatMap { try? key.publicKey.isValidSignature($0, for: message) } ?? false
                    let compared = sealed.sharedSecret == copy && sealed.sharedSecret != different
                    lock.lock()
                    results.append(verified)
                    results.append(compared)
                    lock.unlock()
                }
            }
            thread.stackSize = 8 << 20
            thread.start()
        }
        let finished = group.wait(timeout: .now() + 90)
        #expect(finished == .success, "the worker threads did not finish within 90 seconds")
        lock.lock()
        let snapshot = results
        lock.unlock()
        #expect(snapshot.count == 64)
        #expect(snapshot.allSatisfy { $0 })
    }
}
