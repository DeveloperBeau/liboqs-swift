import Foundation
@testable import OQS

/// A double of the secret memory seam. It wipes through liboqs, then records
/// the bytes it saw. Equality can be forced to a fixed answer.
final class RecordingSecretMemory: SecretMemoryManaging, @unchecked Sendable {
    private let lock = NSLock()
    private var wiped: [[UInt8]] = []
    private var compares = 0
    private let real = LiboqsSecretMemory()
    private let forcedEquality: Bool?

    init(forcedEquality: Bool? = nil) {
        self.forcedEquality = forcedEquality
    }

    /// The buffers seen by `wipe`, as they were after the real wipe.
    var wipes: [[UInt8]] { lock.withLock { wiped } }
    /// The number of calls to `areEqual`.
    var compareCount: Int { lock.withLock { compares } }

    func wipe(_ bytes: UnsafeMutableRawBufferPointer) {
        real.wipe(bytes)
        let seen = Array(bytes)
        lock.withLock { wiped.append(seen) }
    }

    func areEqual(_ lhs: UnsafeRawBufferPointer, _ rhs: UnsafeRawBufferPointer) -> Bool {
        lock.withLock { compares += 1 }
        return forcedEquality ?? real.areEqual(lhs, rhs)
    }
}

extension SecretBytes {
    /// Builds secret bytes over `memory` that hold `bytes`.
    static func make(_ bytes: [UInt8], memory: any SecretMemoryManaging) -> SecretBytes {
        try! SecretBytes(memory: memory, count: bytes.count) { target in
            for (index, byte) in bytes.enumerated() { target[index] = byte }
        }
    }
}
