import Foundation
internal import Cliboqs

/// Secret memory operations backed by liboqs.
struct LiboqsSecretMemory: SecretMemoryManaging {
    func wipe(_ bytes: UnsafeMutableRawBufferPointer) {
        guard let base = bytes.baseAddress, bytes.count > 0 else { return }
        OQS_MEM_cleanse(base, bytes.count)
    }

    // OQS_MEM_secure_bcmp returns 0 when the bytes are equal.
    func areEqual(_ lhs: UnsafeRawBufferPointer, _ rhs: UnsafeRawBufferPointer) -> Bool {
        guard let left = lhs.baseAddress, let right = rhs.baseAddress, lhs.count > 0 else { return true }
        return OQS_MEM_secure_bcmp(left, right, lhs.count) == 0
    }
}
