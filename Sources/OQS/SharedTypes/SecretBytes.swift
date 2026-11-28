import Foundation

/// Secret bytes in memory that is wiped when the value is released.
///
/// A private key or a shared secret lives in a `SecretBytes`. The size is fixed and the
/// bytes cannot change after creation. Equality is constant time.
///
/// Creating a `SecretBytes` from `Data` copies the bytes. The source `Data` is
/// still yours, so wipe it when you no longer need it. ``makeData()`` also gives you a copy
/// that you own and should wipe.
public final class SecretBytes: @unchecked Sendable, ContiguousBytes, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible
{
    // The storage never changes after init, so reads from many threads are safe.
    private let storage: UnsafeMutableRawBufferPointer
    private let memory: any SecretMemoryManaging

    /// The number of bytes.
    public var count: Int { storage.count }

    /// Allocates `count` zeroed bytes and lets `filling` write them.
    ///
    /// If `filling` throws, the storage is wiped and freed, and the error is thrown again.
    init(
        memory: any SecretMemoryManaging,
        count: Int,
        filling: (UnsafeMutableRawBufferPointer) throws -> Void
    ) rethrows {
        let buffer = Self.allocate(count: count)
        do {
            try filling(buffer)
        } catch {
            Self.release(buffer, through: memory)
            throw error
        }
        self.storage = buffer
        self.memory = memory
    }

    /// Copies `bytes` into new storage.
    convenience init(copying bytes: UnsafeRawBufferPointer, memory: any SecretMemoryManaging) {
        self.init(memory: memory, count: bytes.count) { destination in
            if let source = bytes.baseAddress, bytes.count > 0 {
                destination.baseAddress?.copyMemory(from: source, byteCount: bytes.count)
            }
        }
    }

    deinit {
        Self.release(storage, through: memory)
    }

    private static func allocate(count: Int) -> UnsafeMutableRawBufferPointer {
        guard count > 0 else { return UnsafeMutableRawBufferPointer(start: nil, count: 0) }
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: 16)
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        return buffer
    }

    private static func release(_ buffer: UnsafeMutableRawBufferPointer, through memory: any SecretMemoryManaging) {
        memory.wipe(buffer)
        buffer.deallocate()
    }

    /// Calls `body` with a read-only view of the bytes.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(storage))
    }

    /// Returns a plain copy of the bytes.
    ///
    /// The caller owns the copy and should wipe it when done.
    public func makeData() -> Data {
        Data(UnsafeRawBufferPointer(storage))
    }

    /// Compares two values in constant time for the same count.
    public static func == (lhs: SecretBytes, rhs: SecretBytes) -> Bool {
        if lhs === rhs { return true }
        guard lhs.count == rhs.count else { return false }
        return lhs.memory.areEqual(UnsafeRawBufferPointer(lhs.storage), UnsafeRawBufferPointer(rhs.storage))
    }

    /// A description that shows the count and never the bytes.
    public var description: String { "SecretBytes(\(count) bytes)" }

    /// A debug description that shows the count and never the bytes.
    public var debugDescription: String { description }
}
