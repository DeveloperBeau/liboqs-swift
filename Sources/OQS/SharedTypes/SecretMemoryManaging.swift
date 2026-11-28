import Foundation

/// The two memory operations that secret bytes need.
///
/// The seam keeps liboqs out of the entity types, and it lets a test watch the wipe.
protocol SecretMemoryManaging: Sendable {
    /// Overwrites every byte of `bytes` with zero in a way the compiler cannot drop.
    func wipe(_ bytes: UnsafeMutableRawBufferPointer)

    /// Returns whether the two buffers hold the same bytes, in time that does not depend on the bytes.
    ///
    /// The caller guarantees that both buffers have the same length.
    func areEqual(_ lhs: UnsafeRawBufferPointer, _ rhs: UnsafeRawBufferPointer) -> Bool
}
