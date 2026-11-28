import Foundation

extension SecretBytes {
    /// Creates secret bytes by copying `bytes`.
    ///
    /// The copy is wiped when the value is released. You still own the source bytes
    /// and should wipe them when you no longer need them.
    public convenience init<Bytes: ContiguousBytes>(copying bytes: Bytes) {
        let count = bytes.withUnsafeBytes { $0.count }
        self.init(memory: LiboqsSecretMemory(), count: count) { destination in
            bytes.withUnsafeBytes { source in
                if let from = source.baseAddress, let to = destination.baseAddress {
                    to.copyMemory(from: from, byteCount: min(source.count, destination.count))
                }
            }
        }
    }
}
