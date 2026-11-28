import Foundation

/// What verify does with a caller signature of a given length.
enum VerifySignatureInput: Equatable {
    /// The signature is longer than the scheme allows. Verify fails without calling liboqs.
    case reject
    /// The signature has the full length. The caller bytes go to liboqs as they are.
    case passThrough
    /// The signature is shorter than the full length. liboqs gets a zero-filled
    /// buffer of the full length that holds a copy of the signature, and the real count.
    case padded(buffer: [UInt8], count: Int)

    /// Decides the input for a signature, given the scheme's `length_signature`.
    ///
    /// For some schemes liboqs reads the signature before it checks the length.
    /// A padded buffer is always owned by this code, so even an empty signature
    /// reaches liboqs with a valid base address and the full length readable.
    static func plan(for signature: Data, maxLength: Int) -> VerifySignatureInput {
        if signature.count > maxLength { return .reject }
        if signature.count == maxLength { return .passThrough }
        var buffer = [UInt8](repeating: 0, count: maxLength)
        buffer.replaceSubrange(0..<signature.count, with: signature)
        return .padded(buffer: buffer, count: signature.count)
    }
}

/// Runs `body` with the signature bytes that liboqs may read, or returns false
/// when the signature is too long. The buffer that `body` gets holds exactly
/// the real signature length, and its base address is never nil.
func withVerifiableSignature(
    _ signature: Data, maxLength: Int, _ body: (UnsafeRawBufferPointer) -> Bool
) -> Bool {
    switch VerifySignatureInput.plan(for: signature, maxLength: maxLength) {
    case .reject:
        return false
    case .passThrough:
        return signature.withUnsafeBytes(body)
    case .padded(let buffer, let count):
        return buffer.withUnsafeBytes { body(UnsafeRawBufferPointer(rebasing: $0[..<count])) }
    }
}
