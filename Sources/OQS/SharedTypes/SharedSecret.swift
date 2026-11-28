import Foundation

/// A shared secret established between two parties via key encapsulation.
///
/// Both sides end up with the same bytes after a KEM exchange. Use
/// `rawRepresentation` to read the bytes for symmetric encryption.
/// The bytes are wiped when the last reference goes away.
public struct SharedSecret: Sendable, Equatable {
    /// The secret bytes, held in wiped storage.
    public let rawRepresentation: SecretBytes

    /// Creates a shared secret from secret bytes.
    public init(rawRepresentation: SecretBytes) {
        self.rawRepresentation = rawRepresentation
    }

    /// Compares two shared secrets in constant time for the same length.
    public static func == (lhs: SharedSecret, rhs: SharedSecret) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}
