import Foundation

/// The part of every public stateless-signature `PublicKey` type that the
/// parity test uses.
protocol ParitySigPublicKey {
    var rawRepresentation: Data { get }
}
