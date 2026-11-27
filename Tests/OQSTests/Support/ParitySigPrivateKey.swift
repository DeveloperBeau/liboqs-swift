import Foundation

/// The part of every public stateless-signature `PrivateKey` type that the
/// parity test uses.
protocol ParitySigPrivateKey: SendableMetatype {
    associatedtype Public: ParitySigPublicKey
    var rawRepresentation: Data { get }
    var publicKey: Public { get }
    func signature(for data: Data) throws -> Data
}
