import Foundation
@testable import OQS

/// The part of every public stateless-signature `PrivateKey` type that the
/// parity test uses.
protocol ParitySigPrivateKey: SendableMetatype {
    associatedtype Public: ParitySigPublicKey
    var rawRepresentation: SecretBytes { get }
    var publicKey: Public { get }
    func signature(for data: Data) throws -> Data
}
