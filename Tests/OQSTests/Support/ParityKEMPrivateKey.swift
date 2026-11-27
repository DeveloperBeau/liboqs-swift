import Foundation
@testable import OQS

/// The part of every public KEM `PrivateKey` type that the parity test and the length check use.
protocol ParityKEMPrivateKey: SendableMetatype {
    associatedtype Public: ParityKEMPublicKey
    var rawRepresentation: Data { get }
    var publicKey: Public { get }
    init(rawRepresentation: Data, publicKeyRepresentation: Data) throws
    func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret
}
