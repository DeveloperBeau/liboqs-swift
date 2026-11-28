import Foundation
@testable import OQS

/// The part of every public KEM `PrivateKey` type that the parity test and the length check use.
protocol ParityKEMPrivateKey: SendableMetatype {
    associatedtype Public: ParityKEMPublicKey
    var rawRepresentation: SecretBytes { get }
    var publicKey: Public { get }
    init(rawRepresentation: SecretBytes, publicKeyRepresentation: Data) throws
    func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret
}
