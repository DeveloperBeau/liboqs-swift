import Foundation
@testable import OQS

/// The part of every public KEM `PrivateKey` type that the parity test uses.
protocol ParityKEMPrivateKey {
    associatedtype Public: ParityKEMPublicKey
    var rawRepresentation: Data { get }
    var publicKey: Public { get }
    func decryptSharedSecret(_ ciphertext: Data) throws -> SharedSecret
}
