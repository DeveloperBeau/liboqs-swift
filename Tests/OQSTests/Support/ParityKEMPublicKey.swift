import Foundation
@testable import OQS

/// The part of every public KEM `PublicKey` type that the parity test and the length check use.
/// The wrapper types share no protocol, so the test declares this one and
/// conforms each type in ParityConformances.swift.
protocol ParityKEMPublicKey {
    var rawRepresentation: Data { get }
    init(rawRepresentation: Data) throws
    func generateSharedSecret() throws -> SharedSecretResult
}
