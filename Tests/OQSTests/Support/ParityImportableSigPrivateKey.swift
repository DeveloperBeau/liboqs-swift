import Foundation

/// A stateless-signature `PrivateKey` type that imports a key from raw bytes alone.
///
/// Every signature type has this form except SLH-DSA pre-hash, whose import
/// also takes the pre-hash function and parameter set.
protocol ParityImportableSigPrivateKey: ParitySigPrivateKey where Public: ParityImportableSigPublicKey {
    init(rawRepresentation: Data, publicKeyRepresentation: Data) throws
}
