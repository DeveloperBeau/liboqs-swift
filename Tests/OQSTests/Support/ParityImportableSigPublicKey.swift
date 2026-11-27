import Foundation

/// A stateless-signature `PublicKey` type that imports a key from raw bytes alone.
protocol ParityImportableSigPublicKey: ParitySigPublicKey {
    init(rawRepresentation: Data) throws
}
