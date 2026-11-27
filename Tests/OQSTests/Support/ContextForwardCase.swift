import Testing
import Foundation

/// The public verify methods of a stateless signature `PublicKey`, plain and with a context.
protocol ContextSigPublicKey: Sendable {
    var rawRepresentation: Data { get }
    func isValidSignature(_ signature: Data, for data: Data) throws -> Bool
    func isValidSignature(_ signature: Data, for data: Data, context: Data) throws -> Bool
}

/// The public sign methods of a stateless signature `PrivateKey`, plain and with a context.
protocol ContextSigPrivateKey: Sendable {
    associatedtype Public: ContextSigPublicKey
    var publicKey: Public { get }
    var rawRepresentation: Data { get }
    func signature(for data: Data) throws -> Data
    func signature(for data: Data, context: Data) throws -> Data
}

/// One generated key pair seen through its typed methods only.
struct ContextSigner: Sendable {
    let sign: @Sendable (Data) throws -> Data
    let signWithContext: @Sendable (Data, Data) throws -> Data
    let verify: @Sendable (Data, Data) throws -> Bool
    let verifyWithContext: @Sendable (Data, Data, Data) throws -> Bool
    /// The lengths of the generated keys, to tie the closures to the entry's type.
    let publicKeyLength: Int
    let secretKeyLength: Int

    init<K: ContextSigPrivateKey>(_ key: K) {
        let publicKey = key.publicKey
        publicKeyLength = publicKey.rawRepresentation.count
        secretKeyLength = key.rawRepresentation.count
        sign = { try key.signature(for: $0) }
        signWithContext = { try key.signature(for: $0, context: $1) }
        verify = { try publicKey.isValidSignature($0, for: $1) }
        verifyWithContext = { try publicKey.isValidSignature($0, for: $1, context: $2) }
    }
}

/// One row of the context forward table: a liboqs name and a way to make a signer.
struct ContextForwardCase: Sendable, CustomTestStringConvertible {
    let name: String
    let isPrehash: Bool
    let makeSigner: @Sendable () throws -> ContextSigner

    var testDescription: String { name }

    static func typed<K: ContextSigPrivateKey>(
        _ name: String, _ make: @escaping @Sendable () throws -> K
    ) -> ContextForwardCase {
        ContextForwardCase(name: name, isPrehash: false, makeSigner: { ContextSigner(try make()) })
    }

    static func prehash<K: ContextSigPrivateKey>(
        _ name: String, _ make: @escaping @Sendable () throws -> K
    ) -> ContextForwardCase {
        ContextForwardCase(name: name, isPrehash: true, makeSigner: { ContextSigner(try make()) })
    }
}
