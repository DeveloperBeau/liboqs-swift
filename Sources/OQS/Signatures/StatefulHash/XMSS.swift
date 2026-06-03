import Foundation

/// XMSS stateful hash-based signatures (RFC 8391).
///
/// XMSS is a *stateful* signature scheme: each signing key can produce a fixed
/// number of signatures, and every signature consumes a one-time index that must
/// never be reused. Reusing an index destroys the scheme's security. This API
/// makes reuse impossible by construction: ``PrivateKey/signature(for:persistingTo:)``
/// returns a signature only after your persist closure has durably stored the
/// advanced key state.
///
/// ```swift
/// var state: Data? = nil
/// let key = try XMSS.PrivateKey(.sha2_10_256)
/// // Persist the index-0 state BEFORE the first sign.
/// state = try key.serializedSecretKey
///
/// let sig = try key.signature(for: message) { advanced in
///     state = advanced               // durably store before this returns
/// }
///
/// let pub = XMSS.PublicKey(.sha2_10_256, rawRepresentation: key.publicKey.rawRepresentation)
/// let ok = try pub.isValidSignature(sig, for: message)
/// ```
///
/// - Important: After generating a key you MUST persist ``PrivateKey/serializedSecretKey``
///   *before* the first signature, and the persist closure passed to each sign
///   MUST durably store the new state. The serialized blob is a self-contained
///   `publicKey || liboqs-secret-key` value; load it back with
///   ``PrivateKey/init(_:serializedSecretKey:)``.
public enum XMSS: Sendable {
    /// XMSS parameter sets. The raw value is the exact liboqs algorithm name.
    public enum Variant: String, Sendable, CaseIterable {
        case sha2_10_256 = "XMSS-SHA2_10_256"
        /// - Warning: `h16` keygen builds a height-16 tree and is very slow; generate off the hot path.
        case sha2_16_256 = "XMSS-SHA2_16_256"
        /// - Warning: `h20` keygen builds a height-20 tree and is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_20_256 = "XMSS-SHA2_20_256"
        case shake128_10_256 = "XMSS-SHAKE_10_256"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case shake128_16_256 = "XMSS-SHAKE_16_256"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake128_20_256 = "XMSS-SHAKE_20_256"
        case sha2_10_512 = "XMSS-SHA2_10_512"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case sha2_16_512 = "XMSS-SHA2_16_512"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_20_512 = "XMSS-SHA2_20_512"
        case shake256_10_512 = "XMSS-SHAKE_10_512"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case shake256_16_512 = "XMSS-SHAKE_16_512"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake256_20_512 = "XMSS-SHAKE_20_512"
        case sha2_10_192 = "XMSS-SHA2_10_192"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case sha2_16_192 = "XMSS-SHA2_16_192"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_20_192 = "XMSS-SHA2_20_192"
        case shake256_10_192 = "XMSS-SHAKE256_10_192"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case shake256_16_192 = "XMSS-SHAKE256_16_192"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake256_20_192 = "XMSS-SHAKE256_20_192"
        case shake256_10_256 = "XMSS-SHAKE256_10_256"
        /// - Warning: `h16` keygen is very slow; generate off the hot path.
        case shake256_16_256 = "XMSS-SHAKE256_16_256"
        /// - Warning: `h20` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake256_20_256 = "XMSS-SHAKE256_20_256"
    }

    /// A stateful XMSS signing key. Reference type, intentionally **not** `Sendable`:
    /// it owns mutable one-time-key state and must not be shared across isolation
    /// boundaries.
    public final class PrivateKey {
        private let engine: StatefulSigningKey

        /// The variant this key was created with.
        public let variant: Variant

        /// The matching public key, for verification.
        public let publicKey: PublicKey

        /// Generate a fresh signing key.
        ///
        /// - Important: Persist ``serializedSecretKey`` immediately, before the
        ///   first call to ``signature(for:persistingTo:)``.
        public init(_ variant: Variant) throws {
            self.variant = variant
            self.engine = try StatefulSigningKey(generating: variant.rawValue)
            self.publicKey = PublicKey(variant, unchecked: engine.publicKey)
        }

        /// Restore a signing key from a previously persisted state blob.
        ///
        /// - Parameter serializedSecretKey: a value previously obtained from
        ///   ``serializedSecretKey`` or delivered to a sign persist closure.
        public init(_ variant: Variant, serializedSecretKey: Data) throws {
            self.variant = variant
            self.engine = try StatefulSigningKey(algorithm: variant.rawValue, serialized: serializedSecretKey)
            self.publicKey = PublicKey(variant, unchecked: engine.publicKey)
        }

        /// The self-contained current-state blob (`publicKey || liboqs-secret-key`).
        /// Persist this immediately after generation and treat each sign's closure
        /// argument as the new authoritative state.
        public var serializedSecretKey: Data {
            get throws { try engine.serialized }
        }

        /// Number of signatures the key can still produce.
        public var remainingSignatures: UInt64 {
            get throws { try engine.remainingSignatures }
        }

        /// Sign `data`, persisting the advanced key state via `store`.
        ///
        /// The returned signature is produced IF AND ONLY IF `store` returns
        /// without throwing. If `store` throws, that error propagates and no
        /// signature is returned. Persist the bytes handed to `store` durably
        /// (the same self-contained format as ``serializedSecretKey``).
        public func signature(for data: Data, persistingTo store: (Data) throws -> Void) throws -> Data {
            try engine.signature(for: data, persistingTo: store)
        }
    }

    /// An XMSS public key. Verification is stateless.
    public struct PublicKey: Sendable {
        /// The variant this public key belongs to.
        public let variant: Variant
        /// The raw public-key bytes.
        public let rawRepresentation: Data

        /// Build a public key for verification.
        public init(_ variant: Variant, rawRepresentation: Data) {
            self.variant = variant
            self.rawRepresentation = rawRepresentation
        }

        init(_ variant: Variant, unchecked rawRepresentation: Data) {
            self.variant = variant
            self.rawRepresentation = rawRepresentation
        }

        /// Verify `signature` over `data`. Stateless.
        public func isValidSignature(_ signature: Data, for data: Data) throws -> Bool {
            try StatefulSignatureVerifier.verify(
                algorithm: variant.rawValue,
                message: data,
                signature: signature,
                publicKey: rawRepresentation)
        }
    }
}
