import Foundation

/// XMSS^MT (multi-tree XMSS) stateful hash-based signatures (RFC 8391).
///
/// Like ``XMSS`` but with a hypertree of multiple layers, supporting much larger
/// numbers of signatures per key. It is a *stateful* scheme: each signature
/// consumes a one-time index that must never be reused. This API enforces that:
/// ``PrivateKey/signature(for:persistingTo:)`` returns a signature only after the
/// persist closure has durably stored the advanced key state.
///
/// ```swift
/// var state: Data? = nil
/// let key = try XMSSMT.PrivateKey(.sha2_h20_2)
/// state = try key.serializedSecretKey            // persist BEFORE first sign
/// let sig = try key.signature(for: message) { state = $0 }
/// ```
///
/// - Important: After generating a key you MUST persist ``PrivateKey/serializedSecretKey``
///   before the first signature, and each sign's persist closure MUST durably
///   store the new state.
public enum XMSSMT: Sendable {
    /// XMSS^MT parameter sets. The raw value is the exact liboqs algorithm name.
    /// The `hH_D` naming is total tree height `H` over `D` layers.
    public enum Variant: String, Sendable, CaseIterable {
        case sha2_h20_2 = "XMSSMT-SHA2_20/2_256"
        case sha2_h20_4 = "XMSSMT-SHA2_20/4_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_h40_2 = "XMSSMT-SHA2_40/2_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_h40_4 = "XMSSMT-SHA2_40/4_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case sha2_h40_8 = "XMSSMT-SHA2_40/8_256"
        /// - Warning: `h60` keygen is infeasible in practice (very large tree). Not feasible in CI.
        case sha2_h60_3 = "XMSSMT-SHA2_60/3_256"
        /// - Warning: `h60` keygen is infeasible in practice (very large tree). Not feasible in CI.
        case sha2_h60_6 = "XMSSMT-SHA2_60/6_256"
        /// - Warning: `h60` keygen is infeasible in practice (very large tree). Not feasible in CI.
        case sha2_h60_12 = "XMSSMT-SHA2_60/12_256"
        case shake128_h20_2 = "XMSSMT-SHAKE_20/2_256"
        case shake128_h20_4 = "XMSSMT-SHAKE_20/4_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake128_h40_2 = "XMSSMT-SHAKE_40/2_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake128_h40_4 = "XMSSMT-SHAKE_40/4_256"
        /// - Warning: `h40` keygen is extremely slow / memory-heavy. Not feasible in CI.
        case shake128_h40_8 = "XMSSMT-SHAKE_40/8_256"
        /// - Warning: `h60` keygen is infeasible in practice. Not feasible in CI.
        case shake128_h60_3 = "XMSSMT-SHAKE_60/3_256"
        /// - Warning: `h60` keygen is infeasible in practice. Not feasible in CI.
        case shake128_h60_6 = "XMSSMT-SHAKE_60/6_256"
        /// - Warning: `h60` keygen is infeasible in practice. Not feasible in CI.
        case shake128_h60_12 = "XMSSMT-SHAKE_60/12_256"
    }

    /// A stateful XMSS^MT signing key. Reference type, intentionally **not**
    /// `Sendable`: it owns mutable one-time-key state.
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
        public init(_ variant: Variant, serializedSecretKey: Data) throws {
            self.variant = variant
            self.engine = try StatefulSigningKey(algorithm: variant.rawValue, serialized: serializedSecretKey)
            self.publicKey = PublicKey(variant, unchecked: engine.publicKey)
        }

        /// The self-contained current-state blob (`publicKey || liboqs-secret-key`).
        public var serializedSecretKey: Data {
            get throws { try engine.serialized }
        }

        /// Number of signatures the key can still produce.
        public var remainingSignatures: UInt64 {
            get throws { try engine.remainingSignatures }
        }

        /// Sign `data`, persisting the advanced key state via `store`. The
        /// signature is returned IF AND ONLY IF `store` returns without throwing.
        public func signature(for data: Data, persistingTo store: (Data) throws -> Void) throws -> Data {
            try engine.signature(for: data, persistingTo: store)
        }
    }

    /// An XMSS^MT public key. Verification is stateless.
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
