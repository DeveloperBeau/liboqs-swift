import Foundation

/// LMS / HSS stateful hash-based signatures (RFC 8554).
///
/// LMS (and its multi-level HSS variants) is a *stateful* signature scheme: each
/// signature consumes a one-time index that must never be reused. This API makes
/// reuse impossible by construction: ``PrivateKey/signature(for:persistingTo:)``
/// returns a signature only after the persist closure has durably stored the
/// advanced key state.
///
/// The variant naming is `hH_wW`: tree height `H` and Winternitz parameter `W`.
/// Two-level (HSS) variants chain two LMS trees, e.g. `h10_w4_h5_w8`.
///
/// ```swift
/// var state: Data? = nil
/// let key = try LMS.PrivateKey(.sha256_h5_w1)
/// state = try key.serializedSecretKey            // persist BEFORE first sign
/// let sig = try key.signature(for: message) { state = $0 }
/// ```
///
/// - Important: After generating a key you MUST persist ``PrivateKey/serializedSecretKey``
///   before the first signature, and each sign's persist closure MUST durably
///   store the new state.
public enum LMS: Sendable {
    /// LMS / HSS parameter sets. The raw value is the exact liboqs algorithm name.
    public enum Variant: String, Sendable, CaseIterable {
        case sha256_h5_w1 = "LMS_SHA256_H5_W1"
        case sha256_h5_w2 = "LMS_SHA256_H5_W2"
        case sha256_h5_w4 = "LMS_SHA256_H5_W4"
        case sha256_h5_w8 = "LMS_SHA256_H5_W8"
        case sha256_h10_w1 = "LMS_SHA256_H10_W1"
        case sha256_h10_w2 = "LMS_SHA256_H10_W2"
        case sha256_h10_w4 = "LMS_SHA256_H10_W4"
        case sha256_h10_w8 = "LMS_SHA256_H10_W8"
        /// - Warning: `h15` keygen is slow (height-15 tree); generate off the hot path.
        case sha256_h15_w1 = "LMS_SHA256_H15_W1"
        /// - Warning: `h15` keygen is slow; generate off the hot path.
        case sha256_h15_w2 = "LMS_SHA256_H15_W2"
        /// - Warning: `h15` keygen is slow; generate off the hot path.
        case sha256_h15_w4 = "LMS_SHA256_H15_W4"
        /// - Warning: `h15` keygen is slow; generate off the hot path.
        case sha256_h15_w8 = "LMS_SHA256_H15_W8"
        /// - Warning: `h20` keygen is very slow / memory-heavy. Not feasible in CI.
        case sha256_h20_w1 = "LMS_SHA256_H20_W1"
        /// - Warning: `h20` keygen is very slow / memory-heavy. Not feasible in CI.
        case sha256_h20_w2 = "LMS_SHA256_H20_W2"
        /// - Warning: `h20` keygen is very slow / memory-heavy. Not feasible in CI.
        case sha256_h20_w4 = "LMS_SHA256_H20_W4"
        /// - Warning: `h20` keygen is very slow / memory-heavy. Not feasible in CI.
        case sha256_h20_w8 = "LMS_SHA256_H20_W8"
        /// - Warning: `h25` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h25_w1 = "LMS_SHA256_H25_W1"
        /// - Warning: `h25` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h25_w2 = "LMS_SHA256_H25_W2"
        /// - Warning: `h25` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h25_w4 = "LMS_SHA256_H25_W4"
        /// - Warning: `h25` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h25_w8 = "LMS_SHA256_H25_W8"
        case sha256_h5_w8_h5_w8 = "LMS_SHA256_H5_W8_H5_W8"
        /// - Warning: top-level `h10` keygen is slow; generate off the hot path.
        case sha256_h10_w4_h5_w8 = "LMS_SHA256_H10_W4_H5_W8"
        /// - Warning: top-level `h10` keygen is slow; generate off the hot path.
        case sha256_h10_w8_h5_w8 = "LMS_SHA256_H10_W8_H5_W8"
        /// - Warning: top-level `h10` keygen is slow; generate off the hot path.
        case sha256_h10_w2_h10_w2 = "LMS_SHA256_H10_W2_H10_W2"
        /// - Warning: top-level `h10` keygen is slow; generate off the hot path.
        case sha256_h10_w4_h10_w4 = "LMS_SHA256_H10_W4_H10_W4"
        /// - Warning: top-level `h10` keygen is slow; generate off the hot path.
        case sha256_h10_w8_h10_w8 = "LMS_SHA256_H10_W8_H10_W8"
        /// - Warning: top-level `h15` keygen is slow / memory-heavy. Not feasible in CI.
        case sha256_h15_w8_h5_w8 = "LMS_SHA256_H15_W8_H5_W8"
        /// - Warning: top-level `h15` keygen is slow / memory-heavy. Not feasible in CI.
        case sha256_h15_w8_h10_w8 = "LMS_SHA256_H15_W8_H10_W8"
        /// - Warning: top-level `h15` keygen is slow / memory-heavy. Not feasible in CI.
        case sha256_h15_w8_h15_w8 = "LMS_SHA256_H15_W8_H15_W8"
        /// - Warning: top-level `h20` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h20_w8_h5_w8 = "LMS_SHA256_H20_W8_H5_W8"
        /// - Warning: top-level `h20` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h20_w8_h10_w8 = "LMS_SHA256_H20_W8_H10_W8"
        /// - Warning: top-level `h20` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h20_w8_h15_w8 = "LMS_SHA256_H20_W8_H15_W8"
        /// - Warning: top-level `h20` keygen is infeasible in practice. Not feasible in CI.
        case sha256_h20_w8_h20_w8 = "LMS_SHA256_H20_W8_H20_W8"
    }

    /// A stateful LMS signing key. Reference type, intentionally **not**
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

    /// An LMS public key. Verification is stateless.
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
