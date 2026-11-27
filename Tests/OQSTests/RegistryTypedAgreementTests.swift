import Testing
import Foundation
@testable import OQS

/// Every typed Swift algorithm agrees with its ``Registry`` description, and
/// every listed name has a typed algorithm. The typed side is driven from
/// ParityRegistry, whose names come from each type's own `algorithmName`, and
/// from the stateful `Variant` cases. So a missing type or a missing
/// description fails. No test here generates a key.
@Suite struct RegistryTypedAgreementTests {

    @Test("Every typed KEM has a description with its name and lengths, and every listed KEM has a typed KEM")
    func kemTypesAgreeWithDescriptions() throws {
        let typed = ParityRegistry.kems()
        for algorithm in typed {
            let d = try #require(Registry.kemDescription(named: algorithm.name), "no description for typed KEM \(algorithm.name)")
            #expect(d.name == algorithm.name)
            let lengths = try algorithm.typedLengths()
            #expect(lengths == TypedLengths(publicKey: d.publicKeyLength, secretKey: d.secretKeyLength, output: d.ciphertextLength),
                    "\(algorithm.name)")
        }
        let typedNames = Set(typed.map(\.name))
        for name in Registry.enabledKEMNames {
            #expect(typedNames.contains(name), "no typed KEM for listed KEM \(name)")
        }
        #expect(typed.count == Registry.enabledKEMNames.count)
    }

    @Test("Every typed signature has a description with its name and lengths, and every listed signature has a typed signature")
    func signatureTypesAgreeWithDescriptions() throws {
        let typed = ParityRegistry.sigs()
        for algorithm in typed {
            let d = try #require(Registry.signatureDescription(named: algorithm.name), "no description for typed signature \(algorithm.name)")
            #expect(d.name == algorithm.name)
            let lengths = try algorithm.typedLengths()
            #expect(lengths == TypedLengths(publicKey: d.publicKeyLength, secretKey: d.secretKeyLength, output: d.signatureLength),
                    "\(algorithm.name)")
        }
        let typedNames = Set(typed.map(\.name))
        for name in Registry.enabledSignatureNames {
            #expect(typedNames.contains(name), "no typed signature for listed signature \(name)")
        }
        #expect(typed.count == Registry.enabledSignatureNames.count)
    }

    // The public key length a stateful public key checks when it verifies.
    // The typed stateful API reports no secret key or signature length
    // without key generation, so only this length is compared here.
    private static func checkedPublicKeyLength(_ verify: () throws -> Bool) throws -> Int {
        try TypedLengths.expectedLength { _ = try verify() }
    }

    @Test("Every stateful Variant case has a description with its name and public key length, and every listed stateful scheme has a case")
    func statefulVariantsAgreeWithDescriptions() throws {
        var typed: [(name: String, publicKeyLength: Int)] = []
        for v in XMSS.Variant.allCases {
            typed.append((v.rawValue, try Self.checkedPublicKeyLength {
                try XMSS.PublicKey(v, rawRepresentation: Data()).isValidSignature(Data(), for: Data())
            }))
        }
        for v in XMSSMT.Variant.allCases {
            typed.append((v.rawValue, try Self.checkedPublicKeyLength {
                try XMSSMT.PublicKey(v, rawRepresentation: Data()).isValidSignature(Data(), for: Data())
            }))
        }
        for v in LMS.Variant.allCases {
            typed.append((v.rawValue, try Self.checkedPublicKeyLength {
                try LMS.PublicKey(v, rawRepresentation: Data()).isValidSignature(Data(), for: Data())
            }))
        }
        for t in typed {
            let d = try #require(Registry.statefulSignatureDescription(named: t.name), "no description for stateful variant \(t.name)")
            #expect(d.name == t.name)
            #expect(d.publicKeyLength == t.publicKeyLength, "\(t.name)")
        }
        let typedNames = Set(typed.map(\.name))
        for name in Registry.enabledStatefulSignatureNames {
            #expect(typedNames.contains(name), "no Variant case for listed stateful scheme \(name)")
        }
        #expect(typed.count == Registry.enabledStatefulSignatureNames.count)
        #expect(typedNames.count == typed.count)
    }
}
