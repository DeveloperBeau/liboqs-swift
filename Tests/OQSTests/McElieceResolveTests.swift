import Testing
@testable import OQS
internal import Cliboqs

@Suite struct McElieceResolveTests {
    @Test("Classic McEliece f-variant names resolve in liboqs")
    func mcElieceFVariantNamesResolve() {
        for name in ["Classic-McEliece-348864f", "Classic-McEliece-460896f",
                     "Classic-McEliece-6688128f", "Classic-McEliece-6960119f",
                     "Classic-McEliece-8192128f"] {
            let kem = OQS_KEM_new(name)
            #expect(kem != nil, "unresolved: \(name)")
            if let kem { OQS_KEM_free(kem) }
        }
    }
}
