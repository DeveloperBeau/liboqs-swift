import Testing
import Foundation
@testable import OQS
internal import Cliboqs

@Suite struct PrehashResolveTests {

    @Test("All 144 SLH-DSA prehash names resolve in liboqs")
    func allPrehashNamesResolve() {
        for fn in SLHDSA.Prehash.Function.allCases {
            for ps in SLHDSA.Prehash.ParamSet.allCases {
                let name = SLHDSA.Prehash.algorithmName(fn, ps)
                let sig = OQS_SIG_new(name)
                #expect(sig != nil, "unresolved: \(name)")
                if let sig { OQS_SIG_free(sig) }
            }
        }
    }
}
