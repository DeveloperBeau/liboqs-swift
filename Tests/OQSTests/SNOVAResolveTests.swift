import Testing
import Foundation
@testable import OQS
internal import Cliboqs

@Suite struct SNOVAResolveTests {

    @Test("All 12 SNOVA names resolve in liboqs")
    func allSNOVANamesResolve() {
        let names = [
            "SNOVA_24_5_4",
            "SNOVA_24_5_4_SHAKE",
            "SNOVA_24_5_4_esk",
            "SNOVA_24_5_4_SHAKE_esk",
            "SNOVA_24_5_5",
            "SNOVA_25_8_3",
            "SNOVA_29_6_5",
            "SNOVA_37_8_4",
            "SNOVA_37_17_2",
            "SNOVA_49_11_3",
            "SNOVA_56_25_2",
            "SNOVA_60_10_4",
        ]
        for name in names {
            let sig = OQS_SIG_new(name)
            #expect(sig != nil, "unresolved: \(name)")
            if let sig { OQS_SIG_free(sig) }
        }
    }
}
