import Testing
import Foundation
@testable import OQS
internal import Cliboqs

@Suite struct MAYOResolveTests {

    @Test("All 4 MAYO names resolve in liboqs")
    func allMAYONamesResolve() {
        let names = [
            "MAYO-1",
            "MAYO-2",
            "MAYO-3",
            "MAYO-5",
        ]
        for name in names {
            let sig = OQS_SIG_new(name)
            #expect(sig != nil, "unresolved: \(name)")
            if let sig { OQS_SIG_free(sig) }
        }
    }
}
