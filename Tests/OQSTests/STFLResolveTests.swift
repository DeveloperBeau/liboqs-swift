import Testing
import Foundation
@testable import OQS
internal import Cliboqs

/// Name-resolution checks for all 70 stateful-signature variants. Cheap and safe:
/// `OQS_SIG_STFL_new` only allocates the algorithm vtable, no keygen.
@Suite struct STFLResolveTests {

    private func resolve(_ name: String) {
        let sig = OQS_SIG_STFL_new(name)
        #expect(sig != nil, "unresolved: \(name)")
        if let sig { OQS_SIG_STFL_free(sig) }
        let sk = OQS_SIG_STFL_SECRET_KEY_new(name)
        #expect(sk != nil, "secret-key unresolved: \(name)")
        if let sk { OQS_SIG_STFL_SECRET_KEY_free(sk) }
    }

    @Test("All 21 XMSS variants resolve")
    func xmssResolve() {
        #expect(XMSS.Variant.allCases.count == 21)
        for v in XMSS.Variant.allCases { resolve(v.rawValue) }
    }

    @Test("All 16 XMSSMT variants resolve")
    func xmssmtResolve() {
        #expect(XMSSMT.Variant.allCases.count == 16)
        for v in XMSSMT.Variant.allCases { resolve(v.rawValue) }
    }

    @Test("All 33 LMS variants resolve")
    func lmsResolve() {
        #expect(LMS.Variant.allCases.count == 33)
        for v in LMS.Variant.allCases { resolve(v.rawValue) }
    }

    @Test("Total stateful variant count is 70")
    func totalCount() {
        let total = XMSS.Variant.allCases.count
            + XMSSMT.Variant.allCases.count
            + LMS.Variant.allCases.count
        #expect(total == 70)
    }
}
