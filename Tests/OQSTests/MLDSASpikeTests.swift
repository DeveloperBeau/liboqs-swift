import Testing
@testable import OQS
internal import Cliboqs

@Suite(.serialized) struct MLDSASpikeTests {
    @Test("ML-DSA-44 OQS_SIG_new resolves after unity build")
    func mldsa44Resolves() {
        let sig = OQS_SIG_new("ML-DSA-44")
        #expect(sig != nil)
        if let sig { OQS_SIG_free(sig) }
    }
}
