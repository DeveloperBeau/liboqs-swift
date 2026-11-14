import Testing
import Foundation

/// Always-on coverage check for ParityRegistry. It compares names only and runs
/// no key generation. Each registry name comes from the public type's own
/// `algorithmName`, so equality with the liboqs names also proves that every
/// type reports the name liboqs uses.
@Suite struct ParityRegistryTests {
    @Test("Registry names equal the enabled liboqs KEM and stateless signature names")
    func registryCoversEveryEnabledAlgorithm() {
        let enabled = ParityRegistry.enabledNames()
        check(kind: "KEM", registered: ParityRegistry.kems().map(\.name), enabled: enabled.kems)
        check(kind: "signature", registered: ParityRegistry.sigs().map(\.name), enabled: enabled.sigs)
    }

    private func check(kind: String, registered: [String], enabled: [String]) {
        let duplicates = Dictionary(grouping: registered, by: { $0 }).filter { $1.count > 1 }.keys.sorted()
        let missing = Set(enabled).subtracting(registered).sorted()
        let extra = Set(registered).subtracting(enabled).sorted()
        #expect(duplicates.isEmpty, "duplicate \(kind) registry names: \(duplicates)")
        #expect(missing.isEmpty, "enabled \(kind) names with no registry entry: \(missing)")
        #expect(extra.isEmpty, "registry \(kind) names that liboqs does not enable: \(extra)")
    }
}
