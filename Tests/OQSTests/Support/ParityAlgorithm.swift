import Foundation

/// One registered liboqs algorithm: its name and a closure that runs the base
/// case through the algorithm's public Swift type. `run` returns the named
/// output fields in the same order as the raw C reference.
struct ParityAlgorithm: Sendable {
    let name: String
    let run: @Sendable () throws -> [(String, Data)]
}
