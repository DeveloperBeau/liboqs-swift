import Foundation

/// Locates frozen test vector files under `Vectors/`.
///
/// The working directory is checked first, since the Android runner copies
/// `Vectors/` next to the test binary. On Android `Bundle.module` is never
/// consulted because it traps when the resource bundle is not on the device.
enum TestVectors {
    static func url(_ name: String, _ ext: String) -> URL? {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        let local = cwd.appendingPathComponent("Vectors").appendingPathComponent("\(name).\(ext)")
        if FileManager.default.fileExists(atPath: local.path) { return local }
        #if os(Android)
        return nil
        #else
        return Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Vectors")
        #endif
    }
}
