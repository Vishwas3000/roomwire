import Foundation
import RoomWireTransport
import Security

/// A keychain in a temporary directory, deleted when this goes away.
///
/// The selftest mints three identities and must not leave them behind, and more
/// to the point must not touch the login keychain at all: an ad-hoc binary that
/// has just been rebuilt is a different binary to the login keychain's ACL, and
/// it asks the person at the machine about that — once per rebuild, in a dialog,
/// in the middle of a test run. A keychain we made ourselves has no such
/// opinion.
final class TempKeychain {
    let keychain: SecKeychain
    private let directory: URL

    init() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("roomwire-selftest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("selftest.keychain").path
        var created: SecKeychain?
        // A password, and unlocked on creation: an interactive prompt in a test
        // run is a hang, not a failure.
        let password = UUID().uuidString
        let status = SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &created)
        guard status == errSecSuccess, let created else {
            throw Failure("SecKeychainCreate failed (OSStatus \(status))")
        }
        keychain = created
    }

    deinit {
        SecKeychainDelete(keychain)
        try? FileManager.default.removeItem(at: directory)
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }
}
