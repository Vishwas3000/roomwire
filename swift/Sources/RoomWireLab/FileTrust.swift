import Foundation
import RoomWireTransport

/// A trust store in a JSON file, for the lab tool. The app has its own — this
/// exists so `roomwire-lab host` can remember a phone between runs without
/// dragging a real app's storage in.
///
/// Keyed on the certificate fingerprint, and that is the point. The token is
/// sent before anyone has approved anything, so anything keyed on it would
/// admit whoever collected it; the fingerprint is the only thing TLS proved.
/// The token is kept alongside for the record and is never consulted.
final class FileTrust: TrustStore, @unchecked Sendable {
    private struct Entry: Codable {
        let name: String
        let token: String
        let firstSeen: Date
    }

    private let url: URL
    private let lock = NSLock()
    private var entries: [String: Entry]

    init(url: URL) {
        self.url = url
        let data = (try? Data(contentsOf: url)) ?? Data()
        entries = (try? JSONDecoder().decode([String: Entry].self, from: data)) ?? [:]
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count
    }

    func isApproved(token: UUID, fingerprint: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries[fingerprint.hexString] != nil
    }

    func approve(token: UUID, fingerprint: Data, name: String) {
        lock.lock()
        entries[fingerprint.hexString] = Entry(name: name, token: token.uuidString, firstSeen: Date())
        let snapshot = entries
        lock.unlock()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(snapshot) { try? data.write(to: url) }
    }
}

/// Approves everything, for `--auto-approve`. Never in an app.
final class OpenDoor: TrustStore, @unchecked Sendable {
    func isApproved(token: UUID, fingerprint: Data) -> Bool { true }
    func approve(token: UUID, fingerprint: Data, name: String) {}
}
