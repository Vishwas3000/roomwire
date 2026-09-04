import Foundation
import RoomWireProtocol
import RoomWireTransport

/// The transport, end to end, in one process: two identities that have never
/// met, Bonjour, a pairing code compared on both sides, approval, refusal,
/// fan-out, backpressure, and a rejoin that asks nobody.
///
/// Everything runs against a temporary keychain that is deleted afterwards, so
/// the machine this runs on is left as it was found — and, just as usefully, no
/// dialog appears: a rebuilt ad-hoc binary is a different binary to the login
/// keychain's ACL and it asks about that once per rebuild.
enum Selftest {
    static func run() -> Int32 {
        do {
            let box = try TempKeychain()
            try body(box)
            print("selftest: passed")
            return 0
        } catch {
            print("selftest: FAILED — \(error)")
            return 1
        }
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    static func expect(_ condition: Bool, _ what: String) throws {
        guard condition else { throw Failure(what) }
    }

    /// Polls rather than sleeps a fixed time: the fast path finishes in
    /// milliseconds and only a failure waits the whole timeout.
    @discardableResult
    static func until(_ what: String, _ seconds: TimeInterval = 10,
                      _ condition: () -> Bool) throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 0.02)
        }
        throw Failure("timed out waiting for \(what)")
    }

    static func body(_ box: TempKeychain) throws {
        let hostIdentity = try Identity.load(label: "selftest-host", keychain: box.keychain)
        let host = Host(name: "selftest-host", identity: hostIdentity, trust: RecordingTrust())

        let invites = Locked<[Invite]>([])
        let peers = Locked<[Peer]>([])
        let fromViewers = Locked<[(Peer, Data)]>([])
        let drains = Locked<[Peer]>([])
        host.onInvite = { invite in invites.mutate { $0.append(invite) } }
        host.onConnected = { peers.set($0) }
        host.onPacket = { peer, data in fromViewers.mutate { $0.append((peer, data)) } }
        host.onDrained = { peer in drains.mutate { $0.append(peer) } }
        try host.start()
        defer { host.stop() }

        // A: found over Bonjour, approved, connected.
        let a = try Joiner(label: "selftest-a", keychain: box.keychain)
        a.viewer.startBrowsing()
        let found = try until("A to find the host over Bonjour") {
            a.viewer.hosts.contains { $0.name == "selftest-host" }
        }
        try expect(found, "A never saw the host")
        let discovered = a.viewer.hosts.first { $0.name == "selftest-host" }!
        // Against the constant, not a literal: the point of this line is that
        // what was advertised is what this build speaks, and a hardcoded 1
        // only tested that nobody had bumped it.
        try expect(discovered.version == Bonjour.version,
                   "the TXT record said version \(discovered.version), not \(Bonjour.version)")

        let tokenA = UUID()
        a.viewer.join(discovered, token: tokenA, name: "Viewer A")
        try until("A to reach awaitingApproval") { a.code() != nil }
        try until("the host to raise an invite for A") { invites.get().count == 1 }
        let inviteA = invites.get()[0]
        try expect(inviteA.code == a.code(), "the two ends showed different codes: \(inviteA.code) and \(a.code() ?? "nil")")
        try expect(inviteA.peer.displayName == "Viewer A", "the host saw the wrong name")
        inviteA.respond(true)
        try until("A to connect") { a.isConnected() }
        try until("the host to report one peer") { peers.get().count == 1 }

        // B: a second viewer, so fan-out has somewhere to fan.
        let b = try Joiner(label: "selftest-b", keychain: box.keychain)
        b.viewer.startBrowsing()
        try until("B to find the host") { b.viewer.hosts.contains { $0.name == "selftest-host" } }
        b.viewer.join(b.viewer.hosts.first { $0.name == "selftest-host" }!, token: UUID(), name: "Viewer B")
        try until("an invite for B") { invites.get().count == 2 }
        let inviteB = invites.get()[1]
        try expect(inviteB.code != inviteA.code, "two viewers produced the same pairing code")
        inviteB.respond(true)
        try until("B to connect") { b.isConnected() }
        try until("the host to report two peers") { peers.get().count == 2 }

        // C: refused, and told nothing about why.
        let c = try Joiner(label: "selftest-c", keychain: box.keychain)
        c.viewer.startBrowsing()
        try until("C to find the host") { c.viewer.hosts.contains { $0.name == "selftest-host" } }
        c.viewer.join(c.viewer.hosts.first { $0.name == "selftest-host" }!, token: UUID(), name: "Viewer C")
        try until("an invite for C") { invites.get().count == 3 }
        invites.get()[2].respond(false)
        try until("C to fail") { c.failed() != nil }
        try expect(peers.get().count == 2, "a refused viewer reached the connected set")
        c.viewer.leave()

        // Fan-out: one 200 KB frame, sliced once, sealed twice, byte-identical
        // at both ends.
        let frame = Data([1] + (0 ..< 200_000).map { _ in UInt8.random(in: 0 ... 255) })
        a.received.set([])
        b.received.set([])
        host.send(frame, to: peers.get(), mode: .unreliable)
        try until("A to receive the frame") { a.received.get().contains(frame) }
        try until("B to receive the frame") { b.received.get().contains(frame) }

        // Small messages, both lanes, arriving whole.
        let cursor = Packet.encodeCursor(seq: 7, sentMs: 1234, x: 0.25, y: 0.75)
        host.send(cursor, to: peers.get(), mode: .unreliable)
        try until("A to receive the cursor over the media lane") { a.received.get().contains(cursor) }
        host.send(Packet.identifyMessage, to: peers.get(), mode: .reliable)
        try until("A to receive identify over the control lane") { a.received.get().contains(Packet.identifyMessage) }

        // And back the other way.
        a.viewer.send(Packet.needKeyframeMessage, mode: .unreliable)
        try until("the host to receive needKeyframe from A") {
            fromViewers.get().contains { $0.1 == Packet.needKeyframeMessage }
        }

        // Backpressure: ten frames back to back drain to zero, and the drain
        // edge fires at least once and not once per datagram.
        drains.set([])
        let peerA = peers.get().first { $0.displayName == "Viewer A" }!
        for _ in 0 ..< 10 {
            host.send(Data([1] + (0 ..< 60_000).map { _ in UInt8.random(in: 0 ... 255) }),
                      to: [peerA], mode: .unreliable)
        }
        try until("A's in-flight count to drain", 5) { host.inFlight(to: peerA) == 0 }
        let edges = drains.get().filter { $0 == peerA }.count
        try expect(edges >= 1 && edges <= 12, "drain fired \(edges) times, which is not an edge")
        Thread.sleep(forTimeInterval: 0.3)
        try expect(host.inFlight(to: peerA) == 0, "in-flight did not stay at zero when quiet")

        // A leaves and rejoins on the same token. It is remembered by its
        // certificate, so nobody is asked again.
        let before = invites.get().count
        a.viewer.leave()
        try until("the host to drop A") { peers.get().count == 1 }
        a.viewer.startBrowsing()
        try until("A to find the host again") { a.viewer.hosts.contains { $0.name == "selftest-host" } }
        a.viewer.join(a.viewer.hosts.first { $0.name == "selftest-host" }!, token: tokenA, name: "Viewer A")
        try until("A to reconnect without being asked about", 5) { a.isConnected() }
        try expect(invites.get().count == before, "a remembered viewer raised another invite")

        // Stopping takes everything with it, including the in-flight entries.
        host.stop()
        try until("the connected set to empty") { host.connected.isEmpty }
        try expect(host.inFlight(to: peerA) == 0, "a stopped host still reports in-flight datagrams")
        a.viewer.leave()
        b.viewer.leave()
    }

    /// Approves on first sight and remembers by fingerprint, which is what an
    /// app's own store has to do.
    final class RecordingTrust: TrustStore, @unchecked Sendable {
        private let lock = NSLock()
        private var known: Set<String> = []

        func isApproved(token: UUID, fingerprint: Data) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return known.contains(fingerprint.hexString)
        }

        func approve(token: UUID, fingerprint: Data, name: String) {
            lock.lock(); known.insert(fingerprint.hexString); lock.unlock()
        }
    }

    /// One viewer plus the state it has been through, so assertions can ask
    /// questions of it without racing the callbacks.
    final class Joiner {
        let viewer: Viewer
        let received = Locked<[Data]>([])
        private let states = Locked<[Viewer.State]>([])

        init(label: String, keychain: SecKeychain?) throws {
            viewer = Viewer(identity: try Identity.load(label: label, keychain: keychain))
            viewer.onState = { [states] state in states.mutate { $0.append(state) } }
            viewer.onPacket = { [received] data in received.mutate { $0.append(data) } }
        }

        func code() -> String? {
            for state in states.get().reversed() {
                if case .awaitingApproval(_, let code, _) = state { return code }
            }
            return nil
        }

        func isConnected() -> Bool {
            if case .connected = viewer.state { return true }
            return false
        }

        func failed() -> String? {
            if case .failed(let why) = viewer.state { return why }
            return nil
        }
    }

    /// The smallest thing that makes a value safe to read from a callback on
    /// another queue while the test's own thread polls it.
    final class Locked<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Value

        init(_ value: Value) { self.value = value }

        func get() -> Value {
            lock.lock(); defer { lock.unlock() }
            return value
        }

        func set(_ new: Value) { lock.lock(); value = new; lock.unlock() }

        func mutate(_ change: (inout Value) -> Void) {
            lock.lock(); change(&value); lock.unlock()
        }
    }
}
