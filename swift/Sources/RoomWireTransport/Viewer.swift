import CryptoKit
import Foundation
import Network
import RoomWireProtocol

/// The watching end: browses for hosts, joins one, and holds the session.
///
/// The UDP socket is bound *before* `hello` is sent, because `hello` has to
/// carry the port. That is what lets the host dial the viewer instead of the
/// other way round, and it is why a viewer needs no listener anybody has to
/// find.
public final class Viewer: @unchecked Sendable {
    public enum State: Equatable, Sendable {
        case idle
        case browsing
        case connecting(DiscoveredHost)
        /// Both screens now show `code`. `hostChanged` is true when this host's
        /// name is one we have joined before but the certificate behind it is
        /// not the one it had then — which is what a machine wearing a trusted
        /// host's name looks like, and equally what a reinstalled Mac looks
        /// like, so it is shown rather than refused.
        case awaitingApproval(DiscoveredHost, code: String, hostChanged: Bool)
        case connected(Peer)
        case failed(String)
    }

    public var hosts: [DiscoveredHost] {
        lock.lock(); defer { lock.unlock() }
        return found
    }

    public var state: State {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    public var onHosts: (([DiscoveredHost]) -> Void)?
    public var onState: ((State) -> Void)?
    /// A whole `Packet` message from the host, byte 0 first.
    public var onPacket: ((Data) -> Void)?

    /// Where a host's fingerprint is remembered, by name. A warning aid, not a
    /// secret — anyone can read it, and knowing it grants nothing.
    static let knownHostsKey = "com.roomwire.knownHosts"

    private let identity: Identity
    private let queue = DispatchQueue(label: "roomwire.viewer")
    private let lock = NSLock()
    private var browser: NWBrowser?
    private var found: [DiscoveredHost] = []
    private var current: State = .idle

    private var control: ControlLane?
    private var media: InboundMedia?
    private var target: DiscoveredHost?
    private var token = UUID()
    private var displayName = "?"
    private var hostFingerprint = Data()
    private var hostChanged = false
    private var joinedAt: Date?

    public init(identity: Identity) {
        self.identity = identity
    }

    /// Idempotent, and specifically valid from `.failed`: a refused join is not
    /// a dead viewer, and the way back is to look again.
    public func startBrowsing() {
        lock.lock()
        let alreadyConnected = isConnected(current)
        lock.unlock()
        guard !alreadyConnected else { return }
        if browser == nil {
            let parameters = NWParameters()
            parameters.includePeerToPeer = true
            let browser = NWBrowser(for: .bonjourWithTXTRecord(type: Bonjour.type, domain: nil),
                                    using: parameters)
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                self?.absorb(results)
            }
            browser.start(queue: queue)
            self.browser = browser
        }
        set(.browsing)
    }

    public func stopBrowsing() {
        browser?.cancel()
        browser = nil
        lock.lock()
        found = []
        let browsing = current == .browsing
        lock.unlock()
        onHosts?([])
        if browsing { set(.idle) }
    }

    /// `token` is a fresh random per attempt and is not an identity: it is
    /// committed to in `hello` and revealed afterwards, and that is all it is
    /// for. What identifies this viewer is its certificate.
    public func join(_ host: DiscoveredHost, token: UUID, name: String) {
        leave(quietly: true)
        self.token = token
        displayName = Packet.clampName(name)
        target = host
        joinedAt = Date()
        set(.connecting(host))

        queue.async { [self] in
            // The socket first: its port has to be in the hello.
            guard let inbound = try? InboundMedia(), let port = inbound.start() else {
                return set(.failed("no UDP port"))
            }
            media = inbound
            inbound.onLive = { [weak self] in self?.lanesUp() }
            inbound.onPacket = { [weak self] packet in self?.onPacket?(packet) }
            inbound.onClosed = { [weak self] in self?.fail("the media lane closed") }

            let endpoint = NWEndpoint.service(name: host.serviceName, type: Bonjour.type,
                                              domain: "local.", interface: nil)
            let connection = NWConnection(to: endpoint,
                                          using: TLS.parameters(identity: identity, requirePeer: false,
                                                                queue: queue))
            let lane = ControlLane(connection: connection, queue: queue)
            control = lane
            lane.onReady = { [weak self] fingerprint in
                guard let self else { return }
                hostFingerprint = fingerprint
                hostChanged = Self.known(host.name).map { $0 != fingerprint.hexString } ?? false
                lane.send(Packet.encodeHello(commitment: Pairing.commitment(for: token),
                                             udpPort: port, name: displayName))
            }
            lane.onMessage = { [weak self] message in self?.handle(message, port: port) }
            lane.onClosed = { [weak self] in
                // Closed before a welcome is what a presenter saying no looks
                // like from here — there is no message for a refusal, because
                // sending one would tell an unwanted viewer it was seen.
                self?.fail("declined")
            }
            lane.start()

            queue.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard let self else { return }
                lock.lock()
                let stuck: Bool
                if case .connecting = self.current { stuck = true } else { stuck = false }
                lock.unlock()
                if stuck { fail("timed out") }
            }
        }
    }

    /// Any thread. Video never goes this way — a viewer has none — so
    /// `.unreliable` takes the media lane when it fits one datagram and the
    /// control lane when it does not.
    public func send(_ data: Data, mode: Reliability = .reliable) {
        guard !data.isEmpty else { return }
        queue.async { [self] in
            guard case .connected = current else { return }
            if mode == .unreliable, let media, media.send(message: data) { return }
            control?.send(data)
        }
    }

    /// Valid from anywhere, and from `.awaitingApproval` it cancels the join
    /// outright — the presenter's answer, whenever it comes, arrives to nobody.
    public func leave() {
        leave(quietly: false)
    }

    private func leave(quietly: Bool) {
        control?.onClosed = nil
        control?.close()
        control = nil
        media?.cancel()
        media = nil
        target = nil
        guard !quietly else { return }
        lock.lock()
        let browsing = browser != nil
        lock.unlock()
        set(browsing ? .browsing : .idle)
    }

    private func handle(_ message: Data, port: UInt16) {
        switch Packet.decodeMessage(message) {
        case .hostNonce(let nonce):
            guard let host = target else { return }
            // Reveal only now: the host's contribution is fixed, so neither
            // side got to choose its half after seeing the other's.
            control?.send(Packet.encodeReveal(token: token))
            let code = Pairing.code(hostFingerprint: hostFingerprint,
                                    viewerFingerprint: identity.fingerprint,
                                    token: token, hostNonce: nonce)
            set(.awaitingApproval(host, code: code, hostChanged: hostChanged))

        case .welcome(let hostPort, let key, let fingerprint):
            // The fingerprint here is a cross-check, never a source: the one
            // that counts came out of the TLS handshake. A disagreement is a
            // host contradicting itself, and there is nothing to salvage.
            guard fingerprint == hostFingerprint else {
                return fail("the host's certificate did not match its welcome")
            }
            guard let host = target else { return }
            Self.remember(host.name, fingerprint)
            media?.accept(key: SymmetricKey(data: key), from: hostPort)
            // The host is pinging already; answering is what makes the lane
            // two-way, and its first datagram is what adopts the flow.
            media?.ping()

        case .some:
            guard case .connected = state else { return }
            onPacket?(message)

        case .none:
            fail("the host sent something we could not read")
        }
    }

    /// The first authenticated datagram is what proves the media lane carries;
    /// before that the session is not connected, however far the control lane
    /// has got.
    private func lanesUp() {
        lock.lock()
        let live = isConnected(current)
        lock.unlock()
        guard !live, let host = target else { return }
        media?.ping()
        set(.connected(Peer(id: UUID(), displayName: host.name, fingerprint: hostFingerprint)))
    }

    private func absorb(_ results: Set<NWBrowser.Result>) {
        var seen: [DiscoveredHost] = []
        for result in results {
            guard case .service(let name, _, _, _) = result.endpoint else { continue }
            var version = Bonjour.version
            var display = name
            if case .bonjour(let txt) = result.metadata {
                // A host speaking a version we do not is one to leave alone
                // rather than half-understand.
                if let raw = txt["v"], let parsed = Int(raw) { version = parsed }
                if let advertised = txt["name"], !advertised.isEmpty { display = advertised }
            }
            guard version == Bonjour.version else { continue }
            seen.append(DiscoveredHost(name: display, version: version, serviceName: name))
        }
        let sorted = seen.sorted { $0.name < $1.name }
        lock.lock(); found = sorted; lock.unlock()
        onHosts?(sorted)
    }

    private func fail(_ reason: String) {
        lock.lock()
        var alreadyFailed = false
        if case .failed = current { alreadyFailed = true }
        lock.unlock()
        guard !alreadyFailed else { return }
        control?.onClosed = nil
        control?.close()
        control = nil
        media?.cancel()
        media = nil
        set(.failed(reason))
    }

    private func isConnected(_ state: State) -> Bool {
        if case .connected = state { return true }
        return false
    }

    private func set(_ next: State) {
        lock.lock()
        guard current != next else { return lock.unlock() }
        current = next
        lock.unlock()
        onState?(next)
    }

    // MARK: - Remembered hosts

    static func known(_ name: String) -> String? {
        (UserDefaults.standard.dictionary(forKey: knownHostsKey) as? [String: String])?[name]
    }

    static func remember(_ name: String, _ fingerprint: Data) {
        var all = (UserDefaults.standard.dictionary(forKey: knownHostsKey) as? [String: String]) ?? [:]
        all[name] = fingerprint.hexString
        UserDefaults.standard.set(all, forKey: knownHostsKey)
    }
}
