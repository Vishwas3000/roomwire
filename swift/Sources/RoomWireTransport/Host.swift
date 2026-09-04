import CryptoKit
import Foundation
import Network
import RoomWireProtocol

/// The presenting end: advertises over Bonjour, admits viewers, and sends to
/// them.
///
/// One `NWListener` for the control lane, and one outbound UDP flow per admitted
/// viewer for the media lane. The host never listens on UDP — it dials the port
/// the viewer named in its `hello` — so there is no session id on the wire,
/// no demultiplexing to write, and a per-viewer send queue for free.
///
/// `send` is callable from any thread, never blocks and never throws, because it
/// stands where the app's old MultipeerConnectivity sender stood and is called
/// off the encoder's queue.
public final class Host: @unchecked Sendable {
    /// The peers with both lanes up, as an authoritative snapshot. A viewer
    /// appears here only once its media lane has carried a datagram in each
    /// direction — not when TLS came up, and not when it was approved.
    public var connected: [Peer] {
        lock.lock(); defer { lock.unlock() }
        return sessions.values.compactMap { $0.state == .live ? $0.peer : nil }
    }

    /// The whole set, on every change. Never a delta.
    public var onConnected: (([Peer]) -> Void)?
    /// A viewer this host has not admitted before. Answer it, or do not — a
    /// viewer that is never answered gives up on its own timeout.
    public var onInvite: ((Invite) -> Void)?
    /// A whole `Packet` message from a viewer, byte 0 first.
    public var onPacket: ((Peer, Data) -> Void)?
    /// This peer's in-flight count reached zero.
    public var onDrained: ((Peer) -> Void)?
    /// The listener stopped, before or after it came up. `start()` returning
    /// is not the same as this host being reachable: `NWListener` reports
    /// almost everything that can go wrong — a refused Bonjour registration,
    /// a local-network denial, a TLS identity it cannot use — asynchronously,
    /// long after `start()` has returned. Without this a host that never
    /// listened is indistinguishable from one nobody has joined yet.
    public var onFailed: ((Error) -> Void)?
    /// True once the listener is `.ready`. Answers "is this host actually
    /// reachable" without waiting for someone to try.
    public private(set) var listening = false

    /// Whether video ignores `mode` and always takes the media lane.
    ///
    /// Off by default, which means `mode` is honoured — and that is the useful
    /// default because a recovery frame sent `.reliable` then goes over TCP,
    /// where it cannot be the one frame that is lost. Turn it on to measure
    /// what the lane does with everything on it.
    public var videoAlwaysUDP = false

    private let name: String
    private let identity: Identity
    private let trust: any TrustStore
    private let queue = DispatchQueue(label: "roomwire.host")
    private let lock = NSLock()
    private var listener: NWListener?
    private var sessions: [UUID: Session] = [:]
    /// At most one viewer may be waiting on the presenter at a time, and only
    /// so many may ask per minute. Per-source-IP limiting was the obvious shape
    /// and it is not a limit on a local network: the attacker picks its own
    /// address, and a /24 is seven hundred and fifty attempts a minute. What is
    /// scarce is the presenter's attention, so that is what is rationed.
    private var invitePending = false
    /// When each viewer last asked, by certificate fingerprint. Counted per
    /// viewer rather than in total, because a person tapping join again is one
    /// person and not five: a flat count turned a handful of honest retries
    /// into a minute of silent refusals, with no prompt on the Mac and no
    /// reason on the phone. Distinct certificates are still capped, which is
    /// the case the limit is for.
    private var recentPrompts: [Data: Date] = [:]
    private var refusingAll = false

    /// What this machine is called, clamped to what a `hello` can carry. A
    /// sensible default for both ends of the lab tool, and for an app that has
    /// nothing better.
    public static func deviceName() -> String {
        Packet.clampName(ProcessInfo.processInfo.hostName
            .replacingOccurrences(of: ".local", with: ""))
    }

    public init(name: String, identity: Identity, trust: any TrustStore) {
        self.name = Packet.clampName(name)
        self.identity = identity
        self.trust = trust
    }

    public func start() throws {
        let parameters = TLS.parameters(identity: identity, requirePeer: true, queue: queue)
        let listener = try NWListener(using: parameters)
        listener.service = NWListener.Service(name: name, type: Bonjour.type,
                                              txtRecord: NWTXTRecord(["v": "\(Bonjour.version)",
                                                                      "name": name]))
        listener.newConnectionHandler = { [weak self] connection in self?.adopt(connection) }
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.listening = true
            case .failed(let error):
                self.listening = false
                self.onFailed?(error)
            case .cancelled:
                self.listening = false
            default:
                break
            }
        }
        listener.start(queue: queue)
        self.listener = listener
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        lock.lock()
        let open = Array(sessions.values)
        sessions = [:]
        lock.unlock()
        for session in open { session.tearDown() }
        announce()
    }

    /// Datagrams handed to the kernel for this peer and not yet accepted by it.
    /// Zero for a peer that has gone, which is why a departed peer's entry is
    /// deleted rather than left at its last value.
    public func inFlight(to peer: Peer) -> Int {
        lock.lock(); defer { lock.unlock() }
        return sessions[peer.id]?.media?.inFlight ?? 0
    }

    /// Stop asking the presenter about new viewers for the rest of this
    /// session. Everything already admitted stays.
    public func stopAsking() {
        lock.lock(); refusingAll = true; lock.unlock()
    }

    /// Any thread. Dead peers are filtered rather than reported: a caller
    /// sending to a list it snapshotted a moment ago is the normal case.
    ///
    /// Routing. Video — byte 0 is 0 or 1 — takes the media lane when
    /// `videoAlwaysUDP` is set, and otherwise does what `mode` asks. Anything
    /// else `.unreliable` goes as a single datagram if it fits one, and over
    /// the control lane if it does not, because a message too big for a
    /// datagram has nowhere else to go. `.reliable` is always the control lane.
    ///
    /// The frame is sliced once here and sealed per peer, because the seal is
    /// per-peer — each has its own key and its own counter — but the slicing is
    /// not. Both happen outside the lock; the lock covers the peer table only.
    public func send(_ data: Data, to peers: [Peer], mode: Reliability = .reliable) {
        guard !data.isEmpty else { return }
        let isVideo = (data.first ?? 0xFF) <= 1
        let overMedia = isVideo ? (videoAlwaysUDP || mode == .unreliable) : mode == .unreliable

        lock.lock()
        let live = peers.compactMap { sessions[$0.id] }.filter { $0.state == .live }
        lock.unlock()

        for session in live {
            guard overMedia, let media = session.media else {
                session.control.send(data)
                continue
            }
            if isVideo {
                // Over 512 slices cannot be sent at all. Say so and ask for
                // another keyframe rather than losing the one frame the stream
                // cannot start without.
                if !media.send(frame: data) {
                    onPacket?(session.peer, Packet.needKeyframeMessage)
                }
            } else if !media.send(message: data) {
                session.control.send(data)
            }
        }
    }

    // MARK: - One viewer, from TLS up to a live session

    private enum Stage { case handshaking, awaitingHello, awaitingReveal, deciding, admitted, live }

    private final class Session {
        let id = UUID()
        let control: ControlLane
        var media: OutboundMedia?
        var state: Stage = .handshaking
        var fingerprint = Data()
        var commitment = Data()
        var token = UUID()
        var displayName = "?"
        var viewerPort: UInt16 = 0
        let hostNonce = Data((0 ..< 16).map { _ in UInt8.random(in: 0 ... 255) })
        var answered = false
        var pinger: DispatchSourceTimer?

        var peer: Peer { Peer(id: id, displayName: displayName, fingerprint: fingerprint) }

        init(control: ControlLane) { self.control = control }

        func tearDown() {
            pinger?.cancel()
            pinger = nil
            media?.cancel()
            media = nil
            control.close()
        }
    }

    private func adopt(_ connection: NWConnection) {
        let control = ControlLane(connection: connection, queue: queue)
        let session = Session(control: control)
        lock.lock(); sessions[session.id] = session; lock.unlock()

        control.onReady = { [weak self, weak session] fingerprint in
            guard let self, let session else { return }
            session.fingerprint = fingerprint
            session.state = .awaitingHello
            // A connection that says nothing is a connection holding a slot.
            queue.asyncAfter(deadline: .now() + 5) { [weak session] in
                guard let session, session.state == .awaitingHello else { return }
                self.drop(session)
            }
        }
        control.onMessage = { [weak self, weak session] message in
            guard let self, let session else { return }
            handle(message, on: session)
        }
        control.onClosed = { [weak self, weak session] in
            guard let self, let session else { return }
            drop(session)
        }
        control.start()
    }

    private func handle(_ message: Data, on session: Session) {
        switch Packet.decodeMessage(message) {
        case .hello(let commitment, let port, let name) where session.state == .awaitingHello:
            session.commitment = commitment
            session.viewerPort = port
            session.displayName = name
            session.state = .awaitingReveal
            // The host's half of the pairing code goes out before approval, so
            // the viewer can show the code while the presenter is deciding.
            session.control.send(Packet.encodeHostNonce(session.hostNonce))

        case .reveal(let token) where session.state == .awaitingReveal:
            // A viewer that cannot produce the preimage of its own commitment
            // is either broken or steering the code, and the two look the same
            // from here.
            guard Pairing.opens(commitment: session.commitment, token: token) else {
                return drop(session)
            }
            session.token = token
            session.state = .deciding
            decide(session)

        case .some(let decoded) where session.state == .live:
            // Everything the transport does not consume goes up whole.
            _ = decoded
            onPacket?(session.peer, message)

        default:
            // A newer peer sending something this build has no case for, once
            // the session is up: skipped, not fatal. Additive ids are then
            // free forever, and only the version that introduces the tolerance
            // itself needs a Bonjour bump.
            //
            // A *malformed known* message is still fatal, which is why this
            // reads byte 0 rather than trusting the nil from decodeMessage:
            // the two are indistinguishable there, and a peer that cannot
            // encode what it claims to be sending is not one to guess at.
            if session.state == .live, let id = message.first, id > Packet.highestKnownId {
                return
            }
            // Out of order, unknown, or before the session was live. A control
            // lane that is not following the sequence is not one to guess at.
            drop(session)
        }
    }

    private func decide(_ session: Session) {
        if trust.isApproved(token: session.token, fingerprint: session.fingerprint) {
            return admit(session)
        }
        lock.lock()
        let now = Date()
        recentPrompts = recentPrompts.filter { now.timeIntervalSince($0.value) <= 60 }
        // A viewer already counted in this window is re-asking, not arriving.
        let seenBefore = recentPrompts[session.fingerprint] != nil
        let refuse = refusingAll || invitePending || (!seenBefore && recentPrompts.count >= 5)
        if !refuse {
            invitePending = true
            recentPrompts[session.fingerprint] = now
        }
        lock.unlock()
        guard !refuse else { return drop(session) }

        let code = Pairing.code(hostFingerprint: identity.fingerprint,
                                viewerFingerprint: session.fingerprint,
                                token: session.token, hostNonce: session.hostNonce)
        let invite = Invite(peer: session.peer, token: session.token, code: code) { [weak self, weak session] yes in
            guard let self else { return }
            queue.async { [weak session] in
                guard let session, !session.answered else { return }
                session.answered = true
                self.lock.lock(); self.invitePending = false; self.lock.unlock()
                guard yes else { return self.drop(session) }
                self.trust.approve(token: session.token, fingerprint: session.fingerprint,
                                   name: session.displayName)
                self.admit(session)
            }
        }
        onInvite?(invite)
    }

    /// A fresh key per session, never one kept against a remembered viewer: a
    /// key that outlived its control connection would be used twice with
    /// counters that restart at 1.
    private func admit(_ session: Session) {
        guard session.state == .deciding || session.state == .awaitingReveal,
              let host = session.control.remoteHost,
              let port = NWEndpoint.Port(rawValue: session.viewerPort) else { return drop(session) }
        session.state = .admitted
        let key = SymmetricKey(size: .bits256)
        let media = OutboundMedia(to: host, port: port, key: key, queue: queue)
        session.media = media

        media.onReady = { [weak self, weak session] localPort in
            guard let self, let session else { return }
            session.control.send(Packet.encodeWelcome(
                udpPort: localPort,
                mediaKey: key.withUnsafeBytes { Data($0) },
                hostFingerprint: identity.fingerprint))
            // Ping until the viewer answers on the lane. Until it does, the
            // media path is only half proven — a NAT or a firewall between
            // them shows up exactly here and nowhere earlier.
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 0.1, repeating: 0.5)
            let deadline = Date().addingTimeInterval(10)
            timer.setEventHandler { [weak self, weak session] in
                guard let self, let session else { return }
                guard session.state != .live else { return }
                guard Date() < deadline else { return drop(session) }
                session.media?.ping()
            }
            timer.resume()
            session.pinger = timer
        }
        media.onDatagram = { [weak self, weak session] fields, body in
            guard let self, let session else { return }
            if session.state != .live {
                session.state = .live
                session.pinger?.cancel()
                session.pinger = nil
                announce()
            }
            // A ping is liveness and nothing else; a message goes up whole. The
            // viewer never sends video, so a video datagram from one is noise.
            if fields.kind == .message, !body.isEmpty {
                onPacket?(session.peer, body)
            }
        }
        media.onDrained = { [weak self, weak session] in
            guard let self, let session, session.state == .live else { return }
            onDrained?(session.peer)
        }
        media.onClosed = { [weak self, weak session] in
            guard let self, let session else { return }
            drop(session)
        }
        media.start()
    }

    /// Either lane closing takes both, and the peer's in-flight entry with them.
    private func drop(_ session: Session) {
        lock.lock()
        let known = sessions.removeValue(forKey: session.id) != nil
        if !session.answered { invitePending = false }
        lock.unlock()
        guard known else { return }
        session.answered = true
        let wasLive = session.state == .live
        session.state = .handshaking
        session.tearDown()
        if wasLive { announce() }
    }

    private func announce() {
        onConnected?(connected)
    }
}
