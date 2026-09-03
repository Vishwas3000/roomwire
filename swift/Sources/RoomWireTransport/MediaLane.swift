import CryptoKit
import Foundation
import Network
import RoomWireProtocol

/// The host's end of one viewer's media lane: a single outbound UDP flow,
/// dialled at the port the viewer put in its `hello`.
///
/// One socket per viewer, and the host never listens. That is the whole design
/// of this lane. The kernel demultiplexes by 5-tuple, so there is no session id
/// on the wire and nothing to match a datagram against; each viewer gets its own
/// send queue, so one slow phone cannot hold up another; and `.contentProcessed`
/// on this connection is a per-viewer in-flight count, which is the
/// backpressure number a shared socket cannot give.
///
/// It receives as well as sends: a flow dialled outbound is a two-way 5-tuple,
/// so the viewer's pings and small messages arrive here.
final class OutboundMedia {
    /// A datagram that opened and was not a replay. On `queue`.
    var onDatagram: ((ChunkHeader.Fields, Data) -> Void)?
    /// The flow is up and this is the local port to put in `welcome`.
    var onReady: ((UInt16) -> Void)?
    var onClosed: (() -> Void)?
    /// The in-flight count fell to zero. On `queue`.
    var onDrained: (() -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let sealer: MediaSeal.Sealer
    private let opener: MediaSeal.Opener
    private let lock = NSLock()
    private var pending = 0
    private var nextFrame: UInt32 = 0
    private var closed = false

    init(to host: NWEndpoint.Host, port: NWEndpoint.Port, key: SymmetricKey, queue: DispatchQueue) {
        connection = NWConnection(to: .hostPort(host: host, port: port), using: TLS.udp())
        self.queue = queue
        sealer = MediaSeal.Sealer(key: key, role: .host)
        opener = MediaSeal.Opener(key: key, role: .host)
    }

    /// Datagrams handed to the kernel but not yet accepted by it. Note what
    /// this is not: `.contentProcessed` fires on kernel acceptance, not on the
    /// radio actually sending, so this is the depth of our own queue and not a
    /// measure of the air.
    var inFlight: Int {
        lock.lock(); defer { lock.unlock() }
        return pending
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard let port = localPort() else { return cancel() }
                onReady?(port)
            case .failed, .cancelled:
                fire()
            default:
                break
            }
        }
        connection.start(queue: queue)
        receive()
    }

    /// Whatever port the kernel gave this flow. Before `.ready` it reads 0,
    /// which dials nowhere, so a `welcome` must never be built from it early.
    private func localPort() -> UInt16? {
        guard case .hostPort(_, let port) = connection.currentPath?.localEndpoint,
              port.rawValue != 0 else { return nil }
        return port.rawValue
    }

    /// One frame, sliced and sealed. The frame id belongs to this connection,
    /// which is why the transport assigns it and not the app: two viewers
    /// receiving the same frame need not agree about what it is called, and a
    /// reassembler only ever sees one sender.
    ///
    /// Returns false when the frame cannot be sliced — over 512 slices — so the
    /// caller can ask the encoder for another keyframe rather than lose one
    /// silently.
    @discardableResult
    func send(frame: Data) -> Bool {
        guard let slices = Chunker.slice(frame) else { return false }
        lock.lock()
        nextFrame &+= 1
        let id = nextFrame
        lock.unlock()
        let sealed = slices.enumerated().map { index, body in
            sealer.seal(kind: .video, body: body, frameId: id,
                        index: UInt16(index), count: UInt16(slices.count))
        }
        hand(over: sealed)
        return true
    }

    /// A small message, whole, in one datagram. False when it does not fit —
    /// the caller then sends it on the control lane instead.
    @discardableResult
    func send(message: Data) -> Bool {
        guard message.count <= ChunkHeader.body else { return false }
        hand(over: [sealer.seal(kind: .message, body: message)])
        return true
    }

    func ping() {
        hand(over: [sealer.seal(kind: .ping, body: Data())])
    }

    /// The in-flight count is raised for the whole batch before any of it is
    /// handed over, so a completion that lands mid-loop cannot see zero and
    /// fire a spurious drain.
    private func hand(over datagrams: [Data]) {
        guard !closed, !datagrams.isEmpty else { return }
        lock.lock()
        pending += datagrams.count
        lock.unlock()
        for datagram in datagrams {
            connection.send(content: datagram, completion: .contentProcessed { [weak self] _ in
                guard let self else { return }
                lock.lock()
                pending -= 1
                let drained = pending == 0
                lock.unlock()
                if drained { onDrained?() }
            })
        }
    }

    func cancel() {
        closed = true
        connection.cancel()
    }

    private func fire() {
        guard !closed else { return }
        closed = true
        onClosed?()
    }

    private func receive() {
        connection.receiveMessage { [weak self] datagram, _, _, error in
            guard let self else { return }
            if let datagram, let opened = opener.open(datagram) {
                onDatagram?(opened.0, opened.1)
            }
            if error != nil { return fire() }
            receive()
        }
    }
}

/// The viewer's end: a UDP listener bound before `hello` is even sent, so the
/// port can go in it, and then locked to the one flow the host dials.
///
/// Only one flow is ever adopted, and only from the port `welcome` named.
/// Anything else on that socket is somebody else's traffic and is dropped
/// without a connection being kept for it.
final class InboundMedia {
    /// A whole `Packet` message: a reassembled video frame, or a small message
    /// that travelled in one datagram. Never a slice — the header is stripped
    /// and the frame is whole, so the app sees byte 0 of a Packet first and
    /// nothing above this ever learns the lane exists.
    var onPacket: ((Data) -> Void)?
    /// Any datagram that opened and was not a replay. The first one is what
    /// proves the lane carries in this direction, which is what a session
    /// being connected actually means.
    var onLive: (() -> Void)?
    var onClosed: (() -> Void)?

    private let listener: NWListener
    /// Its own queue, and that is not a detail. `start` has to block until the
    /// listener has a port — `hello` cannot be written without one — and if it
    /// blocked the queue the listener reports readiness on, it would be waiting
    /// for a callback it is itself preventing. That deadlock is what this
    /// separate queue exists to make impossible.
    private let queue = DispatchQueue(label: "roomwire.viewer.media")
    private var flow: NWConnection?
    private var sealer: MediaSeal.Sealer?
    private var opener: MediaSeal.Opener?
    /// One sender, one flow, so one reassembler and no lock: everything here
    /// runs on this instance's own queue.
    private var reassembler = Reassembler()
    /// Set from `welcome`. Until it is, nothing is adopted.
    private var expectedPort: UInt16?
    private var closed = false

    init() throws {
        listener = try NWListener(using: TLS.udp())
    }

    /// The port to advertise in `hello`. Blocks the calling thread until the
    /// listener has one, because `hello` cannot be written without it.
    func start(timeout: TimeInterval = 5) -> UInt16? {
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in self?.adopt(connection) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + timeout) == .success,
              let port = listener.port?.rawValue, port != 0 else { return nil }
        return port
    }

    /// Called once `welcome` has been read and checked: the key for this
    /// session and the only remote port worth listening to.
    func accept(key: SymmetricKey, from port: UInt16) {
        queue.async { [self] in
            sealer = MediaSeal.Sealer(key: key, role: .viewer)
            opener = MediaSeal.Opener(key: key, role: .viewer)
            expectedPort = port
        }
    }

    /// Answers the host's ping, which is what tells it the lane is two-way.
    func ping() {
        queue.async { [self] in
            guard let sealer, let flow else { return }
            flow.send(content: sealer.seal(kind: .ping, body: Data()), completion: .idempotent)
        }
    }

    func send(message: Data) -> Bool {
        guard message.count <= ChunkHeader.body else { return false }
        queue.async { [self] in
            guard let sealer, let flow else { return }
            flow.send(content: sealer.seal(kind: .message, body: message), completion: .idempotent)
        }
        return true
    }

    func cancel() {
        closed = true
        flow?.cancel()
        listener.cancel()
    }

    private func adopt(_ connection: NWConnection) {
        // Before `welcome`, or from any port other than the one it named, this
        // is not the host. Refuse it rather than hold a socket open for it.
        guard !closed, flow == nil, let expectedPort,
              case .hostPort(_, let port) = connection.endpoint, port.rawValue == expectedPort else {
            connection.cancel()
            return
        }
        flow = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .failed = state { closedOnce() }
            if case .cancelled = state { closedOnce() }
        }
        connection.start(queue: queue)
        receive(on: connection)
    }

    private func closedOnce() {
        guard !closed else { return }
        closed = true
        onClosed?()
    }

    private func receive(on connection: NWConnection) {
        connection.receiveMessage { [weak self] datagram, _, _, error in
            guard let self else { return }
            if let datagram, let (fields, body) = opener?.open(datagram) {
                onLive?()
                switch fields.kind {
                case .video:
                    // Slices in, whole frames out, and only frames newer than
                    // the last one delivered. A frame with a hole in it is
                    // never handed up late: recovering the picture is the
                    // encoder's job, not this one's.
                    if let frame = reassembler.absorb(fields, body: body,
                                                      now: ProcessInfo.processInfo.systemUptime) {
                        onPacket?(frame)
                    }
                case .message:
                    if !body.isEmpty { onPacket?(body) }
                case .ping:
                    break
                }
            }
            if error != nil { return closedOnce() }
            receive(on: connection)
        }
    }
}
