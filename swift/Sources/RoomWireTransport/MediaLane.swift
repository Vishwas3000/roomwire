import CryptoKit
import Foundation
import Network
import RoomWireLink
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

    init(to host: NWEndpoint.Host, port: NWEndpoint.Port, key: SymmetricKey, queue: DispatchQueue, reach: Reach) {
        connection = NWConnection(to: .hostPort(host: host, port: port), using: MediaParameters.udp(reach: reach))
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
    func send(frame: Data, parity: Bool = false) -> Bool {
        guard let slices = Chunker.slice(frame) else { return false }
        lock.lock()
        nextFrame &+= 1
        let id = nextFrame
        lock.unlock()
        var sealed = slices.enumerated().map { index, body in
            sealer.seal(kind: .video, body: body, frameId: id,
                        index: UInt16(index), count: UInt16(slices.count))
        }
        // One extra datagram, last in the batch so the receiver has every data
        // slice in hand before it — sent first, it would rebuild the final
        // slice one datagram early on every frame. `index` carries the last
        // slice's length, the one number the rebuild needs and the slicer
        // writes nowhere else. Only when asked: the caller withholds it from
        // the droppable enhancement frames, where a loss costs one frame and
        // breaks no chain and parity would buy least.
        if parity {
            sealed.append(sealer.seal(kind: .parity, body: Parity.of(slices), frameId: id,
                                      index: UInt16(slices.last!.count), count: UInt16(slices.count)))
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
