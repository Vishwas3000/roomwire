import CryptoKit
import Foundation
import Network
import RoomWireProtocol

/// Plain UDP parameters, peer-to-peer enabled — no DTLS, no certificates.
///
/// The media lane's confidentiality is `MediaSeal` (ChaCha20-Poly1305), never
/// transport TLS. That is the whole reason this lane can live in a module an
/// iOS build links without swift-certificates/BoringSSL, while the control
/// lane's mutual TLS stays quarantined in RoomWireTransport (macOS only).
public enum MediaParameters {
    public static func udp() -> NWParameters {
        let parameters = NWParameters(dtls: nil, udp: NWProtocolUDP.Options())
        parameters.includePeerToPeer = true
        return parameters
    }
}

/// The viewer's end: a UDP listener bound before `hello` is even sent, so the
/// port can go in it, and then locked to the one flow the host dials.
///
/// Only one flow is ever adopted, and only from the port `welcome` named.
/// Anything else on that socket is somebody else's traffic and is dropped
/// without a connection being kept for it.
public final class InboundMedia {
    /// A whole `Packet` message: a reassembled video frame, or a small message
    /// that travelled in one datagram. Never a slice — the header is stripped
    /// and the frame is whole, so the app sees byte 0 of a Packet first and
    /// nothing above this ever learns the lane exists.
    public var onPacket: ((Data) -> Void)?
    /// Any datagram that opened and was not a replay. The first one is what
    /// proves the lane carries in this direction, which is what a session
    /// being connected actually means.
    public var onLive: (() -> Void)?
    public var onClosed: (() -> Void)?

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

    public init() throws {
        listener = try NWListener(using: MediaParameters.udp())
    }

    /// The port to advertise in `hello`. Blocks the calling thread until the
    /// listener has one, because `hello` cannot be written without it.
    public func start(timeout: TimeInterval = 5) -> UInt16? {
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
    public func accept(key: SymmetricKey, from port: UInt16) {
        queue.async { [self] in
            sealer = MediaSeal.Sealer(key: key, role: .viewer)
            opener = MediaSeal.Opener(key: key, role: .viewer)
            expectedPort = port
        }
    }

    /// Answers the host's ping, which is what tells it the lane is two-way.
    public func ping() {
        queue.async { [self] in
            guard let sealer, let flow else { return }
            flow.send(content: sealer.seal(kind: .ping, body: Data()), completion: .idempotent)
        }
    }

    public func send(message: Data) -> Bool {
        guard message.count <= ChunkHeader.body else { return false }
        queue.async { [self] in
            guard let sealer, let flow else { return }
            flow.send(content: sealer.seal(kind: .message, body: message), completion: .idempotent)
        }
        return true
    }

    public func cancel() {
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
                case .video, .parity:
                    // Slices in, whole frames out, and only frames newer than
                    // the last one delivered. One hole is filled from the
                    // frame's parity if it came; more than one is never handed
                    // up late — recovering the picture past that is the
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
