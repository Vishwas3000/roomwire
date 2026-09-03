import Foundation
import Network
import RoomWireProtocol

/// One TLS connection, carrying length-prefixed `Packet` messages.
///
/// Everything here happens on `queue`, one connection per instance, so the
/// framing decoder needs no lock. A framing violation — a zero length, or one
/// past 8 MiB — closes the connection rather than being skipped: a peer that is
/// not speaking this protocol is not one to resynchronise with.
final class ControlLane {
    /// A whole message, byte 0 first. On `queue`.
    var onMessage: ((Data) -> Void)?
    /// The handshake finished and the peer's fingerprint is known.
    var onReady: ((Data) -> Void)?
    /// Closed, for any reason, exactly once.
    var onClosed: (() -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var decoder = Framing.Decoder()
    private var closed = false

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    /// The address the peer is at, which is where the host dials the media lane.
    var remoteHost: NWEndpoint.Host? {
        if case .hostPort(let host, _) = connection.currentPath?.remoteEndpoint { return host }
        if case .hostPort(let host, _) = connection.endpoint { return host }
        return nil
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                // A peer with no certificate is one nothing above can decide
                // anything about, so it does not get a connection.
                guard let fingerprint = TLS.peerFingerprint(of: connection) else { return close() }
                onReady?(fingerprint)
            case .failed, .cancelled:
                fire()
            default:
                break
            }
        }
        connection.start(queue: queue)
        receive()
    }

    func send(_ message: Data) {
        guard !closed else { return }
        connection.send(content: Framing.encode(message), completion: .idempotent)
    }

    func close() {
        connection.cancel()
        fire()
    }

    private func fire() {
        guard !closed else { return }
        closed = true
        onClosed?()
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                guard let messages = decoder.feed(data) else {
                    // Not this protocol. Close, and do not guess at the rest.
                    return close()
                }
                for message in messages { onMessage?(message) }
            }
            if done || error != nil { return close() }
            receive()
        }
    }
}
