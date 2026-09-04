import Foundation

/// A device at the other end of a session. `fingerprint` is SHA-256 of its
/// certificate's DER, which is the thing that is actually pinned — the display
/// name is whatever the peer said it was called.
public struct Peer: Hashable, Sendable {
    public let id: UUID
    public let displayName: String
    public let fingerprint: Data

    public init(id: UUID, displayName: String, fingerprint: Data) {
        self.id = id; self.displayName = displayName; self.fingerprint = fingerprint
    }
}

/// Reliable rides the control lane (TCP, in order, never dropped). Unreliable
/// takes the media lane if it fits one datagram and the control lane if it does
/// not, because a message too big for a datagram has nowhere else to go.
public enum Reliability: Sendable { case reliable, unreliable }

/// Where a host remembers who it has admitted. The app owns the storage — this
/// is deliberately the smallest surface that a pairing decision needs, so an
/// app can back it with whatever it already has.
///
/// Both methods are called off the main thread, on the control lane's queue.
public protocol TrustStore: AnyObject {
    /// True when this exact pair has been approved before. A token that is
    /// known but arrives with a *different* certificate is not approved: that
    /// is either a reinstalled phone or somebody wearing its name, and the
    /// presenter gets asked either way.
    func isApproved(token: UUID, fingerprint: Data) -> Bool
    func approve(token: UUID, fingerprint: Data, name: String)
}

/// A viewer asking to be let in. The presenter sees `peer.displayName` and
/// `code`, and the viewer's own screen shows the same six characters; reading
/// one off the other is what rules out a third machine having completed a
/// handshake with each of them separately.
///
/// `respond` may be called from any thread, and exactly once — a second call is
/// ignored. Never calling it leaves the viewer waiting, and the viewer's own
/// 15-second timeout is what ends that.
public struct Invite: Identifiable, Sendable {
    public let id: UUID
    public let peer: Peer
    public let token: UUID
    public let code: String
    public let respond: @Sendable (Bool) -> Void

    public init(id: UUID = UUID(), peer: Peer, token: UUID, code: String,
                respond: @escaping @Sendable (Bool) -> Void) {
        self.id = id; self.peer = peer; self.token = token; self.code = code; self.respond = respond
    }
}

/// A host seen on the local network. `version` is the TXT record's protocol
/// version and only 1 is spoken today; the endpoint it was found at is kept
/// inside, because a Bonjour name is what a dial actually resolves and an app
/// has no use for the rest.
public struct DiscoveredHost: Hashable, Sendable {
    public let name: String
    public let version: Int
    let serviceName: String

    init(name: String, version: Int, serviceName: String) {
        self.name = name; self.version = version; self.serviceName = serviceName
    }
}

/// What the two lanes are advertised and found as.
public enum Bonjour {
    static let type = "_roomwire._tcp"
    /// 2 since ids 26 and 27. Both ends already refuse to *list* a host whose
    /// TXT version differs, so skew is handled by not connecting at all —
    /// which is the mechanism this codebase chose, and it suits a protocol
    /// whose two halves ship together.
    ///
    /// This should be the last bump for an added message. From this version
    /// on, an id past `Packet.highestKnownId` is skipped by a live session
    /// rather than ending it, so anything additive costs nothing.
    public static let version = 2
}
