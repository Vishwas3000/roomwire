import CryptoKit
import Foundation

/// The media lane's envelope: ChaCha20-Poly1305 over the body, with the
/// 17-byte header as associated data so a header cannot be re-pointed at
/// another frame without the tag failing.
///
/// Nonce = lane ‖ counter, twelve bytes. Lane 0 is host to viewer, 1 viewer to
/// host, so the two directions never share a nonce under one key; the counter
/// never repeats within a direction; and the key is minted fresh in every
/// `welcome` — **per session, not per viewer** — so a reconnecting viewer never
/// restarts a counter under a key that has already used it.
///
/// Use `Sealer` and `Opener` rather than the two primitives below. They exist
/// because every way of getting this wrong is a way of getting it *quietly*
/// wrong, and all of them are one plausible line of transport code:
///
///  - Both ends sealing lane 0, which one shared `let lane: UInt32 = 0` does.
///    Two directions, one keystream, one counter sequence each: the two streams
///    XOR to plaintext. `Role` is why the lane is derived and never passed.
///  - Two send paths sharing a counter without a lock. A ping from a heartbeat
///    timer and video off the encoder queue are both on the sending lane and
///    both need the next counter; if they can read the same one, that is the
///    same nonce twice. The sealer allocates it under a lock, and callers never
///    see it.
///  - Consulting the replay window before the tag verifies. An off-path
///    attacker then sprays forged datagrams, fills all 1024 slots, and locks
///    out the real ones. The opener owns its window and reaches it only after
///    `open` has succeeded, so the order cannot be written the wrong way round.
public enum MediaSeal {
    /// Which end of the lane this is. Both lane numbers follow from it, which
    /// is the point: a lane is never a parameter anybody can pass wrongly.
    public enum Role: Sendable {
        case host, viewer

        /// The lane this end seals on. Host to viewer is 0.
        public var sendingLane: UInt32 { self == .host ? 0 : 1 }
        /// The lane this end expects to receive on.
        public var receivingLane: UInt32 { self == .host ? 1 : 0 }
    }

    /// The outbound half: owns the counter, hands back a finished datagram.
    /// Safe to call from any queue — a heartbeat and an encoder both do.
    public final class Sealer: @unchecked Sendable {
        private let key: SymmetricKey
        private let lane: UInt32
        private let lock = NSLock()
        private var counter: UInt64 = 0

        public init(key: SymmetricKey, role: Role) {
            self.key = key
            lane = role.sendingLane
        }

        /// `body` must be at most `ChunkHeader.body` bytes; slicing a frame to
        /// that size is `Chunker.slice`'s job.
        public func seal(kind: ChunkHeader.Kind, body: Data,
                         frameId: UInt32 = 0, index: UInt16 = 0, count: UInt16 = 1) -> Data {
            precondition(body.count <= ChunkHeader.body, "a body past the datagram ceiling")
            lock.lock()
            counter += 1
            let next = counter
            lock.unlock()
            // A u64 at sixty frames a second is about sixty-five thousand
            // years, so this cannot happen — and if it does, reusing a nonce is
            // not the way to carry on.
            precondition(next != 0, "the media lane's counter wrapped")
            return MediaSeal.seal(.init(kind: kind, counter: next, frameId: frameId,
                                        index: index, count: count),
                                  body: body, key: key, lane: lane)
        }
    }

    /// The inbound half: bounds, then the tag, then — and only then — the
    /// replay window. One per receiving connection, one thread.
    ///
    /// A class and not a struct, because it owns the replay window. Value
    /// semantics on a window is a way to duplicate one by accident — copy the
    /// opener and each copy forgets what the other admitted — and a replay
    /// window that can be forked is not one.
    public final class Opener {
        private let key: SymmetricKey
        private let lane: UInt32
        private var window: ReplayWindow

        public init(key: SymmetricKey, role: Role, window: Int = 1024) {
            self.key = key
            lane = role.receivingLane
            self.window = ReplayWindow(size: window)
        }

        /// nil for anything that does not open or has been seen before. The
        /// window is consulted last, so a forged counter costs an attacker
        /// nothing and buys them nothing.
        public func open(_ datagram: Data) -> (ChunkHeader.Fields, Data)? {
            guard let (fields, body) = MediaSeal.open(datagram, key: key, lane: lane) else { return nil }
            guard window.admit(fields.counter) else { return nil }
            return (fields, body)
        }
    }

    // MARK: - The primitives. Prefer Sealer and Opener; the vectors use these.

    public static func nonce(lane: UInt32, counter: UInt64) -> Data {
        var out = Data(capacity: 12)
        out.appendBE(lane)
        out.appendBE64(counter)
        return out
    }

    /// The key is 32 bytes by construction (`welcome` carries exactly that);
    /// anything else is a programming error, not network input, and traps.
    public static func seal(_ h: ChunkHeader.Fields, body: Data, key: SymmetricKey, lane: UInt32) -> Data {
        let header = ChunkHeader.encode(h)
        let nonce = try! ChaChaPoly.Nonce(data: nonce(lane: lane, counter: h.counter))
        let box = try! ChaChaPoly.seal(body, using: key, nonce: nonce, authenticating: header)
        return header + box.ciphertext + box.tag
    }

    /// nil for anything that does not open: too short, too long, a header we
    /// refuse, or a tag that does not match — header, body, key, lane and
    /// counter all have to agree. Nothing says which; a datagram is not owed a
    /// reason. This does *not* consult a replay window: `Opener` does, after.
    public static func open(_ datagram: Data, key: SymmetricKey, lane: UInt32) -> (ChunkHeader.Fields, Data)? {
        guard datagram.count >= ChunkHeader.size + ChunkHeader.tag,
              datagram.count <= ChunkHeader.datagramMax,
              let h = ChunkHeader.decode(datagram) else { return nil }
        let header = datagram.prefix(ChunkHeader.size)
        let ciphertext = datagram.dropFirst(ChunkHeader.size).dropLast(ChunkHeader.tag)
        let tag = datagram.suffix(ChunkHeader.tag)
        guard let nonce = try? ChaChaPoly.Nonce(data: nonce(lane: lane, counter: h.counter)),
              let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
              let body = try? ChaChaPoly.open(box, using: key, authenticating: header) else { return nil }
        return (h, body)
    }
}
