import Foundation

/// One datagram on the media lane: a 17-byte cleartext header, the body under
/// ChaCha20-Poly1305 with that header as associated data, then the 16-byte tag.
///
///   [0]      kind: 0 a slice of a video frame, 1 a whole small message, 2 a ping,
///            4 the parity of one frame's slices (see `Parity`)
///   [1..8]   counter: per sender, per session, from 1, +1 every datagram. The
///            AEAD nonce and the replay window both hang off it, and the key it
///            is used under lives exactly as long as it does — see `MediaSeal`.
///   [9..12]  frame id: video only — per connection, +1 per frame sent. Ignored
///            for a message or a ping, and *not* checked: neither end has any
///            use for it there, so there is nothing for a decoder to enforce.
///   [13..14] index of this slice within its frame — or, for a parity, the
///            length of the frame's last slice, 1…1367. A parity has no slot of
///            its own (one per frame) and the slicer writes no length anywhere,
///            so this is where the one number a repair needs rides. The field
///            was already kind-conditional: frame id means nothing for a
///            message, count is pinned to 1 for anything but video.
///   [15..16] slices in the frame: 1…512 for video and parity, exactly 1 else
///
/// 1400 bytes is the datagram ceiling. A real-time stream never leans on IP
/// fragmentation, and 1400 plus UDP/IP headers fits every link this is meant
/// for, AWDL's 1484 included. What the header and the tag leave for the body
/// is 1367.
public enum ChunkHeader {
    public static let size = 17
    public static let datagramMax = 1400
    public static let tag = 16
    public static let body = datagramMax - size - tag   // 1367
    /// A keyframe at 5 Mbit/s is a few hundred KB; 512 slices is 700 KB, past
    /// anything we produce, so more is refused rather than trusted with a buffer.
    public static let maxChunks: UInt16 = 512

    /// 3 is deliberately unallocated: it is the byte the `chunk.unknownKind`
    /// vector uses to prove an unknown kind is refused. A grouped parity — one
    /// per eight slices, say — would have to be a *new* kind (5): a receiver
    /// that knows only 4 would apply a group's parity to the whole frame and
    /// deliver a corrupt one.
    public enum Kind: UInt8 { case video = 0, message = 1, ping = 2, parity = 4 }

    public struct Fields: Equatable {
        public let kind: Kind
        public let counter: UInt64
        public let frameId: UInt32
        public let index: UInt16
        public let count: UInt16

        public init(kind: Kind, counter: UInt64, frameId: UInt32, index: UInt16, count: UInt16) {
            self.kind = kind; self.counter = counter; self.frameId = frameId
            self.index = index; self.count = count
        }
    }

    public static func encode(_ f: Fields) -> Data {
        var out = Data([f.kind.rawValue])
        out.appendBE64(f.counter)
        out.appendBE(f.frameId)
        out.appendBE16(f.index)
        out.appendBE16(f.count)
        return out
    }

    /// Reads the header off the front of a datagram. Network input: the kind
    /// must be one we know and the count 1…512; then what index means, and
    /// what count may be, depends on the kind — a slice's index falls inside
    /// the count, a parity's index is a slice length inside the body, and a
    /// message or ping is exactly one chunk at index 0.
    public static func decode(_ d: Data) -> Fields? {
        guard d.count >= size else { return nil }
        let b = [UInt8](d.prefix(size))
        guard let kind = Kind(rawValue: b[0]) else { return nil }
        let index = Packet.be16(b, 13), count = Packet.be16(b, 15)
        guard count >= 1, count <= maxChunks else { return nil }
        switch kind {
        case .video: guard index < count else { return nil }
        case .parity: guard index >= 1, Int(index) <= body else { return nil }
        case .message, .ping: guard count == 1, index == 0 else { return nil }
        }
        return Fields(kind: kind, counter: Packet.be64(b, 1), frameId: Packet.be32(b, 9),
                      index: index, count: count)
    }
}

/// Cuts a frame into bodies of at most `ChunkHeader.body` bytes. The headers
/// are the transport's to write — counter and frame id are per peer — so a
/// frame is sliced once and sealed once per viewer.
///
/// nil for an empty frame, or one that would need more than 512 slices — which
/// is 699,904 bytes, and a 5K keyframe at high quality can exceed it. **A
/// caller that gets nil must ask the encoder for another keyframe and say so
/// in a log, not return quietly**: dropping the one frame the stream cannot
/// start without, silently, is the whole failure. `count` is a u16, so raising
/// the cap later is a sender-only change.
public enum Chunker {
    public static func slice(_ frame: Data) -> [Data]? {
        let body = ChunkHeader.body
        guard !frame.isEmpty else { return nil }
        let count = (frame.count + body - 1) / body
        guard count <= Int(ChunkHeader.maxChunks) else { return nil }
        return (0 ..< count).map { i in
            let from = frame.startIndex + i * body
            return Data(frame[from ..< min(from + body, frame.endIndex)])
        }
    }
}

/// Puts slices back into frames. One per receiving connection, one thread.
///
/// UDP reorders and loses; H.264 only decodes forward. So only a frame newer
/// than the last one delivered ever comes back, a frame missing a slice is
/// never delivered late, and a partial whose first slice is older than the
/// deadline is scrap — the next refresh is a better use of the air than a frame
/// the clock has already passed. Recovering the picture is the encoder's job.
///
/// Frame ids wrap at 32 bits and are compared by signed distance, so a session
/// that runs long enough to wrap notices nothing.
public struct Reassembler {
    public static let deadline: TimeInterval = 0.1
    /// Partials held at once. At 30 fps eight is a quarter of a second of
    /// frames still arriving, which is more than a link that is working needs.
    public static let maxPartials = 8

    private struct Partial {
        let count: Int
        let firstSeen: TimeInterval
        var slices: [Data?]
        var have = 0
    }

    private var partials: [UInt32: Partial] = [:]
    private var lastDelivered: UInt32?

    public init() {}

    /// One slice in, possibly one whole frame out.
    public mutating func absorb(_ h: ChunkHeader.Fields, body: Data, now: TimeInterval) -> Data? {
        // `Fields` is public and anyone may build one, so every bound is
        // checked here as well as in the decoder.
        guard h.count >= 1, h.count <= ChunkHeader.maxChunks, h.index < h.count,
              body.count <= ChunkHeader.body else { return nil }
        if let last = lastDelivered, !Self.newer(h.frameId, than: last) { return nil }

        partials = partials.filter { now - $0.value.firstSeen <= Self.deadline }

        var partial = partials[h.frameId]
            ?? Partial(count: Int(h.count), firstSeen: now, slices: Array(repeating: nil, count: Int(h.count)))
        // A liar (same id, different count) or a duplicate changes nothing.
        guard partial.count == Int(h.count), partial.slices[Int(h.index)] == nil else { return nil }
        partial.slices[Int(h.index)] = body
        partial.have += 1
        guard partial.have == partial.count else {
            partials[h.frameId] = partial
            // Room for eight. The one furthest behind goes first — it is the
            // one a completing frame would evict anyway.
            while partials.count > Self.maxPartials,
                  let oldest = partials.keys.min(by: { Self.newer($1, than: $0) }) {
                partials[oldest] = nil
            }
            return nil
        }

        // Complete. Everything older is now history it would be wrong to show.
        partials = partials.filter { Self.newer($0.key, than: h.frameId) }
        lastDelivered = h.frameId
        return partial.slices.reduce(into: Data()) { $0.append($1 ?? Data()) }
    }

    /// Frame ids are 32 bits and wrap; "newer" is the signed distance.
    static func newer(_ a: UInt32, than b: UInt32) -> Bool { Int32(bitPattern: a &- b) > 0 }
}

/// Which counters have already been seen, over a sliding window of the most
/// recent `size`. Consulted only *after* a datagram's tag has verified: a
/// forged counter must not be able to mark a real datagram as already seen.
/// Counter 0 is never valid — senders start at 1.
public struct ReplayWindow {
    private var seen: [Bool]
    private var highest: UInt64 = 0

    public init(size: Int = 1024) { seen = Array(repeating: false, count: max(1, size)) }

    public mutating func admit(_ counter: UInt64) -> Bool {
        guard counter != 0 else { return false }
        let size = UInt64(seen.count)
        if counter > highest {
            // The window slides forward: every slot it passes over is fresh again.
            if counter - highest >= size {
                for i in seen.indices { seen[i] = false }
            } else {
                for c in (highest + 1) ... counter { seen[Int(c % size)] = false }
            }
            highest = counter
        } else if highest - counter >= size {
            return false
        }
        let slot = Int(counter % size)
        if seen[slot] { return false }
        seen[slot] = true
        return true
    }
}
