import CryptoKit
import Foundation

// The media lane's pure half: frames cut into slices and put back together
// byte-identical, in order or shuffled; a hole never delivered; the deadline,
// eviction and room rules; hostile headers refused; the envelope sealing,
// opening, and refusing a flipped bit anywhere; and the replay window.
// Run with:  ./check.sh

@main
enum MediaLaneCheck {
    static func main() {
        chunks()
        seal()
        sealerAndOpener()
        replay()
        print("media lane checks passed")
    }

    /// The composed halves, and the two mistakes they exist to make
    /// unwritable: a lane chosen by hand, and a counter two queues can read at
    /// the same time.
    static func sealerAndOpener() {
        let key = SymmetricKey(size: .bits256)
        let host = MediaSeal.Sealer(key: key, role: .host)
        var viewer = MediaSeal.Opener(key: key, role: .viewer)
        let back = MediaSeal.Sealer(key: key, role: .viewer)
        var hostSide = MediaSeal.Opener(key: key, role: .host)

        // The lane is derived from the role, so each end opens what the other seals.
        let d = host.seal(kind: .video, body: Data([1, 2, 3]), frameId: 4, index: 0, count: 1)
        guard let (fields, body) = viewer.open(d) else { fatalError("the viewer could not open the host's datagram") }
        assert(fields.counter == 1 && body == Data([1, 2, 3]), "first counter is not 1")
        assert(hostSide.open(d) == nil, "the host opened its own outbound datagram")
        let up = back.seal(kind: .ping, body: Data())
        assert(hostSide.open(up) != nil, "the host could not open the viewer's datagram")
        assert(viewer.open(up) == nil, "the viewer opened its own outbound datagram")

        // Seen once. And the window is reached only after the tag, so a forged
        // counter cannot burn a real one — the transcripts pin that too.
        assert(viewer.open(d) == nil, "a replayed datagram was accepted")

        // Two queues, one sealer, no repeated counter. Without the lock this
        // hands the same counter out twice, which is the same nonce twice.
        let sealer = MediaSeal.Sealer(key: key, role: .host)
        let lock = NSLock()
        var counters: Set<UInt64> = []
        let group = DispatchGroup()
        for _ in 0 ..< 4 {
            DispatchQueue.global().async(group: group) {
                for _ in 0 ..< 500 {
                    let datagram = sealer.seal(kind: .ping, body: Data())
                    guard let h = ChunkHeader.decode(datagram) else { fatalError("sealed a datagram we cannot read") }
                    lock.lock(); counters.insert(h.counter); lock.unlock()
                }
            }
        }
        group.wait()
        assert(counters.count == 2000, "the counter was handed out twice: \(counters.count) distinct of 2000")
        assert(counters.min() == 1 && counters.max() == 2000, "counters are not 1…2000")
    }

    static func header(_ id: UInt32, _ index: Int, _ count: Int) -> ChunkHeader.Fields {
        .init(kind: .video, counter: 1, frameId: id, index: UInt16(index), count: UInt16(count))
    }

    static func chunks() {
        var rng = SystemRandomNumberGenerator()
        let frame = Data((0 ..< 200_000).map { _ in UInt8.random(in: 0 ... 255, using: &rng) })
        guard let slices = Chunker.slice(frame) else { fatalError("a 200 KB frame did not slice") }
        assert(slices.count == (frame.count + ChunkHeader.body - 1) / ChunkHeader.body, "slice count wrong: \(slices.count)")
        assert(slices.allSatisfy { $0.count <= ChunkHeader.body }, "a slice exceeds the body")
        assert(slices.reduce(Data(), +) == frame, "slices do not concatenate back to the frame")
        assert(Chunker.slice(Data()) == nil, "an empty frame sliced")
        // The cap is inclusive, and one byte past it is nil — which a caller
        // must turn into a keyframe request, not a silent drop.
        assert(Chunker.slice(Data(repeating: 0, count: ChunkHeader.body * 512))?.count == 512, "512 slices refused")
        assert(Chunker.slice(Data(repeating: 0, count: ChunkHeader.body * 512 + 1)) == nil, "513 slices accepted")

        // In order, the frame comes back byte-identical.
        var r = Reassembler()
        var out: Data?
        for (i, s) in slices.enumerated() { out = r.absorb(header(9, i, slices.count), body: s, now: 100) ?? out }
        assert(out == frame, "in-order reassembly not identical")

        // Shuffled — UDP reorders — still byte-identical.
        r = Reassembler()
        out = nil
        for i in (0 ..< slices.count).shuffled() {
            out = r.absorb(header(9, i, slices.count), body: slices[i], now: 100) ?? out
        }
        assert(out == frame, "shuffled reassembly not identical")

        // A missing slice means the frame is never delivered…
        r = Reassembler()
        for i in slices.indices where i != 3 {
            assert(r.absorb(header(9, i, slices.count), body: slices[i], now: 100) == nil, "delivered with a hole in it")
        }

        // …unless its parity arrived. Any one slice — the first, one in the
        // middle, the short last one — and the frame comes back byte-identical.
        let parity = Parity.of(slices)
        func parityHeader(_ id: UInt32) -> ChunkHeader.Fields {
            .init(kind: .parity, counter: 1, frameId: id, index: UInt16(slices.last!.count), count: UInt16(slices.count))
        }
        for drop in [0, 3, slices.count - 1] {
            r = Reassembler()
            for i in slices.indices where i != drop {
                assert(r.absorb(header(9, i, slices.count), body: slices[i], now: 100) == nil,
                       "delivered with slice \(drop) missing and no parity")
            }
            assert(r.absorb(parityHeader(9), body: parity, now: 100) == frame, "repair of slice \(drop) not identical")
        }
        // Two missing is past one parity: nothing, and no crash.
        r = Reassembler()
        for i in slices.indices where i != 3 && i != 4 { _ = r.absorb(header(9, i, slices.count), body: slices[i], now: 100) }
        assert(r.absorb(parityHeader(9), body: parity, now: 100) == nil, "two holes repaired from one parity")
        // A one-slice frame is its own parity, padded: it delivers alone.
        r = Reassembler()
        let one = Data(frame.prefix(700))
        assert(r.absorb(.init(kind: .parity, counter: 1, frameId: 9, index: 700, count: 1),
                        body: Parity.of([one]), now: 100) == one, "one-slice frame not rebuilt from its parity")
        // A parity that is not exactly the body is refused, whatever it says.
        r = Reassembler()
        assert(r.absorb(parityHeader(9), body: parity.prefix(1366), now: 100) == nil, "short parity accepted")

        // A newer frame completing evicts an older partial for good.
        r = Reassembler()
        let small = Data(frame.prefix(10_000))
        let smallSlices = Chunker.slice(small)!
        for i in 0 ..< slices.count / 2 { _ = r.absorb(header(5, i, slices.count), body: slices[i], now: 100) }
        var delivered: Data?
        for (i, s) in smallSlices.enumerated() {
            delivered = r.absorb(header(6, i, smallSlices.count), body: s, now: 100) ?? delivered
        }
        assert(delivered == small, "newer frame lost")
        for i in slices.count / 2 ..< slices.count {
            assert(r.absorb(header(5, i, slices.count), body: slices[i], now: 100) == nil,
                   "stale frame delivered after a newer one")
        }

        // A partial whose first slice is older than the deadline is scrap.
        r = Reassembler()
        for (i, s) in smallSlices.dropLast().enumerated() {
            _ = r.absorb(header(7, i, smallSlices.count), body: s, now: 200)
        }
        assert(r.absorb(header(7, smallSlices.count - 1, smallSlices.count), body: smallSlices.last!, now: 200.25) == nil,
               "a frame past its deadline was delivered")

        // Room for eight partials: the ninth drops the one furthest behind.
        r = Reassembler()
        for id in 1 ... 9 { _ = r.absorb(header(UInt32(id), 0, 2), body: Data([1]), now: 300) }
        assert(r.absorb(header(1, 1, 2), body: Data([2]), now: 300) == nil, "a dropped partial completed")
        assert(r.absorb(header(9, 1, 2), body: Data([2]), now: 300) == Data([1, 2]), "the newest partial was lost")

        // Ids wrap at 32 bits and nothing notices.
        r = Reassembler()
        assert(r.absorb(header(0xFFFF_FFFF, 0, 1), body: Data([1]), now: 1) != nil, "last id refused")
        assert(r.absorb(header(0, 0, 1), body: Data([1]), now: 1) != nil, "wrap treated as going backwards")
        assert(r.absorb(header(0xFFFF_FFFF, 0, 1), body: Data([1]), now: 1) == nil, "pre-wrap id accepted after the wrap")

        // Hostile headers are refused by the decoder, and again by the
        // reassembler, whose input type anyone can construct.
        assert(ChunkHeader.decode(Data(repeating: 0, count: 16)) == nil, "short header accepted")
        var bad = ChunkHeader.encode(header(1, 0, 1))
        bad[0] = 9
        assert(ChunkHeader.decode(bad) == nil, "unknown kind accepted")
        bad = ChunkHeader.encode(header(1, 0, 1))
        bad[15] = 0; bad[16] = 0
        assert(ChunkHeader.decode(bad) == nil, "zero count accepted")
        bad[15] = 0xFF; bad[16] = 0xFF
        assert(ChunkHeader.decode(bad) == nil, "absurd count accepted")
        bad = ChunkHeader.encode(header(1, 5, 5))
        assert(ChunkHeader.decode(bad) == nil, "index past count accepted")
        bad = ChunkHeader.encode(.init(kind: .message, counter: 1, frameId: 0, index: 0, count: 2))
        assert(ChunkHeader.decode(bad) == nil, "a two-slice message accepted")
        r = Reassembler()
        assert(r.absorb(.init(kind: .video, counter: 1, frameId: 1, index: 0, count: 0), body: Data([1]), now: 1) == nil)
        assert(r.absorb(.init(kind: .video, counter: 1, frameId: 1, index: 2, count: 2), body: Data([1]), now: 1) == nil)
        assert(r.absorb(.init(kind: .video, counter: 1, frameId: 1, index: 0, count: 513), body: Data([1]), now: 1) == nil)
        assert(r.absorb(header(1, 0, 1), body: Data(repeating: 0, count: ChunkHeader.body + 1), now: 1) == nil,
               "oversized body accepted")

        // Random fields and random bodies never crash it — slices and parities.
        for _ in 0 ..< 2000 {
            let h = ChunkHeader.Fields(kind: Bool.random(using: &rng) ? .video : .parity, counter: 1,
                                       frameId: UInt32.random(in: 0 ... 20, using: &rng),
                                       index: UInt16(Int.random(in: 0 ... 600, using: &rng)),
                                       count: UInt16(Int.random(in: 0 ... 600, using: &rng)))
            let n = Int.random(in: 0 ... 1400, using: &rng)
            _ = r.absorb(h, body: Data((0 ..< n).map { _ in UInt8.random(in: 0 ... 255, using: &rng) }), now: 2)
        }
    }

    static func seal() {
        let key = SymmetricKey(size: .bits256)
        let body = Data((0 ..< ChunkHeader.body).map { UInt8(truncatingIfNeeded: $0) })
        let h = ChunkHeader.Fields(kind: .video, counter: 42, frameId: 7, index: 3, count: 10)
        let d = MediaSeal.seal(h, body: body, key: key, lane: 0)
        assert(d.count == ChunkHeader.datagramMax, "a full body is not a 1400-byte datagram: \(d.count)")
        guard let opened = MediaSeal.open(d, key: key, lane: 0) else { fatalError("a sealed datagram did not open") }
        assert(opened.0 == h && opened.1 == body, "the round trip changed something")
        assert(MediaSeal.open(d, key: key, lane: 1) == nil, "opened on the other lane")
        assert(MediaSeal.open(d, key: SymmetricKey(size: .bits256), lane: 0) == nil, "opened with the wrong key")
        // One bit, anywhere: the kind, the counter, the frame id, the count,
        // the first body byte, the middle, the last tag byte.
        for i in [0, 5, 12, 16, 17, 800, d.count - 1] {
            var t = d
            t[i] ^= 0x80
            assert(MediaSeal.open(t, key: key, lane: 0) == nil, "tampered byte \(i) opened")
        }
        assert(MediaSeal.open(d.prefix(32), key: key, lane: 0) == nil, "too short opened")
        assert(MediaSeal.open(d + Data([0]), key: key, lane: 0) == nil, "too long opened")

        // An empty body — a ping — round-trips as 17 + 16 bytes on the viewer's lane.
        let ping = ChunkHeader.Fields(kind: .ping, counter: 1, frameId: 0, index: 0, count: 1)
        let p = MediaSeal.seal(ping, body: Data(), key: key, lane: 1)
        assert(p.count == ChunkHeader.size + ChunkHeader.tag, "ping is not 33 bytes")
        assert(MediaSeal.open(p, key: key, lane: 1)?.1 == Data(), "ping did not round-trip")

        // Random bytes never open and never crash.
        var rng = SystemRandomNumberGenerator()
        for _ in 0 ..< 2000 {
            let n = Int.random(in: 0 ... 1450, using: &rng)
            let junk = Data((0 ..< n).map { _ in UInt8.random(in: 0 ... 255, using: &rng) })
            assert(MediaSeal.open(junk, key: key, lane: 0) == nil, "random bytes opened")
        }
    }

    static func replay() {
        var w = ReplayWindow()
        assert(!w.admit(0), "counter 0 accepted")
        assert(w.admit(1) && w.admit(2) && !w.admit(2), "duplicate accepted")
        assert(w.admit(10) && w.admit(3) && !w.admit(3), "reordered arrival mishandled")
        assert(w.admit(2000) && !w.admit(976) && w.admit(977), "window edge wrong")

        // Slots the window slid past are fresh again; a slot it did not reach stays taken.
        w = ReplayWindow()
        assert(w.admit(2) && w.admit(1000) && w.admit(1026), "a slot the window slid past was not fresh")
        assert(!w.admit(2), "far behind accepted")
        assert(!w.admit(1000), "a counter still inside the window was forgotten")

        // A small window, exhaustively.
        w = ReplayWindow(size: 4)
        for c in 1 ... 5 { assert(w.admit(UInt64(c)), "\(c) refused") }
        assert(!w.admit(1), "1 is 4 behind 5 and outside a window of 4")
        assert(!w.admit(2) && !w.admit(5), "seen counters accepted")
        for c in 6 ... 9 { assert(w.admit(UInt64(c)), "\(c) refused") }
        assert(!w.admit(5) && w.admit(10), "window did not slide")
    }
}
