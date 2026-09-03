import Foundation

// Losing a frame and breaking the stream are not the same event. Getting this
// wrong is either a frozen picture (treating a harmless loss as fatal) or a
// corrupt one (decoding against a frame that never arrived), and neither
// shows up in a compiler. Run with:  ./check.sh

@main
enum ChainGateCheck {
    /// The host's own numbering: base frames advance the base count,
    /// enhancement frames name the base they were built on.
    struct Stream {
        var sequence: UInt16 = 0
        var base: UInt16 = 0
        mutating func next(droppable: Bool) -> (seq: UInt16, base: UInt16, droppable: Bool) {
            sequence &+= 1
            if !droppable { base &+= 1 }
            return (sequence, base, droppable)
        }
    }

    static func main() {
        startsClosed()
        steadyStreamDecodes()
        losingEnhancementFramesIsHarmless()
        losingABaseFrameBreaksIt()
        recoveryReopensIt()
        lossIsCountedEitherWay()
        survivesTheWrap()
        reorderingIsNotLoss()
        duplicatesAreNotLoss()
        lateEnhancementDoesNotBreakTheChain()
        onlyBaseLossCountsAsDamage()
        print("chain gate: all checks passed")
    }

    // Deltas ride unreliable sends, so frames arrive late and occasionally
    // twice. Every one of these cases used to read "one behind" as "65,535
    // ahead" and break the stream. None of the tests above covers them,
    // which is exactly why they were missed.

    /// A packet that turns up late must not be counted as ~65,000 losses.
    static func reorderingIsNotLoss() {
        var g = ChainGate()
        _ = g.admit(sequence: 100, baseSequence: 50, droppable: false, restores: true)
        _ = g.admit(sequence: 102, baseSequence: 51, droppable: false, restores: false)
        let before = g.missing
        let v = g.admit(sequence: 101, baseSequence: 50, droppable: true, restores: false)
        assert(v == .stale, "a late packet was treated as something to decode or repair")
        assert(g.missing == before, "a late packet invented \(g.missing - before) losses")
        assert(g.missing < 100, "loss count ran away: \(g.missing)")
    }

    static func duplicatesAreNotLoss() {
        var g = ChainGate()
        _ = g.admit(sequence: 10, baseSequence: 5, droppable: false, restores: true)
        _ = g.admit(sequence: 11, baseSequence: 6, droppable: false, restores: false)
        let before = g.missing
        let v = g.admit(sequence: 11, baseSequence: 6, droppable: false, restores: false)
        assert(v == .stale, "a duplicate was decoded twice or broke the chain")
        assert(!g.isBroken, "a duplicate broke the chain")
        assert(g.missing == before, "a duplicate invented \(g.missing - before) losses")
    }

    /// The inverse of the whole premise: a frame nothing depends on, whose
    /// reference already arrived, must never break anything by being late.
    static func lateEnhancementDoesNotBreakTheChain() {
        var g = ChainGate()
        _ = g.admit(sequence: 1, baseSequence: 1, droppable: false, restores: true)
        // The next base frame overtakes the enhancement frame before it.
        assert(g.admit(sequence: 3, baseSequence: 2, droppable: false, restores: false) == .decode)
        assert(g.admit(sequence: 2, baseSequence: 1, droppable: true, restores: false) == .stale,
               "a late enhancement frame was decoded out of order")
        assert(!g.isBroken, "a late enhancement frame broke the chain")
        // ...and the stream carries on untouched.
        assert(g.admit(sequence: 4, baseSequence: 3, droppable: false, restores: false) == .decode,
               "the stream stayed broken after a harmless reorder")

        // Two base frames swapping must not leave the marker running
        // backwards, or every frame after them mismatches too.
        var h = ChainGate()
        _ = h.admit(sequence: 1, baseSequence: 1, droppable: false, restores: true)
        _ = h.admit(sequence: 3, baseSequence: 3, droppable: false, restores: false)   // broken, as it should be
        _ = h.admit(sequence: 2, baseSequence: 2, droppable: false, restores: false)   // the late one
        let r = h.admit(sequence: 9, baseSequence: 4, droppable: false, restores: true)
        assert(r == .decode && !h.isBroken, "recovery could not clear a swapped pair")
        assert(h.admit(sequence: 10, baseSequence: 5, droppable: false,
                       restores: false) == .decode, "the base marker was left behind")
    }

    /// Enhancement frames the *host* shed on purpose are loss on the wire but
    /// not damage, and only damage should reach the bitrate governor.
    static func onlyBaseLossCountsAsDamage() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        for i in 0 ..< 40 {
            let f = s.next(droppable: i % 2 == 1)
            if f.droppable { continue }          // shed by the host
            _ = g.admit(sequence: f.seq, baseSequence: f.base, droppable: false, restores: false)
        }
        assert(g.missing > 0, "shedding went entirely unnoticed")
        assert(g.missingBase == 0,
               "frames nothing depends on were counted as damage: \(g.missingBase)")
        assert(!g.isBroken, "shedding enhancement frames broke the chain")
    }

    /// Nothing decodes before something establishes the chain — a delta
    /// against a reference that was never received is corruption, not a
    /// dropped frame.
    static func startsClosed() {
        var g = ChainGate()
        assert(g.isBroken, "a fresh gate let deltas through")
        var s = Stream()
        let f = s.next(droppable: false)
        assert(g.admit(sequence: f.seq, baseSequence: f.base, droppable: false, restores: false) == .broken,
               "decoded a delta before any keyframe")
    }

    static func steadyStreamDecodes() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        assert(g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true) == .decode)
        // 60 frames, alternating base and enhancement, nothing lost.
        for i in 0 ..< 60 {
            let f = s.next(droppable: i % 2 == 1)
            assert(g.admit(sequence: f.seq, baseSequence: f.base,
                           droppable: f.droppable, restores: false) == .decode,
                   "frame \(i) refused on a clean stream")
        }
        assert(!g.isBroken && g.missing == 0, "a clean stream reported damage")
    }

    /// The whole point: half the stream can be lost without breaking anything.
    static func losingEnhancementFramesIsHarmless() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        var decoded = 0
        for i in 0 ..< 60 {
            let f = s.next(droppable: i % 2 == 1)
            if f.droppable { continue }        // lost in the air, and it did not matter
            let v = g.admit(sequence: f.seq, baseSequence: f.base, droppable: false, restores: false)
            assert(v == .decode, "a hole made only of enhancement frames broke the chain")
            decoded += 1
        }
        assert(decoded == 30, "wrong number of base frames survived: \(decoded)")
        assert(!g.isBroken, "still broken after losing only droppable frames")
        // 29, not the 30 that went missing: a hole is only visible once
        // something lands on the far side of it, and the last frame dropped
        // here has nothing after it. Counting it would mean guessing.
        assert(g.missing == 29, "loss went uncounted: \(g.missing)")
    }

    static func losingABaseFrameBreaksIt() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        _ = s.next(droppable: false)          // a base frame, lost
        let after = s.next(droppable: false)
        assert(g.admit(sequence: after.seq, baseSequence: after.base,
                       droppable: false, restores: false) == .broken,
               "a missing base frame was let through")
        // ...and everything after stays broken, including enhancement frames
        // built on the base that never came.
        for i in 0 ..< 10 {
            let f = s.next(droppable: i % 2 == 1)
            assert(g.admit(sequence: f.seq, baseSequence: f.base,
                           droppable: f.droppable, restores: false) == .broken,
                   "the chain healed itself without a restoring frame")
        }
    }

    /// An enhancement frame whose base never arrived is undecodable too —
    /// it names a base ahead of the last one in hand.
    static func enhancementAfterMissingBase() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        _ = s.next(droppable: false)          // base frame, lost
        let e = s.next(droppable: true)       // built on the one that vanished
        assert(g.admit(sequence: e.seq, baseSequence: e.base,
                       droppable: true, restores: false) == .broken,
               "an enhancement frame built on a missing base was decoded")
    }

    static func recoveryReopensIt() {
        enhancementAfterMissingBase()
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        _ = s.next(droppable: false)          // lost
        let broken = s.next(droppable: false)
        assert(g.admit(sequence: broken.seq, baseSequence: broken.base,
                       droppable: false, restores: false) == .broken)

        // A recovery frame restarts from itself, whatever came before.
        let r = s.next(droppable: false)
        assert(g.admit(sequence: r.seq, baseSequence: r.base,
                       droppable: false, restores: true) == .decode,
               "a recovery frame did not reopen the chain")
        assert(!g.isBroken, "still broken after recovery")
        // And the stream continues cleanly from there.
        for i in 0 ..< 10 {
            let f = s.next(droppable: i % 2 == 1)
            assert(g.admit(sequence: f.seq, baseSequence: f.base,
                           droppable: f.droppable, restores: false) == .decode,
                   "frame \(i) refused after recovery")
        }
    }

    static func lossIsCountedEitherWay() {
        var g = ChainGate()
        var s = Stream()
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        for _ in 0 ..< 5 { _ = s.next(droppable: true) }   // five gone
        let f = s.next(droppable: false)
        _ = g.admit(sequence: f.seq, baseSequence: f.base, droppable: false, restores: false)
        assert(g.missing == 5, "miscounted loss: \(g.missing)")

        g.reset()
        assert(g.isBroken && g.missing == 0, "reset left state behind")
    }

    /// 16 bits wrap every few minutes at 30 fps; the arithmetic has to cope
    /// or a session silently breaks itself on the hour.
    static func survivesTheWrap() {
        var g = ChainGate()
        var s = Stream(sequence: 0xFFFD, base: 0xFFFE)
        let k = s.next(droppable: false)
        _ = g.admit(sequence: k.seq, baseSequence: k.base, droppable: false, restores: true)
        for i in 0 ..< 20 {
            let f = s.next(droppable: i % 2 == 1)
            assert(g.admit(sequence: f.seq, baseSequence: f.base,
                           droppable: f.droppable, restores: false) == .decode,
                   "frame \(i) refused across the counter wrap")
        }
        assert(g.missing == 0, "the wrap invented \(g.missing) lost frames")
    }
}
