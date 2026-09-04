import Foundation

// Frames must be presented on the sender's clock, a hold late: jitter inside
// the hold vanishes, a stalled backlog is skipped rather than replayed.
//
// The hold is adaptive, so these assert the properties rather than the
// numbers — that a steady link settles on one hold, that a late frame widens
// it and is still presented, that the buffer stays wide afterwards. A test
// spelling out 0.12 only ever proved nobody had retuned it.
// Run with:  ./check.sh

@main
enum PacerCheck {
    static func main() {
        // A steady 30 fps cadence with steady transit: every frame gets its
        // slot, one hold after it was sent.
        var p = Pacer()
        var steadyHold: Double?
        for k in 0 ..< 30 {
            let t = Double(k) / 30
            guard case .present(let after) = p.admit(remote: t, now: 10 + t).verdict else {
                fatalError("steady frame \(k) not presented")
            }
            // Nothing is ever late, so the hold settles and stays there.
            if let held = steadyHold {
                guard abs(after - held) < 1e-9 else {
                    fatalError("steady frame \(k) held \(after), not \(held)")
                }
            } else {
                steadyHold = after
            }
        }
        guard let steadyHold, steadyHold > 0 else { fatalError("a steady link held nothing") }

        // A late frame widens the buffer that decides its own fate, so it is
        // still presented rather than being the one that stutters — and the
        // measured lateness rides back with the verdict.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        let jittered = p.admit(remote: 1.0 / 30, now: 10 + 1.0 / 30 + 0.05)
        guard case .present(let a1) = jittered.verdict else {
            fatalError("a frame 50 ms late lost its slot")
        }
        assert(abs(jittered.lateness - 0.05) < 1e-9, "lateness not measured: \(jittered.lateness)")
        // after + lateness is the hold this frame was scheduled against, and
        // it has to have grown past what a quiet link settles on.
        assert(a1 + jittered.lateness > steadyHold + 1e-9,
               "the buffer did not widen for a late frame: \(a1 + jittered.lateness)")

        // And it stays wide: the frame after the spike is on time, and is
        // still given more cushion than a link that never stuttered. This is
        // the whole point — a buffer that collapsed here would stutter on the
        // next spike.
        let afterSpike = p.admit(remote: 2.0 / 30, now: 10 + 2.0 / 30)
        guard case .present(let a2) = afterSpike.verdict else {
            fatalError("the frame after a spike was not presented")
        }
        assert(a2 > steadyHold + 1e-9, "the buffer collapsed straight after a spike: \(a2)")
        // A faster frame tightens the mapping and still presents.
        guard case .present = p.admit(remote: 3.0 / 30, now: 10 + 3.0 / 30 - 0.01).verdict else {
            fatalError("faster frame not presented")
        }

        // A 300 ms stall, then the backlog at once: the stale body is decoded
        // silently, the tail inside the hold is presented, in order.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        var dues: [Double] = []
        var shownFrom: Int?
        for k in 1 ... 9 {
            switch p.admit(remote: Double(k) * 0.033, now: 10.3).verdict {
            case .present(let after):
                // Which frame the tail starts at moves with the hold, so what
                // is asserted is the shape: a contiguous tail is shown, in
                // order, and the stale head is not.
                dues.append(after)
                shownFrom = shownFrom ?? k
            case .decodeOnly:
                assert(shownFrom == nil, "frame \(k) hidden after the tail began")
            case .showNow:
                fatalError("burst tripped starvation with a shown frame only 0.3 s ago")
            }
        }
        assert(!dues.isEmpty, "the burst showed nothing at all")
        assert(shownFrom.map { $0 > 1 } ?? false,
               "the whole stale burst was replayed rather than skipped")
        assert(dues == dues.sorted(), "burst tail out of order")

        // A stall much longer than the hold still surfaces a slideshow.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        var pops = 0
        for k in 1 ... 30 {
            let t = Double(k) / 30
            if case .showNow = p.admit(remote: t, now: 10 + t + 1.5).verdict { pops += 1 }
        }
        assert(pops >= 2, "a second and a half of lateness showed \(pops) frames")

        // Lateness that persists is the link's new floor: within a couple of
        // seconds the pacer accepts it and returns to full rate.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        var presentedTail = 0
        for k in 1 ... 120 {
            let t = Double(k) / 30
            if case .present = p.admit(remote: t, now: 10 + t + 0.5).verdict, k > 90 {
                presentedTail += 1
            }
        }
        assert(presentedTail == 30, "full rate not restored after persistent lateness: \(presentedTail)/30")

        // A clock artefact — the 32-bit stamp wrapping backwards — recovers
        // instead of freezing the picture.
        p = Pacer()
        _ = p.admit(remote: 5000, now: 10)
        guard case .present = p.admit(remote: 100, now: 10.033).verdict else {
            fatalError("counter wrap froze the picture")
        }

        print("pacer: all checks passed")
    }
}
