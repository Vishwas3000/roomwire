import Foundation

// Frames must be presented on the sender's clock, a fixed hold late: jitter
// inside the hold vanishes, a stalled backlog is skipped rather than replayed.
// Run with:  ./check.sh

@main
enum PacerCheck {
    static func main() {
        // A steady 30 fps cadence with steady transit: every frame gets its
        // slot, one hold after it was sent.
        var p = Pacer()
        for k in 0 ..< 30 {
            let t = Double(k) / 30
            guard case .present(let after) = p.admit(remote: t, now: 10 + t).verdict,
                  abs(after - 0.12) < 1e-9 else {
                fatalError("steady frame \(k) not on the clock")
            }
        }

        // Jitter inside the hold keeps the slot: a frame 50 ms late is held
        // 70 ms, so on glass it lands exactly where the clock says — and the
        // measured lateness rides back with the verdict.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        let jittered = p.admit(remote: 1.0 / 30, now: 10 + 1.0 / 30 + 0.05)
        guard case .present(let a1) = jittered.verdict, abs(a1 - 0.07) < 1e-9 else {
            fatalError("jittered frame lost its slot")
        }
        assert(abs(jittered.lateness - 0.05) < 1e-9, "lateness not measured: \(jittered.lateness)")
        // A faster frame tightens the mapping and still presents.
        guard case .present = p.admit(remote: 2.0 / 30, now: 10 + 2.0 / 30 - 0.01).verdict else {
            fatalError("faster frame not presented")
        }

        // A 300 ms stall, then the backlog at once: the stale body is decoded
        // silently, the tail inside the hold is presented, in order.
        p = Pacer()
        _ = p.admit(remote: 0, now: 10)
        var dues: [Double] = []
        for k in 1 ... 9 {
            switch p.admit(remote: Double(k) * 0.033, now: 10.3).verdict {
            case .present(let after):
                assert(k >= 6, "mid-burst frame \(k) presented")
                dues.append(after)
            case .decodeOnly:
                assert(k <= 5, "fresh frame \(k) hidden")
            case .showNow:
                fatalError("burst tripped starvation with a shown frame only 0.3 s ago")
            }
        }
        assert(dues.count == 4, "burst tail miscounted: \(dues.count)")
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
