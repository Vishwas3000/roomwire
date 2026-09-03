import CoreGraphics
import Foundation

// The pointer is sampled at 60 Hz, drawn at up to 120, delivered unreliably
// and out of order, and arrives in bursts behind video decoding. Sequencing
// decides what to believe; the glide decides what to draw between arrivals.
// Run with:  ./check.sh

@main
enum CursorMotionCheck {
    static func main() {
        sequencing()
        glide()
        print("cursor motion: all checks passed")
    }

    static func sequencing() {
        assert(isCursorSeqNewer(5, than: 4), "next in order not admitted")
        assert(!isCursorSeqNewer(4, than: 4), "duplicate treated as newer")
        assert(!isCursorSeqNewer(7, than: 10), "stale packet treated as newer")

        // Wraps: 0 follows 65535, not the other way round.
        assert(isCursorSeqNewer(0, than: 65535), "wrap not admitted")
        assert(!isCursorSeqNewer(65535, than: 0), "pre-wrap packet treated as newer")

        // Exactly opposite on the circle: no correct answer, but it has to be
        // stable, not a coin flip that ping-pongs the pointer forever.
        assert(!isCursorSeqNewer(0x8000, than: 0), "half-circle tie not resolved consistently")
    }

    /// The host samples on a 60 Hz metronome; the phone receives in bursts.
    /// The point of the buffer is that the drawn motion follows the former.
    static func glide() {
        // CursorTrack.minHold — what the hold settles to on a link whose
        // delays stay small, which is what these feeds are.
        let hold = 0.05
        let pump = 1.0 / 60     // the host's sampling interval
        let frame = 1.0 / 120   // a ProMotion display frame

        // Nothing to draw before anything has arrived.
        var t = CursorTrack()
        assert(t.position(now: 10) == nil, "drew a pointer before one arrived")
        assert(t.idle(now: 10), "an empty track is not idle")

        // Motion sampled evenly and delivered *unevenly* must still be drawn
        // evenly. The host walks x by 10 every 16.7 ms; arrival is shoved
        // around by up to 30 ms and two packets are dropped outright.
        t = CursorTrack()
        let base = 1000.0
        let jitter = [0.0, 0.021, 0.004, 0.030, 0.012, 0.0, 0.027, 0.008,
                      0.019, 0.002, 0.024, 0.011, 0.006, 0.029, 0.015, 0.003]
        let count = 90
        for i in 0 ..< count {
            let hostAt = Double(i) * pump
            if i == 12 || i == 25 || i == 61 { continue }   // lost in the air
            t.arrived(sentMs: UInt32(1_000_000 + Int(hostAt * 1000)),
                      at: CGPoint(x: CGFloat(i) * 10, y: 0),
                      now: base + hostAt + 0.005 + jitter[i % jitter.count])
        }

        // Read it back at the display's rate and compare against the motion
        // the host actually made. Anchored on the first arrival, so a drawn
        // sample at viewer time v should show the host's position at
        // v - firstArrival - hold.
        var worst = 0.0
        var previousX: CGFloat = -1
        var checked = 0
        var at = base + hold + 0.010
        while at < base + hold + Double(count - 2) * pump {
            guard let drawn = t.position(now: at) else { fatalError("stopped drawing mid-motion") }
            assert(drawn.x >= previousX, "drew backwards: \(drawn.x) after \(previousX)")
            previousX = drawn.x
            // Where the host was at the moment this frame represents.
            let hostMoment = at - (base + 0.005) - hold
            if hostMoment > 0, hostMoment < Double(count - 1) * pump {
                let ideal = CGFloat(hostMoment / pump) * 10
                worst = max(worst, abs(Double(drawn.x - ideal)))
                checked += 1
            }
            at += frame
        }
        assert(checked > 100, "not enough frames compared: \(checked)")
        // One pump step is 10 units. Staying inside a step means the drawn
        // motion tracks the hand, not the radio — including straight across
        // the two dropped packets, whose neighbours bracket the hole.
        assert(worst < 10, "drawn motion strayed \(worst) from the host's own path")

        // Between two arrivals it keeps moving: the whole point is that the
        // frames with no packet behind them are not frozen.
        var moving = CursorTrack()
        moving.arrived(sentMs: 1000, at: CGPoint(x: 0, y: 0), now: 500)
        moving.arrived(sentMs: 1000 + UInt32(pump * 1000), at: CGPoint(x: 60, y: 0), now: 500 + pump)
        let a = moving.position(now: 500 + hold + 0.002)!
        let b = moving.position(now: 500 + hold + 0.010)!
        assert(b.x > a.x, "froze between two known positions: \(a.x) then \(b.x)")
        assert(a.x >= 0, "interpolated before the first position")
        assert(b.x <= 60, "interpolated past the second position")

        // Once the buffer is spent it holds the last real position rather
        // than inventing motion, and says so.
        let parked = moving.position(now: 500 + 5)!
        assert(parked == CGPoint(x: 60, y: 0), "extrapolated past the last position: \(parked)")
        assert(moving.idle(now: 500 + 5), "spent buffer not reported idle")

        // A packet that travelled quicker than the ones before it must not
        // throw the buffer away. Doing so made the buffer behave like no
        // buffer at all — every lucky packet snapped the pointer to the
        // newest position and froze it there, which is the whole fault this
        // exists to fix, so it is worth a guard of its own.
        var quick = CursorTrack()
        for i in 0 ..< 8 {
            quick.arrived(sentMs: UInt32(2000 + i * 16), at: CGPoint(x: CGFloat(i) * 10, y: 0),
                          now: 300 + Double(i) * pump + 0.050)
        }
        // ...then one that arrives with barely any transit delay at all.
        quick.arrived(sentMs: UInt32(2000 + 8 * 16), at: CGPoint(x: 80, y: 0),
                      now: 300 + 8 * pump + 0.001)
        // Still mid-motion, still interpolating between real positions, not
        // parked on the newest one.
        let midway = quick.position(now: 300 + 0.050 + hold + 2 * pump)!
        assert(midway.x > 0 && midway.x < 80,
               "a faster packet dumped the buffer and jumped to the newest position: \(midway.x)")
        assert(!quick.idle(now: 300 + 0.050 + hold + 2 * pump),
               "buffer reported spent while positions were still queued")

        // A stamp that jumps backwards — the 32-bit clock wrapping, or a new
        // session — starts over instead of stranding the pointer forever.
        var wrapped = CursorTrack()
        wrapped.arrived(sentMs: 4_294_967_200, at: CGPoint(x: 1, y: 1), now: 900)
        wrapped.arrived(sentMs: 40, at: CGPoint(x: 2, y: 2), now: 900.1)
        assert(wrapped.position(now: 900.1) != nil, "counter wrap stranded the pointer")

        // The pointer leaving stops the drawing entirely.
        var gone = CursorTrack()
        gone.arrived(sentMs: 5, at: CGPoint(x: 5, y: 5), now: 700)
        gone.clear()
        assert(gone.isEmpty, "clear left samples behind")
        assert(gone.position(now: 700) == nil, "kept drawing a pointer that left")
    }
}
