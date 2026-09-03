import CoreGraphics
import Foundation

/// Wraparound-safe "is `a` newer than `b`" for a 16-bit sequence counter —
/// the standard RFC1982 serial comparison: half the space counts as ahead of
/// `b`, half counts as behind. The cursor rides unreliable delivery, so
/// packets can arrive out of order or duplicated; video is sent reliably and
/// so is checked with plain equality against what's expected next instead.
public func isCursorSeqNewer(_ a: UInt16, than b: UInt16) -> Bool {
    a != b && a &- b < 0x8000
}

/// Replays the pointer on the clock it was sampled on, a fixed hold late.
///
/// Measured on a real Mac -> iPhone session: the host's pump is a metronome
/// (16.0 ms between samples, sd 0.9), but arrival on the phone is not
/// (sd 20.7 ms, p95 35 ms, worst 869 ms) and 5.6% never arrive at all. Tiny
/// unreliable pointer packets queue behind several megabits of video on the
/// same radio. Drawing each position the moment it lands therefore paints
/// the *radio's* timing, not the hand's.
///
/// Easing toward the newest position cannot fix that, which was the mistake
/// worth recording: during a 100 ms silence there is nothing to ease toward,
/// so the pointer reaches the last known point and freezes until the next
/// packet snaps it forward. Freeze-then-jump, a couple of times a second, is
/// exactly what reads as stutter.
///
/// So hold arrivals briefly and play them back on the sender's clock — the
/// same move Pacer.swift makes for video, and for the same reason. The hold
/// buys the one thing easing cannot: by the time a position is due, the one
/// *after* it has usually arrived too, so the frames in between interpolate
/// between two positions the hand really visited instead of guessing. A
/// dropped packet stops mattering for the same reason — its neighbours
/// bracket the hole, and the path across it is exact.
///
/// One instance per stream, one thread (the viewer uses main). Clocks never
/// cross machines: the host's stamps are only compared with each other,
/// anchored against this machine's clock at the best transit seen so far.
public struct CursorTrack {
    /// How far behind the mapped send time each position is drawn, and the
    /// one real cost here — every millisecond of it is a millisecond the
    /// pointer trails the hand. So it is not fixed: it follows the link.
    ///
    /// It has to, because the delays are not ordinary jitter. Measured on a
    /// real session, the pointer stops arriving on a metronome — a stall
    /// every 528 ms (median), while the link is otherwise idle: barely 3 KB
    /// of video in the 300 ms before a typical one. That is AWDL's own
    /// availability window, near enough its 512 TU (524 ms) period, not
    /// anything this app is doing. Half the packets land within 4 ms of the
    /// best transit ever seen; 15% land 120 ms or more behind it.
    ///
    /// A fixed hold cannot serve both: sized for the quiet 85% it runs dry
    /// on every window, sized for the windows it charges the quiet majority
    /// a quarter-second of lag it never needed.
    private var hold: TimeInterval {
        min(max(spread * 1.2, minHold), maxHold)
    }
    /// Cheap enough to pay on a good link — about three 120 Hz frames.
    private let minHold: TimeInterval = 0.05
    /// The most lag worth paying to stay smooth. Chosen to bracket the
    /// video's own 120 ms hold (Pacer.hold) rather than run far past it: a
    /// pointer near the picture's own delay reads as belonging to it, one a
    /// quarter-second behind reads as broken however smoothly it moves.
    private let maxHold: TimeInterval = 0.16
    /// Rises to meet any delay at once, falls about 50 ms per second of
    /// arrivals. Asymmetric on purpose, the same shape BitrateGovernor uses:
    /// the cost of reacting late to a worsening link is a visible stall, the
    /// cost of lingering a moment on a recovering one is a little lag.
    private let ease: TimeInterval = 0.0008
    /// The delay above the best transit that the hold is currently sized for.
    private var spread: TimeInterval = 0
    /// The mapping between the two clocks may only slip this fast when
    /// transit *worsens* — about a millisecond per arrival. A better transit
    /// is adopted at once, because that is genuine new information about the
    /// link; a worse one is treated as jitter until it persists, or a single
    /// unlucky packet would drag the whole timeline late behind it.
    private let slipPerArrival: TimeInterval = 0.001
    /// Beyond this it is a clock artefact — sleep, a session restart — not
    /// congestion. Start over.
    private let brokenAfter: TimeInterval = 30
    /// Nothing is kept once it is this far behind: one sample before `now`
    /// is all that interpolation needs.
    private let keepBehind: TimeInterval = 0.5

    /// Positions waiting for their slot, in the viewer's own clock.
    private var samples: [(dueAt: TimeInterval, point: CGPoint)] = []
    /// The first stamp seen, as a fixed origin for the host's clock, and the
    /// current estimate of `viewer time - host elapsed`. Held apart so the
    /// estimate can be nudged without disturbing the origin, which is what
    /// lets the buffer keep its shape.
    private var origin: UInt32?
    private var offset: TimeInterval?

    /// True once the buffer is spent and nothing new has come for a while —
    /// the hand has stopped, and the caller can stop asking for frames.
    public init() {}

    public func idle(now: TimeInterval) -> Bool {
        guard let last = samples.last else { return true }
        return now > last.dueAt + keepBehind
    }

    public var isEmpty: Bool { samples.isEmpty }

    public mutating func clear() {
        samples = []
        origin = nil
        offset = nil
    }

    /// A position arrived. `sentMs` is the host's steady clock when it was
    /// sampled, `now` this machine's clock as it landed.
    public mutating func arrived(sentMs: UInt32, at point: CGPoint, now: TimeInterval) {
        guard let origin, let offset else { return restart(sentMs, point, now) }
        // Wrapping subtraction read as signed, so the 32-bit stamp rolling
        // over costs nothing at all rather than stranding the pointer.
        let elapsed = TimeInterval(Int32(bitPattern: sentMs &- origin)) / 1000
        guard elapsed > -1, elapsed < brokenAfter * 60 else {
            return restart(sentMs, point, now)
        }

        // What this one packet says the mapping should be. Believe it at once
        // when it claims a faster link, creep toward it when it claims a
        // slower one. Crucially the buffer is never thrown away for this —
        // discarding it was the bug that made the buffer behave like no
        // buffer at all, snapping to the newest position on every packet
        // that happened to travel a little quicker than the last.
        let observed = now - elapsed
        // How far behind the best transit ever seen this one landed. Measured
        // against the old estimate, before it moves, or a packet would be
        // compared with itself and every delay would read as zero.
        spread = max(observed - offset, spread - ease)

        if observed < offset {
            self.offset = observed
        } else {
            self.offset = offset + min(observed - offset, slipPerArrival)
        }

        insert(dueAt: (self.offset ?? offset) + elapsed + hold, point)
    }

    /// Where to draw this display frame, or nil if nothing has arrived yet.
    /// Interpolates between the two positions that bracket `now`; once the
    /// buffer is spent it holds the last one rather than inventing motion.
    public mutating func position(now: TimeInterval) -> CGPoint? {
        prune(before: now - keepBehind)
        guard let first = samples.first else { return nil }
        guard now > first.dueAt else { return first.point }

        var previous = first
        for sample in samples.dropFirst() {
            if sample.dueAt > now {
                let span = sample.dueAt - previous.dueAt
                guard span > 0 else { return sample.point }
                let t = CGFloat((now - previous.dueAt) / span)
                return CGPoint(x: previous.point.x + (sample.point.x - previous.point.x) * t,
                               y: previous.point.y + (sample.point.y - previous.point.y) * t)
            }
            previous = sample
        }
        // Ran out: the hand stopped, or the link went quiet. Either way the
        // last real position is the honest answer — extrapolating here would
        // draw motion nobody made.
        return previous.point
    }

    /// Only for a clock that genuinely restarted — a new session, a sleep.
    private mutating func restart(_ sentMs: UInt32, _ point: CGPoint, _ now: TimeInterval) {
        origin = sentMs
        offset = now
        spread = 0
        samples = [(now + hold, point)]
    }

    /// Arrivals are almost always in order, so this walks from the back.
    /// Never earlier than what is already queued: pulling the mapping in on
    /// a fast packet must not let a later position be drawn before an
    /// earlier one, which on glass is the pointer twitching backwards.
    private mutating func insert(dueAt: TimeInterval, _ point: CGPoint) {
        var due = dueAt
        if let last = samples.last, due <= last.dueAt {
            due = last.dueAt + 0.0005
        }
        samples.append((due, point))
    }

    private mutating func prune(before cutoff: TimeInterval) {
        // Keep the last one already past: it is the left end of the segment
        // currently being interpolated.
        var drop = 0
        while drop + 1 < samples.count, samples[drop + 1].dueAt < cutoff { drop += 1 }
        if drop > 0 { samples.removeFirst(drop) }
    }
}
