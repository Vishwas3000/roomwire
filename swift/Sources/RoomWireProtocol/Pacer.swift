import Foundation

/// Decides when each arriving video frame should be shown.
///
/// The transport is ordered and lossless, so a Wi-Fi stall loses nothing — it
/// queues frames and then delivers the backlog all at once. Shown on arrival,
/// that is freeze followed by fast-forward; even ordinary jitter arrives as
/// judder. The fix is the one AirPlay mirroring uses: every frame carries the
/// sender's clock, the viewer maps it onto its own, and frames are presented
/// *on that clock, a fixed hold late*. Jitter smaller than the hold becomes
/// invisible; a genuine stall reads as a freeze that jumps back to current,
/// because the backlog is decoded silently instead of replayed.
///
/// One instance per stream, one thread (the viewer uses main). Clocks never
/// cross machines: the sender's stamps are only compared with each other,
/// anchored against this machine's clock at the best transit seen so far.
public struct Pacer {
    public enum Verdict: Equatable {
        /// On schedule: show `after` seconds from now — its slot on the clock.
        case present(after: TimeInterval)
        /// Late, but the eye has waited long enough: show it immediately.
        case showNow
        /// Part of a stale backlog: decode to keep the H.264 chain intact,
        /// never show.
        case decodeOnly
    }

    /// The hold between a frame's mapped send time and its presentation —
    /// the jitter buffer — sized by what the link is actually doing.
    ///
    /// It was a flat 0.12 for every link, which is two wrong answers rather
    /// than one: a wired-quiet Wi-Fi network pays 120 ms it never needed, and
    /// a radio with a stall every half second gets a buffer too small to
    /// cover it and stutters anyway. The pointer has run an adaptive one
    /// since it shipped (`CursorMotion`), and this is that mechanism, on the
    /// number the picture is scheduled against.
    ///
    /// The input is free: `lateness` is already measured against an anchor
    /// that rebases whenever a frame beats it, so it is excess over the best
    /// transit seen — which is what wants an envelope drawn round it.
    private var hold: TimeInterval { min(max(spread * 1.2, minHold), maxHold) }

    /// The delay above the best transit that the hold is currently sized for.
    /// Rises to meet any lateness on the frame that shows it; falls slowly
    /// afterwards, so one bad second does not cost the next thirty.
    private var spread: TimeInterval = 0
    /// Per admitted frame, so about 24 ms of give back per second at 30 fps.
    private let ease: TimeInterval = 0.0008
    /// Cheap enough to pay on a good link, and about three frames at 60 fps.
    private let minHold: TimeInterval = 0.05
    /// The most delay worth paying to stay smooth. Above the old fixed value
    /// on purpose: a link that genuinely needs 150 ms should be allowed to
    /// have it rather than stutter at 120.
    private let maxHold: TimeInterval = 0.20
    /// 1.2 headroom over observed jitter, the same margin the pointer uses.
    /// While a backlog drains, still surface a frame this often: a long stall
    /// reads as a slow slideshow, never a freeze.
    private let starvedAfter: TimeInterval = 0.3
    /// Lateness that holds this long is the link's new floor, not a burst
    /// still draining. Accept the added delay and get back to full rate.
    private let floorAfter: TimeInterval = 2
    /// Lateness beyond this is a clock artefact — sleep, the 32-bit stamp
    /// wrapping — not congestion. Start over.
    private let brokenAfter: TimeInterval = 30

    private var anchor: (remote: TimeInterval, local: TimeInterval)?
    private var lastShown: TimeInterval = -.infinity
    private var lateSince: TimeInterval?

    /// `remote` is the sender's clock at send, `now` this machine's clock at
    /// arrival, both in seconds. The lateness comes back with the verdict —
    /// it is the one number the choke analysis lives on.
    public init() {}

    public mutating func admit(remote: TimeInterval, now: TimeInterval) -> (verdict: Verdict, lateness: TimeInterval) {
        guard let anchor else { return (rebase(remote, now), 0) }
        let lateness = now - (anchor.local + (remote - anchor.remote))

        // A clock artefact — sleep, or the 32-bit stamp wrapping — says
        // nothing about the link, so the envelope starts again with it.
        if lateness > brokenAfter {
            spread = 0
            return (rebase(remote, now), lateness)
        }
        // Travelled faster than the anchor frame did: adopt this frame as the
        // new baseline for "on schedule". The envelope survives, because a
        // link that just proved it can be quick is still the link that was
        // slow a moment ago.
        if lateness < 0 { return (rebase(remote, now), lateness) }

        // Before the hold is read, so a frame that is late widens the buffer
        // that decides its own fate. That is deliberate: the first late frame
        // of a burst is then presented rather than being the one that
        // stutters, which is the whole difference between a buffer that
        // reacts and one that reports.
        // Clamped to the ceiling on the way in, not just on the way out.
        // A 300 ms stall is not 300 ms of jitter — it is the link stopping and
        // then dumping, which the backlog path below already handles. Letting
        // it set the envelope would pin the buffer at its maximum for seconds
        // afterwards on the strength of one event that a bigger buffer would
        // not have helped with anyway.
        spread = max(min(lateness, maxHold), spread - ease)

        if lateness <= hold {
            lateSince = nil
            lastShown = now + (hold - lateness)
            return (.present(after: hold - lateness), lateness)
        }

        // Past its slot: a backlog is draining.
        if lateSince == nil { lateSince = now }
        if now - lateSince! >= floorAfter { return (rebase(remote, now), lateness) }
        if now - lastShown >= starvedAfter {
            lastShown = now
            return (.showNow, lateness)
        }
        return (.decodeOnly, lateness)
    }

    private mutating func rebase(_ remote: TimeInterval, _ now: TimeInterval) -> Verdict {
        anchor = (remote, now)
        lateSince = nil
        lastShown = now + hold
        return .present(after: hold)
    }
}
