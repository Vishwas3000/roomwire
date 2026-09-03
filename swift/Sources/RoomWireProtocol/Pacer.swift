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
    /// the jitter buffer. AirPlay mirroring sits near 150 ms; the pointer
    /// rides its own channel, so the picture can afford this and the share
    /// still feels live.
    private let hold: TimeInterval = 0.12
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

        // Travelled faster than the anchor frame did (or the clock broke):
        // adopt this frame as the new baseline for "on schedule".
        if lateness < 0 || lateness > brokenAfter { return (rebase(remote, now), lateness) }

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
