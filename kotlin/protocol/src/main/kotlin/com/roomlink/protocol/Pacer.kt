package com.roomlink.protocol

/**
 * A port of swift/Sources/RoomLinkProtocol/Pacer.swift. Behaviour is held to
 * the Swift side by protocol/transcripts.txt.
 *
 * Decides when each arriving video frame should be shown.
 *
 * A Wi-Fi stall on an ordered transport loses nothing — it queues frames and
 * then delivers the backlog all at once. Shown on arrival, that is freeze
 * followed by fast-forward. The fix is the one AirPlay mirroring uses: every
 * frame carries the sender's clock, the viewer maps it onto its own, and frames
 * are presented *on that clock, a fixed hold late*.
 *
 * One instance per stream, one thread. Clocks never cross machines: the
 * sender's stamps are only compared with each other, anchored against this
 * machine's clock at the best transit seen so far.
 */
class Pacer {
    sealed interface Verdict {
        /** On schedule: show `after` seconds from now — its slot on the clock. */
        data class Present(val after: Double) : Verdict
        /** Late, but the eye has waited long enough: show it immediately. */
        data object ShowNow : Verdict
        /** Part of a stale backlog: decode to keep the H.264 chain intact, never show. */
        data object DecodeOnly : Verdict
    }

    /** The hold between a frame's mapped send time and its presentation — the jitter buffer. */
    private val hold = 0.12
    /** While a backlog drains, still surface a frame this often. */
    private val starvedAfter = 0.3
    /** Lateness that holds this long is the link's new floor, not a burst still draining. */
    private val floorAfter = 2.0
    /** Lateness beyond this is a clock artefact — sleep, the stamp wrapping — not congestion. */
    private val brokenAfter = 30.0

    private var anchor: Pair<Double, Double>? = null   // (remote, local)
    private var lastShown = Double.NEGATIVE_INFINITY
    private var lateSince: Double? = null

    /**
     * `remote` is the sender's clock at send, `now` this machine's clock at
     * arrival, both in seconds. The lateness comes back with the verdict — it
     * is the one number the choke analysis lives on.
     */
    fun admit(remote: Double, now: Double): Pair<Verdict, Double> {
        val a = anchor ?: return Pair(rebase(remote, now), 0.0)
        val lateness = now - (a.second + (remote - a.first))

        // Travelled faster than the anchor frame did (or the clock broke):
        // adopt this frame as the new baseline for "on schedule".
        if (lateness < 0 || lateness > brokenAfter) return Pair(rebase(remote, now), lateness)

        if (lateness <= hold) {
            lateSince = null
            lastShown = now + (hold - lateness)
            return Pair(Verdict.Present(hold - lateness), lateness)
        }

        // Past its slot: a backlog is draining.
        if (lateSince == null) lateSince = now
        if (now - lateSince!! >= floorAfter) return Pair(rebase(remote, now), lateness)
        if (now - lastShown >= starvedAfter) {
            lastShown = now
            return Pair(Verdict.ShowNow, lateness)
        }
        return Pair(Verdict.DecodeOnly, lateness)
    }

    private fun rebase(remote: Double, now: Double): Verdict {
        anchor = Pair(remote, now)
        lateSince = null
        lastShown = now + hold
        return Verdict.Present(hold)
    }
}
