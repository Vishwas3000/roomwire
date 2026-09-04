package com.roomwire.protocol

import kotlin.math.max
import kotlin.math.min

/**
 * A port of swift/Sources/RoomWireProtocol/Pacer.swift. Behaviour is held to
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

    /**
     * The hold between a frame's mapped send time and its presentation — the
     * jitter buffer — sized by what the link is actually doing.
     *
     * It was a flat 0.12 for every link, which is two wrong answers rather
     * than one: a quiet network pays 120 ms it never needed, and a radio with
     * a stall every half second gets a buffer too small to cover it and
     * stutters anyway. The pointer has run an adaptive one since it shipped
     * (CursorMotion); this is that mechanism on the number the picture is
     * scheduled against.
     *
     * The input is free: `lateness` is already measured against an anchor
     * that rebases whenever a frame beats it, so it is excess over the best
     * transit seen.
     */
    private val hold: Double get() = min(max(spread * 1.2, minHold), maxHold)

    /**
     * The delay above the best transit the hold is currently sized for. Rises
     * to meet any lateness on the frame that shows it; falls slowly after, so
     * one bad second does not cost the next thirty.
     */
    private var spread = 0.0
    /** Per admitted frame, so about 24 ms of give back per second at 30 fps. */
    private val ease = 0.0008
    /**
     * Cheap enough to pay on a good link, and about three frames at 60 fps.
     * The same in both modes: the floor is what a quiet link costs, and a
     * quiet link costs the same whoever is looking at it.
     */
    private val minHold = 0.05
    /**
     * The most delay worth paying to stay smooth, and the one number the two
     * modes really disagree about. 120 ms while controlling: past that a
     * pointer stops feeling attached to the finger. 400 ms while watching,
     * because that is what the measured jitter actually needs and nobody
     * watching can tell.
     */
    private val maxHold: Double get() = if (mode == Mode.CONTROL) 0.12 else 0.40
    /** While a backlog drains, still surface a frame this often. */
    private val starvedAfter = 0.3
    /**
     * Lateness that holds this long is the link's new floor, not a burst still
     * draining. Sooner while controlling: that rebase is what "latest frame
     * wins" actually is.
     */
    private val floorAfter: Double get() = if (mode == Mode.CONTROL) 1.0 else 2.0
    /** Lateness beyond this is a clock artefact — sleep, the stamp wrapping — not congestion. */
    private val brokenAfter = 30.0

    private var anchor: Pair<Double, Double>? = null   // (remote, local)
    private var lastShown = Double.NEGATIVE_INFINITY
    private var lateSince: Double? = null

    /**
     * What this viewer is for, which decides how much delay it may buy
     * smoothness with. One buffer cannot serve both jobs, and measuring said
     * so: on an access point that adds 250-360 ms to everything, an Android
     * viewer needs about 400 ms of buffer to look smooth, and 400 ms of buffer
     * makes a pointer unusable. The person watching already chose by picking
     * up the pointer.
     */
    enum class Mode { CONTROL, WATCH }

    /** Watching, because that is what a viewer is doing when it joins. */
    var mode: Mode = Mode.WATCH
        private set

    /**
     * The pointer changed hands. The envelope is kept — the link is the same
     * link — and only the ceiling moves, so taking control shrinks the hold at
     * once and the picture jumps forward once to catch up.
     */
    fun use(mode: Mode) {
        this.mode = mode
    }

    /**
     * `remote` is the sender's clock at send, `now` this machine's clock at
     * arrival, both in seconds. The lateness comes back with the verdict — it
     * is the one number the choke analysis lives on.
     */
    fun admit(remote: Double, now: Double): Pair<Verdict, Double> {
        val a = anchor ?: return Pair(rebase(remote, now), 0.0)
        val lateness = now - (a.second + (remote - a.first))

        // A clock artefact — sleep, or the stamp wrapping — says nothing about
        // the link, so the envelope starts again with it.
        if (lateness > brokenAfter) {
            spread = 0.0
            return Pair(rebase(remote, now), lateness)
        }
        // Travelled faster than the anchor frame did: adopt this frame as the
        // new baseline. The envelope survives, because a link that just proved
        // it can be quick is still the link that was slow a moment ago.
        if (lateness < 0) return Pair(rebase(remote, now), lateness)

        // Before the hold is read, so a frame that is late widens the buffer
        // deciding its own fate. Deliberate: the first late frame of a burst
        // is then presented rather than being the one that stutters.
        // Clamped to the ceiling on the way in, not just on the way out. A
        // 300 ms stall is not 300 ms of jitter — it is the link stopping and
        // then dumping, which the backlog path below already handles.
        spread = max(min(lateness, maxHold), spread - ease)

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
