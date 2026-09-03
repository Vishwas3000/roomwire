package com.roomlink.protocol

import kotlin.math.max
import kotlin.math.min

/**
 * Wraparound-safe "is `a` newer than `b`" for a 16-bit sequence counter — the
 * standard RFC 1982 serial comparison: half the space counts as ahead of `b`,
 * half counts as behind. The cursor rides unreliable delivery, so packets can
 * arrive out of order or duplicated.
 */
fun isCursorSeqNewer(a: UShort, than: UShort): Boolean =
    a != than && ((a.toInt() - than.toInt()) and 0xFFFF) < 0x8000

/**
 * A port of swift/Sources/RoomLinkProtocol/CursorMotion.swift. Behaviour is
 * held to the Swift side by protocol/transcripts.txt.
 *
 * Replays the pointer on the clock it was sampled on, a fixed hold late.
 *
 * The host's pump is a metronome but arrival on the phone is not: tiny
 * unreliable pointer packets queue behind several megabits of video on the same
 * radio. Drawing each position the moment it lands paints the radio's timing,
 * not the hand's. So arrivals are held briefly and played back on the sender's
 * clock — the same move Pacer makes for video. By the time a position is due,
 * the one after it has usually arrived too, so the frames in between
 * interpolate between two positions the hand really visited.
 *
 * One instance per stream, one thread. Clocks never cross machines.
 */
class CursorTrack {
    /**
     * How far behind the mapped send time each position is drawn. Not fixed:
     * it follows the link, because the delays are not ordinary jitter — a
     * stall every ~528 ms on an otherwise idle link is the radio's own
     * availability window. Sized for the quiet majority it runs dry on every
     * window; sized for the windows it charges the majority lag it never needed.
     */
    private val hold: Double
        get() = min(max(spread * 1.2, minHold), maxHold)
    /** Cheap enough to pay on a good link — about three 120 Hz frames. */
    private val minHold = 0.05
    /** The most lag worth paying to stay smooth; brackets the video's own hold. */
    private val maxHold = 0.16
    /** Rises to meet any delay at once, falls about 50 ms per second of arrivals. */
    private val ease = 0.0008
    /** The delay above the best transit that the hold is currently sized for. */
    private var spread = 0.0
    /** The clock mapping may only slip this fast when transit *worsens*. */
    private val slipPerArrival = 0.001
    /** Beyond this it is a clock artefact — sleep, a session restart. Start over. */
    private val brokenAfter = 30.0
    /** Nothing is kept once it is this far behind. */
    private val keepBehind = 0.5

    /** Positions waiting for their slot, in the viewer's own clock: (dueAt, point). */
    private val samples = ArrayList<Pair<Double, Point>>()
    /** The first stamp seen, as a fixed origin for the host's clock, and the current estimate of `viewer time - host elapsed`. */
    private var origin: UInt? = null
    private var offset: Double? = null

    /** True once the buffer is spent and nothing new has come for a while. */
    fun idle(now: Double): Boolean {
        val last = samples.lastOrNull() ?: return true
        return now > last.first + keepBehind
    }

    val isEmpty: Boolean get() = samples.isEmpty()

    fun clear() {
        samples.clear()
        origin = null
        offset = null
    }

    /** A position arrived. `sentMs` is the host's steady clock when it was sampled, `now` this machine's clock as it landed. */
    fun arrived(sentMs: UInt, at: Point, now: Double) {
        val o = origin
        val off = offset
        if (o == null || off == null) return restart(sentMs, at, now)
        // Wrapping subtraction read as signed, so the 32-bit stamp rolling
        // over costs nothing at all rather than stranding the pointer.
        val elapsed = (sentMs - o).toInt().toDouble() / 1000
        if (!(elapsed > -1 && elapsed < brokenAfter * 60)) return restart(sentMs, at, now)

        // What this one packet says the mapping should be. Believe it at once
        // when it claims a faster link, creep toward it when it claims a slower
        // one. The buffer is never thrown away for this.
        val observed = now - elapsed
        // Measured against the old estimate, before it moves.
        spread = max(observed - off, spread - ease)

        val next = if (observed < off) observed else off + min(observed - off, slipPerArrival)
        offset = next

        insert(next + elapsed + hold, at)
    }

    /**
     * Where to draw this display frame, or null if nothing has arrived yet.
     * Interpolates between the two positions that bracket `now`; once the
     * buffer is spent it holds the last one rather than inventing motion.
     */
    fun position(now: Double): Point? {
        prune(now - keepBehind)
        val first = samples.firstOrNull() ?: return null
        if (!(now > first.first)) return first.second

        var previous = first
        for (i in 1 until samples.size) {
            val sample = samples[i]
            if (sample.first > now) {
                val span = sample.first - previous.first
                if (!(span > 0)) return sample.second
                val t = (now - previous.first) / span
                return Point(
                    previous.second.x + (sample.second.x - previous.second.x) * t,
                    previous.second.y + (sample.second.y - previous.second.y) * t,
                )
            }
            previous = sample
        }
        // Ran out: the last real position is the honest answer.
        return previous.second
    }

    /** Only for a clock that genuinely restarted — a new session, a sleep. */
    private fun restart(sentMs: UInt, point: Point, now: Double) {
        origin = sentMs
        offset = now
        spread = 0.0
        samples.clear()
        samples.add(Pair(now + hold, point))
    }

    /** Never earlier than what is already queued: a later position must not be drawn before an earlier one. */
    private fun insert(dueAt: Double, point: Point) {
        var due = dueAt
        val last = samples.lastOrNull()
        if (last != null && due <= last.first) due = last.first + 0.0005
        samples.add(Pair(due, point))
    }

    private fun prune(cutoff: Double) {
        // Keep the last one already past: it is the left end of the segment
        // currently being interpolated.
        var drop = 0
        while (drop + 1 < samples.size && samples[drop + 1].first < cutoff) drop++
        if (drop > 0) samples.subList(0, drop).clear()
    }
}
