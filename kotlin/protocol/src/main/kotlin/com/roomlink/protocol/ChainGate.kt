package com.roomlink.protocol

/**
 * A port of swift/Sources/RoomLinkProtocol/ChainGate.swift. Behaviour is held
 * to the Swift side by protocol/transcripts.txt.
 *
 * Decides whether an arriving frame can be decoded, or is built on one that
 * never came. Pure decision, fed the numbers off the wire, because getting it
 * wrong is either a frozen picture or a corrupt one, and neither is visible in
 * a compiler.
 *
 * The point it exists to make: **losing a frame and breaking the stream are
 * not the same event.** With temporal layers about half the frames are an
 * enhancement layer that nothing references, so losing one costs exactly that
 * frame. Only a hole in the frames others are *built on* makes what follows
 * undecodable.
 *
 * Two counters, and the difference between them is the whole idea:
 *   - `sequence` counts every frame, and measures what the link lost.
 *   - `baseSequence` counts only frames others depend on.
 *
 * Deltas ride unreliable sends, so frames arrive out of order and occasionally
 * twice. Every comparison is therefore signed distance on a wrapping counter,
 * never equality: a frame that turns up late is stale, which is a different
 * thing from evidence that something was lost.
 */
class ChainGate {
    enum class Verdict {
        /** Everything this frame needs has arrived. */
        DECODE,
        /** Something it is built on never came. Undecodable, and so is everything after it until a frame restarts the chain. */
        BROKEN,
        /** Older than what has already been decoded — a late or duplicated packet. Nothing to decode, nothing to repair. */
        STALE,
    }

    /** True from the first missing base frame until something restores it. */
    var isBroken = true
        private set
    /** Frames that never arrived, whether or not losing them mattered. Measures the link. */
    var missing = 0
        private set
    /** Of those, the ones others were built on. Measures the damage. */
    var missingBase = 0
        private set

    private var lastBase: UShort? = null
    private var nextSequence: UShort? = null

    fun reset() {
        isBroken = true
        missing = 0
        missingBase = 0
        lastBase = null
        nextSequence = null
    }

    /** `restores` is a keyframe or a flagged recovery frame — either one starts the chain again from itself. */
    fun admit(sequence: UShort, baseSequence: UShort, droppable: Boolean, restores: Boolean): Verdict {
        if (restores) {
            isBroken = false
            lastBase = baseSequence
            nextSequence = (sequence + 1u).toUShort()
            return Verdict.DECODE
        }

        // Is this frame older than where the stream has already got to? Both
        // counters have to agree it is current, because either can be the one
        // that went backwards.
        val ahead = nextSequence?.let { distance(sequence, it) } ?: 0
        if (ahead < 0) return Verdict.STALE

        val last = lastBase ?: run {
            // Nothing to measure against yet, and no chain established.
            nextSequence = (sequence + 1u).toUShort()
            return Verdict.BROKEN
        }
        val baseAhead = distance(baseSequence, last)

        if (droppable) {
            // Built on a base already in hand: fine whenever it turns up.
            // Built on one further ahead: that base never arrived.
            if (baseAhead < 0) return Verdict.STALE
            if (baseAhead > 0) { isBroken = true; missingBase += baseAhead }
        } else {
            // The next base frame should be exactly one on.
            if (baseAhead <= 0) return Verdict.STALE
            if (baseAhead > 1) { isBroken = true; missingBase += baseAhead - 1 }
            lastBase = baseSequence          // only ever forward
        }

        // Counted only once the frame is known to be current, so a duplicate
        // cannot invent loss.
        if (ahead > 0) missing += ahead
        nextSequence = (sequence + 1u).toUShort()

        return if (isBroken) Verdict.BROKEN else Verdict.DECODE
    }

    private companion object {
        /** Signed distance on a wrapping 16-bit counter: positive is ahead, negative is behind. */
        fun distance(a: UShort, b: UShort): Int = (a.toInt() - b.toInt()).toShort().toInt()
    }
}
