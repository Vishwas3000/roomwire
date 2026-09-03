package com.roomlink.protocol

import kotlin.math.roundToInt

/**
 * A port of swift/Sources/RoomLinkProtocol/Packet.swift. The bytes are the specification and
 * neither language owns them: protocol/vectors.txt is generated from Swift and
 * asserted here, so a difference between the two shows up as a failing test
 * rather than as a corrupt frame on somebody's phone months later.
 *
 * One H.264 access unit on the wire.
 *
 *   [0]      flags, bit0 = keyframe (also the message type: video is 0 or 1)
 *   [1..4]   sender's steady clock when it was sent, milliseconds (big endian)
 *   [5]      marker: bit0 = an LTR token follows, bit1 = recovery frame — it
 *            restarts a broken chain, so a viewer that saw a gap may decode it
 *            bit2 = nothing depends on this frame (temporal enhancement
 *            layer), so losing it costs only itself
 *   [6..13]  LTR acknowledgement token (big endian, only when marker bit0)
 *   [next 2] sequence number (big endian, wraps) — every frame, so the
 *            viewer can measure real loss
 *   [next 2] base sequence (big endian, wraps) — counts only frames others
 *            depend on. A hole *here* is what breaks decoding; a hole in the
 *            sequence above with this one intact lost nothing that mattered
 *   [...]    SPS length (4 bytes, big endian, 0 = absent)
 *   [...]    SPS
 *   [...]    PPS length (4 bytes, big endian, 0 = absent)
 *   [...]    PPS
 *   [...]    AVCC payload (4-byte length-prefixed NAL units)
 *
 * Parameter sets ride along with every keyframe so a viewer who joins late can
 * start decoding from the next keyframe without any handshake.
 *
 * Everything is big endian. Coordinates are IEEE-754 binary32 bit patterns:
 * encoding clamps to the unit square, decoding *refuses* anything outside it.
 * That asymmetry is deliberate — our own arithmetic overshooting is not the
 * same thing as a peer parking a layer at infinity.
 */
object Packet {

    /** One frame's fate on a viewer, five bytes on the wire. */
    data class FlightRecord(val sequence: UShort, val latenessMs: Short, val flags: UByte) {
        /**
         * What became of the frame. Shown and skipped come from the pacer;
         * gap-dropped frames never reached it (their lateness reads 0x7FFF).
         */
        companion object {
            val shown: UByte = 1u
            val skipped: UByte = 2u
            val gapDropped: UByte = 4u
            val keyframe: UByte = 8u
            val recovery: UByte = 16u
        }
    }

    /**
     * One moment in the pointer probe, eleven bytes on the wire. Either a
     * position arriving off the network or one actually drawn on glass — the
     * two timelines whose difference is the whole question.
     */
    data class ProbeSample(
        /** True: drawn this display frame. False: arrived in a packet. */
        val drawn: Boolean,
        /**
         * The viewer's own clock, milliseconds since its first sample. One
         * timeline across every batch, so they stitch back together.
         */
        val ms: UInt,
        /** Normalized within the watched screen, as sent. */
        val x: Double,
        val y: Double,
        /**
         * The cursor packet this reflects — ties a drawn frame back to the
         * position it was chasing.
         */
        val seq: UShort,
    )

    class Decoded(
        val keyframe: Boolean,
        /**
         * The sender's steady clock at the moment of sending, wrapped to 32
         * bits. Meaningless across machines on its own — the viewer anchors it
         * against its own clock to tell an on-schedule frame from a stale one.
         */
        val sentMs: UInt,
        /**
         * This frame restarts a broken chain — the first one encoded after a
         * refresh or keyframe request — so a viewer sitting on a sequence gap
         * may decode it even though frames before it never came.
         */
        val recovery: Boolean,
        /**
         * Counts every frame the encoder emitted for this screen. A hole means
         * loss (the host dropping under pressure today; the radio, once deltas
         * ride unreliable sends).
         */
        val sequence: UShort,
        /**
         * Counts only the frames others are built on. A hole here is what
         * actually breaks decoding — a hole in [sequence] with this one
         * unbroken lost an enhancement frame and nothing else.
         */
        val baseSequence: UShort,
        /** Nothing references this frame, so losing it costs only itself. */
        val droppable: Boolean,
        /**
         * Set when the encoder marked this frame a long-term reference. The
         * viewer echoes it back once the frame has decoded, and recovery can
         * then be a small P-frame against it instead of a keyframe.
         */
        val ltrToken: ULong?,
        val sps: ByteArray?,
        val pps: ByteArray?,
        val payload: ByteArray,
    )

    /** What a viewer can mark on the screen they are watching. */
    enum class Mark(val raw: UByte) {
        POINT(0u),   // pointer moved here
        DRAW(1u),    // stroke point, joins the one before it
        LIFT(2u),    // pointer lifted or stroke finished
        CLEAR(3u);   // take back everything this viewer drew

        companion object {
            fun of(raw: UByte): Mark? = Mark.entries.firstOrNull { it.raw == raw }
        }
    }

    /** A viewer's one-tap answer back to the presenter. */
    enum class Reaction(val raw: UByte) {
        HAND(0u), YES(1u), NO(2u), TOO_SMALL(3u);

        companion object {
            fun of(raw: UByte): Reaction? = Reaction.entries.firstOrNull { it.raw == raw }
        }
    }

    /**
     * The three-finger swipes a Mac trackpad already means something by. They
     * travel as intentions rather than as the keystrokes they become, because
     * what a Mac does with three fingers is the Mac's business — the phone only
     * reports the hand.
     */
    enum class SystemGesture(val raw: UByte) {
        MISSION_CONTROL(0u), APP_WINDOWS(1u), SPACE_LEFT(2u), SPACE_RIGHT(3u);

        companion object {
            fun of(raw: UByte): SystemGesture? = SystemGesture.entries.firstOrNull { it.raw == raw }
        }
    }

    /**
     * Everything either end can receive. Byte 0 tells them apart:
     * 0/1 video (bit0 = keyframe), 2 pointer position, 3 pointer gone,
     * 4 a viewer's mark, 5 that mark relayed to the other viewers, 6 a
     * reaction, 7 a viewer's own count of what reached it, 8 a viewer asking
     * for a keyframe, 9 the presenter asking this screen to identify itself,
     * 10 a viewer confirming it decoded a long-term reference, 11 a viewer that
     * saw a sequence gap asking for a cheap recovery frame, 12 a viewer's
     * per-frame flight records for the last second, 13 the pointer probe's
     * paired timelines, 14 a controlling viewer's pointer, 15 its scrolling,
     * 16 a viewer asking for control, 17 the presenter's answer.
     *
     * Coordinates are always normalized within the watched screen, so they
     * survive any difference in resolution or zoom between the two ends.
     *
     * The pointer is not baked into the video. It rides these tiny messages at
     * 60 Hz so it stays fluid when frames lag, and is drawn by the viewer.
     */
    sealed interface Message {
        data class Video(val frame: Decoded) : Message

        /**
         * seq: rejects a stale or reordered packet — unlike video this rides
         * unreliable delivery, so packets can arrive out of order.
         * sentMs: the host's steady clock when the pointer was *sampled*. The
         * pump is regular to within a millisecond but arrival is not, so this
         * is what lets the viewer replay the motion on the clock it was made on
         * rather than the clock it happened to reach the phone on.
         */
        data class Cursor(val seq: UShort, val sentMs: UInt, val x: Double, val y: Double) : Message

        data class CursorHidden(val seq: UShort) : Message

        /** viewer -> host */
        data class Mark(val kind: Packet.Mark, val x: Double, val y: Double) : Message

        /** host -> viewers */
        data class RelayedMark(
            val slot: UByte,
            val kind: Packet.Mark,
            val x: Double,
            val y: Double,
        ) : Message

        /** viewer -> host */
        data class Reaction(val kind: Packet.Reaction) : Message

        /**
         * viewer -> host. Counts are cumulative since the viewer joined — the
         * host holds what it sent, so comparing the two measures loss instead
         * of guessing at it. The gaps are the last second's arrival spacing on
         * the viewer: how the link felt, which a count alone cannot show.
         * skipped = frames its pacer decoded but did not show, cumulative.
         * gapDropped = frames lost to a sequence hole, cumulative — real loss
         * the host's own send-backlog counter cannot see for itself.
         *
         * These are Long and not Int because the Swift side takes `Int`, which
         * is 64-bit there. The saturation is the point: a count that wrapped
         * would read as a link that healed.
         */
        data class Telemetry(
            val frames: Long,
            val kilobytes: Long,
            val maxGapMs: Long,
            val p95GapMs: Long,
            val skipped: Long,
            val gapDropped: Long,
        ) : Message

        /**
         * viewer -> host. Nothing decodes until the next keyframe, and they are
         * no longer sent on a timer, so a viewer whose decoder has failed has
         * to say so.
         */
        data object NeedKeyframe : Message

        /**
         * host -> viewer. The presenter tapped this screen on the plan view.
         * Which phone in the room is showing it is otherwise guesswork.
         */
        data object Identify : Message

        /**
         * viewer -> host. This long-term reference decoded here; the encoder
         * may now lean on it for cheap recovery.
         */
        data class AckReference(val token: ULong) : Message

        /**
         * viewer -> host. Frames went missing but nothing was flushed: a
         * recovery frame against a reference this viewer still holds is enough.
         * A flushed decoder asks for a keyframe (8) instead — its references
         * are gone.
         */
        data object NeedRefresh : Message

        /**
         * viewer -> host. The last second, frame by frame: what arrived, how
         * late against the sender's clock, and what became of it. The host
         * writes these into the session's flight file, where a hiccup's period
         * and phase can be read instead of guessed at.
         */
        data class Flight(val records: List<FlightRecord>) : Message

        /**
         * viewer -> host. Dev-only, off unless DP_CURSOR_PROBE is set at both
         * ends. The host drives the pointer along a known circle instead of
         * sampling the mouse; the viewer reports back both what arrived and
         * what it drew, frame by frame, so the two timelines can be laid
         * against the circle they were supposed to trace.
         */
        data class Probe(val samples: List<ProbeSample>) : Message

        /**
         * viewer -> host. A controlling viewer's pointer. [buttons] is the
         * *whole state* — bit0 left, bit1 right — not a click, so a message
         * lost or arriving out of order is corrected by the next one rather
         * than leaving a button held down on the presenter's Mac forever.
         */
        data class Input(val buttons: UByte, val x: Double, val y: Double) : Message

        /** viewer -> host. Pixel deltas, as a finger on glass describes them. */
        data class Scroll(val dx: Short, val dy: Short) : Message

        /**
         * viewer -> host. A viewer asking for the pointer. The presenter
         * answers, or does not — nothing a viewer sends can grant this to
         * itself.
         */
        data object RequestControl : Message

        /**
         * host -> viewer. Granted or taken away. Sent on every change,
         * including the automatic ones: leaving, being moved to another screen,
         * or the presenter simply touching their own mouse.
         */
        data class ControlGranted(val granted: Boolean) : Message

        /** viewer -> host. Three fingers, meaning what they mean on a trackpad. */
        data class SystemGesture(val kind: Packet.SystemGesture) : Message
    }

    fun decodeMessage(b: ByteArray): Message? {
        when (b.firstOrNull()?.toUByte()?.toInt()) {
            0, 1 -> return decode(b)?.let { Message.Video(it) }
            2 -> {
                if (b.size != 15) return null
                val (x, y) = point(b, 7) ?: return null
                return Message.Cursor(b.be16(1), b.be32(3), x, y)
            }
            3 -> {
                if (b.size != 3) return null
                return Message.CursorHidden(b.be16(1))
            }
            4 -> {
                if (b.size != 10) return null
                val kind = Mark.of(b.u(1)) ?: return null
                val (x, y) = point(b, 2) ?: return null
                return Message.Mark(kind, x, y)
            }
            5 -> {
                if (b.size != 11) return null
                val kind = Mark.of(b.u(2)) ?: return null
                val (x, y) = point(b, 3) ?: return null
                return Message.RelayedMark(b.u(1), kind, x, y)
            }
            6 -> {
                if (b.size != 2) return null
                return Message.Reaction(Reaction.of(b.u(1)) ?: return null)
            }
            7 -> {
                if (b.size != 21) return null
                return Message.Telemetry(
                    frames = b.be32(1).toLong(), kilobytes = b.be32(5).toLong(),
                    maxGapMs = b.be16(9).toLong(), p95GapMs = b.be16(11).toLong(),
                    skipped = b.be32(13).toLong(), gapDropped = b.be32(17).toLong(),
                )
            }
            8 -> return if (b.size == 1) Message.NeedKeyframe else null
            9 -> return if (b.size == 1) Message.Identify else null
            10 -> {
                if (b.size != 9) return null
                return Message.AckReference(b.be64(1))
            }
            11 -> return if (b.size == 1) Message.NeedRefresh else null
            12 -> {
                if (b.size < 2) return null
                val n = b.u(1).toInt()
                if (n > 48 || b.size != 2 + n * 5) return null
                return Message.Flight(
                    List(n) { i ->
                        val o = 2 + i * 5
                        FlightRecord(b.be16(o), b.be16(o + 2).toShort(), b.u(o + 4))
                    },
                )
            }
            13 -> {
                if (b.size < 2) return null
                val n = b.u(1).toInt()
                if (n > 64 || b.size != 2 + n * 11) return null
                val samples = ArrayList<ProbeSample>(n)
                for (i in 0 until n) {
                    val o = 2 + i * 11
                    if (b.u(o) > 1u) return null
                    samples.add(
                        ProbeSample(
                            drawn = b.u(o) == 0u.toUByte(), ms = b.be32(o + 1),
                            x = b.be16(o + 5).toDouble() / 65535,
                            y = b.be16(o + 7).toDouble() / 65535,
                            seq = b.be16(o + 9),
                        ),
                    )
                }
                return Message.Probe(samples)
            }
            14 -> {
                // Unknown button bits are refused rather than masked off: a peer
                // that means something we do not understand is not one to guess
                // at while holding the presenter's mouse.
                if (b.size != 10 || b.u(1) > 3u) return null
                val (x, y) = point(b, 2) ?: return null
                return Message.Input(b.u(1), x, y)
            }
            15 -> {
                if (b.size != 5) return null
                return Message.Scroll(b.be16(1).toShort(), b.be16(3).toShort())
            }
            16 -> return if (b.size == 1) Message.RequestControl else null
            17 -> {
                if (b.size != 2 || b.u(1) > 1u) return null
                return Message.ControlGranted(b.u(1) == 1u.toUByte())
            }
            18 -> {
                if (b.size != 2) return null
                return Message.SystemGesture(SystemGesture.of(b.u(1)) ?: return null)
            }
            else -> return null
        }
    }

    /**
     * Two big-endian floats at [o]. Network input: a hostile coordinate would
     * park a layer at infinity, so anything off the unit square is refused.
     */
    private fun point(b: ByteArray, o: Int): Pair<Double, Double>? {
        val x = Float.fromBits(b.be32(o).toInt())
        val y = Float.fromBits(b.be32(o + 4).toInt())
        if (!x.isFinite() || !y.isFinite() || x < 0f || x > 1f || y < 0f || y > 1f) return null
        return x.toDouble() to y.toDouble()
    }

    fun encodeMark(kind: Mark, x: Double, y: Double): ByteArray {
        val out = mutableListOf<Byte>(4, kind.raw.toByte())
        out.appendPoint(x, y)
        return out.toByteArray()
    }

    fun encodeRelayedMark(slot: UByte, kind: Mark, x: Double, y: Double): ByteArray {
        val out = mutableListOf<Byte>(5, slot.toByte(), kind.raw.toByte())
        out.appendPoint(x, y)
        return out.toByteArray()
    }

    fun encodeReaction(reaction: Reaction): ByteArray = byteArrayOf(6, reaction.raw.toByte())

    /**
     * Kilobytes rather than bytes: a 32-bit count of bytes runs out after about
     * two hours at 4 Mbit/s, which is shorter than a long meeting.
     *
     * Long, not Int, because Swift's `Int` is 64-bit — the saturation only
     * means anything if the parameters can hold a value past UInt32.max.
     */
    fun encodeTelemetry(
        frames: Long,
        kilobytes: Long,
        maxGapMs: Long,
        p95GapMs: Long,
        skipped: Long,
        gapDropped: Long,
    ): ByteArray {
        val out = mutableListOf<Byte>(7)
        out.appendBE(clampU32(frames))
        out.appendBE(clampU32(kilobytes))
        out.appendBE16(clampU16(maxGapMs))
        out.appendBE16(clampU16(p95GapMs))
        out.appendBE(clampU32(skipped))
        out.appendBE(clampU32(gapDropped))
        return out.toByteArray()
    }

    fun encodeCursor(seq: UShort, sentMs: UInt, x: Double, y: Double): ByteArray {
        val out = mutableListOf<Byte>(2)
        out.appendBE16(seq)
        out.appendBE(sentMs)
        out.appendPoint(x, y)
        return out.toByteArray()
    }

    fun encodeCursorHidden(seq: UShort): ByteArray {
        val out = mutableListOf<Byte>(3)
        out.appendBE16(seq)
        return out.toByteArray()
    }

    fun encodeAckReference(token: ULong): ByteArray {
        val out = mutableListOf<Byte>(10)
        out.appendBE64(token)
        return out.toByteArray()
    }

    // Fresh arrays: a ByteArray is mutable, so a shared constant is a caller
    // away from being edited under everyone else.
    val needKeyframeMessage: ByteArray get() = byteArrayOf(8)
    val needRefreshMessage: ByteArray get() = byteArrayOf(11)
    val requestControlMessage: ByteArray get() = byteArrayOf(16)
    val identifyMessage: ByteArray get() = byteArrayOf(9)

    /**
     * At 30 fps a second is ~30 records; 48 leaves room for a burst. More than
     * that and the oldest go — the analysis wants texture, not bulk.
     */
    fun encodeFlight(records: List<FlightRecord>): ByteArray {
        val kept = records.takeLast(48)
        val out = mutableListOf<Byte>(12, kept.size.toByte())
        for (r in kept) {
            out.appendBE16(r.sequence)
            out.appendBE16(r.latenessMs.toUShort())
            out.add(r.flags.toByte())
        }
        return out.toByteArray()
    }

    /**
     * Positions are normalized, so 16 bits of fixed point resolves finer than
     * any screen — and keeps a sample at eleven bytes.
     */
    fun encodeProbe(samples: List<ProbeSample>): ByteArray {
        val kept = samples.take(64)
        val out = mutableListOf<Byte>(13, kept.size.toByte())
        for (s in kept) {
            out.add(if (s.drawn) 0 else 1)
            out.appendBE(s.ms)
            out.appendBE16(fixed16(s.x))
            out.appendBE16(fixed16(s.y))
            out.appendBE16(s.seq)
        }
        return out.toByteArray()
    }

    /**
     * Reuses [appendPoint]'s clamp and [point]'s refusal of anything off the
     * unit square. That guard was written so a hostile coordinate could not
     * park a layer at infinity; it now also confines an injected click to the
     * screen actually being shared, which is a good deal more load-bearing.
     */
    fun encodeInput(buttons: UByte, x: Double, y: Double): ByteArray {
        val out = mutableListOf<Byte>(14, (buttons and 3u).toByte())
        out.appendPoint(x, y)
        return out.toByteArray()
    }

    fun encodeScroll(dx: Short, dy: Short): ByteArray {
        val out = mutableListOf<Byte>(15)
        out.appendBE16(dx.toUShort())
        out.appendBE16(dy.toUShort())
        return out.toByteArray()
    }

    fun encodeControlGranted(granted: Boolean): ByteArray =
        byteArrayOf(17, if (granted) 1 else 0)

    fun encodeSystemGesture(kind: SystemGesture): ByteArray =
        byteArrayOf(18, kind.raw.toByte())

    fun encode(
        payload: ByteArray,
        sps: ByteArray?,
        pps: ByteArray?,
        keyframe: Boolean,
        recovery: Boolean = false,
        droppable: Boolean = false,
        sentMs: UInt,
        sequence: UShort,
        baseSequence: UShort,
        ltrToken: ULong? = null,
    ): ByteArray {
        val out = mutableListOf<Byte>(if (keyframe) 1 else 0)
        out.appendBE(sentMs)
        var marker = if (recovery) 2 else 0
        if (ltrToken != null) marker = marker or 1
        if (droppable) marker = marker or 4
        out.add(marker.toByte())
        if (ltrToken != null) out.appendBE64(ltrToken)
        out.appendBE16(sequence)
        out.appendBE16(baseSequence)
        out.appendBE((sps?.size ?: 0).toUInt())
        if (sps != null) out.addAll(sps.asList())
        out.appendBE((pps?.size ?: 0).toUInt())
        if (pps != null) out.addAll(pps.asList())
        out.addAll(payload.asList())
        return out.toByteArray()
    }

    /** Network input — every length is bounds-checked before it is used. */
    fun decode(b: ByteArray): Decoded? {
        var o = 1
        if (b.size <= 18) return null
        val sentMs = b.be32(o)
        o += 4
        val marker = b.u(o).toInt()
        o += 1
        if (marker > 7) return null   // network input: unknown bits are refused
        var ltrToken: ULong? = null
        if (marker and 1 == 1) {
            if (o + 8 > b.size) return null
            ltrToken = b.be64(o)
            o += 8
        }
        if (o + 4 > b.size) return null
        val sequence = b.be16(o)
        o += 2
        val baseSequence = b.be16(o)
        o += 2

        fun length(): Int? {
            if (o + 4 > b.size) return null
            val v = b.be32(o)
            o += 4
            return if (v <= b.size.toUInt()) v.toInt() else null
        }

        val spsLen = length() ?: return null
        if (o + spsLen > b.size) return null
        val sps = if (spsLen > 0) b.copyOfRange(o, o + spsLen) else null
        o += spsLen

        val ppsLen = length() ?: return null
        if (o + ppsLen > b.size) return null
        val pps = if (ppsLen > 0) b.copyOfRange(o, o + ppsLen) else null
        o += ppsLen

        if (o >= b.size) return null
        return Decoded(
            keyframe = b[0].toInt() and 1 == 1, sentMs = sentMs, recovery = marker and 2 == 2,
            sequence = sequence, baseSequence = baseSequence,
            droppable = marker and 4 == 4, ltrToken = ltrToken,
            sps = sps, pps = pps, payload = b.copyOfRange(o, b.size),
        )
    }

    // MARK: - Plumbing. Everything is big endian; there are no exceptions.

    private fun clampU32(v: Long): UInt = v.coerceIn(0L, 4_294_967_295L).toUInt()

    private fun clampU16(v: Long): UShort = v.coerceIn(0L, 65_535L).toUShort()

    /**
     * 16 bits of fixed point across the unit interval.
     *
     * The NaN guard is load-bearing. coerceIn does not remove NaN — every
     * comparison with NaN is false, so it passes straight through — and
     * roundToInt then throws IllegalArgumentException. Swift traps at the same
     * step for the same reason, which is why the guard exists on both sides and
     * why protocol/vectors.txt pins the answer.
     *
     * This is the only path in the file that turns a coordinate into an
     * integer; everywhere else a hostile Double becomes a bit pattern the far
     * end refuses. A probe sample is diagnostics, and diagnostics do not get to
     * take the app down, so NaN reads as zero.
     *
     * The infinities need no case: coerceIn already maps them to the ends,
     * which is the right answer. Guarding on !isFinite instead would catch them
     * too and send a pointer at the far right edge as one at the far left.
     */
    private fun fixed16(v: Double): UShort =
        if (v.isNaN()) 0u else (v.coerceIn(0.0, 1.0) * 65535).roundToInt().toUShort()

    private fun ByteArray.u(o: Int): UByte = this[o].toUByte()

    private fun ByteArray.be16(o: Int): UShort =
        (((this[o].toInt() and 0xFF) shl 8) or (this[o + 1].toInt() and 0xFF)).toUShort()

    private fun ByteArray.be32(o: Int): UInt =
        ((this[o].toInt() and 0xFF).toUInt() shl 24) or
            ((this[o + 1].toInt() and 0xFF).toUInt() shl 16) or
            ((this[o + 2].toInt() and 0xFF).toUInt() shl 8) or
            (this[o + 3].toInt() and 0xFF).toUInt()

    private fun ByteArray.be64(o: Int): ULong =
        (be32(o).toULong() shl 32) or be32(o + 4).toULong()

    private fun MutableList<Byte>.appendPoint(x: Double, y: Double) {
        appendBE(x.coerceIn(0.0, 1.0).toFloat().toRawBits().toUInt())
        appendBE(y.coerceIn(0.0, 1.0).toFloat().toRawBits().toUInt())
    }

    private fun MutableList<Byte>.appendBE64(v: ULong) {
        appendBE((v shr 32).toUInt())
        appendBE(v.toUInt())
    }

    private fun MutableList<Byte>.appendBE16(v: UShort) {
        val i = v.toInt()
        add((i shr 8).toByte())
        add(i.toByte())
    }

    private fun MutableList<Byte>.appendBE(v: UInt) {
        val i = v.toInt()
        add((i shr 24).toByte())
        add((i shr 16).toByte())
        add((i shr 8).toByte())
        add(i.toByte())
    }
}
