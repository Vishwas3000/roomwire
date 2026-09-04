package com.roomwire.protocol

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlin.math.roundToInt

/**
 * A port of swift/Sources/RoomWireProtocol/Packet.swift. The bytes are the specification and
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
     * The keys that produce no text, and therefore cannot ride in TypeText.
     *
     * Deliberately short. Everything a person types is characters and goes as
     * text; this is only the keys that do something rather than insert
     * something. A full keycode table would mean shipping a keymap and agreeing
     * on one across two platforms, to gain keys a phone cannot press.
     */
    enum class Key(val raw: UByte) {
        BACKSPACE(0u), ENTER(1u), TAB(2u), ESCAPE(3u),
        LEFT(4u), RIGHT(5u), UP(6u), DOWN(7u);

        companion object {
            fun of(raw: UByte): Key? = Key.entries.firstOrNull { it.raw == raw }
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
     * 16 a viewer asking for control, 17 the presenter's answer, 18 a
     * three-finger gesture, 19 a viewer introducing itself to the transport,
     * 20 the transport's answer once the viewer is admitted, 21 the host's
     * pairing nonce, 22 the viewer revealing what it committed to.
     *
     * Id 23 is reserved for a second version of [Message.Hello]. A viewer
     * learns the host's protocol version from the Bonjour TXT record —
     * DiscoveredHost carries it — *before* it connects, so it picks which hello
     * to send and a new id is how v2 announces itself. There is no version byte
     * in the handshake and there does not need to be one.
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
         * viewer -> host. Text for the presenter's Mac to type, exactly as
         * given. Characters rather than keystrokes, because that is what the
         * sender has: a soft keyboard reports what was composed, not which keys
         * were pressed, and for most of the world's scripts those are not the
         * same question.
         */
        data class TypeText(val text: String) : Message

        /** viewer -> host. A key that does something rather than inserting something. */
        data class Key(val key: Packet.Key) : Message

        /**
         * host -> viewer. Whether the thing with keyboard focus on the
         * presenter's Mac takes text. A viewer showing a picture of a screen
         * cannot tell a search field from a button, so the only side that can
         * answer this is the one running the applications.
         */
        data class TextFocused(val focused: Boolean) : Message

        /**
         * host -> viewer. Where to reach this host's bulk lane, and the key to
         * speak to it with. Sent once the control lane is authenticated, which
         * is what makes a plain symmetric key safe to hand over: the lane it
         * keys carries no certificates precisely so an iOS viewer can join one
         * without a certificate library.
         */
        data class BulkReady(val port: UShort, val key: ByteArray) : Message {
            override fun equals(other: Any?): Boolean =
                other is BulkReady && port == other.port && key.contentEquals(other.key)

            override fun hashCode(): Int = 31 * port.hashCode() + key.contentHashCode()
        }

        /**
         * Either way. Copied text, for pasting at the other end. On this lane
         * rather than the bulk one because a paste has to be instant, and the
         * bulk lane is dialled lazily.
         */
        data class ClipboardText(val text: String) : Message

        /**
         * host -> viewer. Granted or taken away. Sent on every change,
         * including the automatic ones: leaving, being moved to another screen,
         * or the presenter simply touching their own mouse.
         */
        data class ControlGranted(val granted: Boolean) : Message

        /** viewer -> host. Three fingers, meaning what they mean on a trackpad. */
        data class SystemGesture(val kind: Packet.SystemGesture) : Message

        /**
         * viewer -> host. The first frame on the control lane, within five
         * seconds of TLS coming up.
         *
         * [commitment] is SHA-256 of a token the viewer has *not* sent yet.
         * That ordering is the whole point and it is what makes six characters
         * enough — see [Pairing.code]. The token itself arrives later, in
         * [Reveal], and the host tears the connection down if it does not hash
         * to this.
         *
         * The token is **not** an identity and nothing may be keyed on it. It
         * is a fresh random per attempt whose only job is to be committed to
         * and then revealed. What identifies a peer is SHA-256 of its
         * certificate, which is the only thing TLS actually proved anything
         * about.
         *
         * [udpPort] is where the viewer is already listening for the media
         * lane: the host dials it, so no viewer ever needs a listener the host
         * can find. Port 0 dials nowhere and is refused. The name is 1…63 bytes
         * of UTF-8, shown to the presenter when asked to approve; more is
         * truncated on the way out and refused on the way in.
         *
         * A plain class and not a data class: [commitment] is a ByteArray, so a
         * generated equals would compare it by identity and quietly answer the
         * wrong question. Same for [Welcome].
         */
        class Hello(val commitment: ByteArray, val udpPort: UShort, val name: String) : Message

        /**
         * host -> viewer. Sent only once the viewer is approved: where the
         * host's own end of the media lane sits, a **fresh 32-byte key per
         * session**, and the SHA-256 of the host's own certificate.
         *
         * Fresh per session, and never cached against a remembered viewer. A
         * key that outlives its control connection is a key used twice with
         * counters that restart at 1 — the same keystream over two different
         * frames, which XORs to plaintext, and the Poly1305 block with it, so
         * it is forgery and not merely disclosure. An attacker who can reset
         * the cleartext TCP connection chooses when that happens, and a phone
         * going to sleep does it unprompted. So: minted in every welcome,
         * destroyed when the control lane closes.
         *
         * [hostFingerprint] is a cross-check and not a source. The viewer
         * already has the host's fingerprint from the TLS handshake — it needs
         * it before this message arrives, to show the pairing code while
         * approval is still pending — so this field must be *compared* against
         * that and the session torn down if it differs. Adopting the value from
         * here would be trusting the thing being checked.
         */
        class Welcome(val udpPort: UShort, val mediaKey: ByteArray, val hostFingerprint: ByteArray) : Message

        /**
         * host -> viewer. Sixteen fresh bytes, sent before approval so the
         * viewer can show the pairing code while the presenter is still
         * deciding. The host's half of the code, and it arrives after the
         * viewer has already committed — without that order the code is a value
         * one side chooses last, which compares nothing.
         */
        class HostNonce(val nonce: ByteArray) : Message

        /**
         * viewer -> host. The token [Hello] committed to. The host hashes it,
         * checks it against the commitment, and closes on a mismatch.
         */
        data class Reveal(val token: UUID) : Message
    }

    /** The most a display name may occupy on the wire, in UTF-8 bytes. */
    const val MAX_NAME_BYTES = 63

    /**
     * One byte carries the length, so 255 is the ceiling the format gives.
     * Typing is not bulk transfer; a longer burst is several messages, split by
     * the sender where a character ends.
     */
    const val MAX_TEXT_BYTES = 255

    /**
     * Big enough for anything anyone pastes as text, small enough that one of
     * them stalls the control lane's other traffic for about two milliseconds
     * rather than two seconds.
     */
    const val MAX_CLIPBOARD_BYTES = 8192

    /**
     * The largest id this build understands. A peer speaking a later version
     * may send something newer, and at the live stage that is skipped rather
     * than fatal. Not a licence to ignore a malformed *known* message: those
     * still close the connection.
     */
    const val HIGHEST_KNOWN_ID: Int = 27

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
            19 -> {
                // The name length is a byte the peer wrote; the frame must be
                // exactly what it claims, the port must dial somewhere, and the
                // name must be text — bytes that are not UTF-8 are not a name we
                // can show anyone.
                if (b.size < 36) return null
                val nameLen = b.u(35).toInt()
                if (nameLen !in 1..MAX_NAME_BYTES || b.size != 36 + nameLen) return null
                val port = b.be16(33)
                if (port == 0u.toUShort()) return null
                val name = strictUtf8(b, 36, b.size) ?: return null
                return Message.Hello(b.copyOfRange(1, 33), port, name)
            }
            20 -> {
                if (b.size != 67) return null
                val port = b.be16(1)
                if (port == 0u.toUShort()) return null
                return Message.Welcome(port, b.copyOfRange(3, 35), b.copyOfRange(35, 67))
            }
            21 -> {
                if (b.size != 17) return null
                return Message.HostNonce(b.copyOfRange(1, 17))
            }
            23 -> {
                // Same shape as a name, refused the same way: exactly the
                // length it claims, and bytes that are not UTF-8 are not text
                // anyone can type.
                if (b.size < 3) return null
                val len = b.u(1).toInt()
                if (len !in 1..MAX_TEXT_BYTES || b.size != 2 + len) return null
                return Message.TypeText(strictUtf8(b, 2, b.size) ?: return null)
            }
            24 -> {
                if (b.size != 2) return null
                return Message.Key(Key.of(b.u(1)) ?: return null)
            }
            25 -> {
                if (b.size != 2) return null
                val raw = b.u(1).toInt()
                if (raw > 1) return null
                return Message.TextFocused(raw == 1)
            }
            26 -> {
                if (b.size != 35) return null
                val port = b.be16(1)
                if (port == 0u.toUShort()) return null
                return Message.BulkReady(port, b.copyOfRange(3, 35))
            }
            27 -> {
                if (b.size < 4) return null
                val length = b.be16(1).toInt()
                if (length !in 1..MAX_CLIPBOARD_BYTES || b.size != 3 + length) return null
                return Message.ClipboardText(strictUtf8(b, 3, b.size) ?: return null)
            }
            22 -> {
                if (b.size != 17) return null
                return Message.Reveal(uuidAt(b, 1))
            }
            else -> return null
        }
    }

    /**
     * [commitment] is 32 bytes — [Pairing.commitment] makes one. The name is
     * cut to [MAX_NAME_BYTES] of UTF-8 on a code point boundary, so a long name
     * loses its tail rather than the whole hello being refused at the far end.
     * An empty name reads as "?": the format needs one byte.
     */
    fun encodeHello(commitment: ByteArray, udpPort: UShort, name: String): ByteArray {
        require(commitment.size == 32) { "a commitment is SHA-256, which is 32 bytes" }
        val out = mutableListOf<Byte>(19)
        out.addAll(commitment.asList())
        out.appendBE16(udpPort)
        val bytes = nameBytes(name)
        out.add(bytes.size.toByte())
        out.addAll(bytes.asList())
        return out.toByteArray()
    }

    /** Sixteen bytes, and they must be fresh for every viewer that connects. */
    fun encodeHostNonce(nonce: ByteArray): ByteArray {
        require(nonce.size == 16) { "a host nonce is 16 bytes" }
        return byteArrayOf(21) + nonce
    }

    fun encodeReveal(token: UUID): ByteArray = byteArrayOf(22) + uuidBytes(token)

    /** [mediaKey] and [hostFingerprint] are 32 bytes each; anything else is a programming error. */
    fun encodeWelcome(udpPort: UShort, mediaKey: ByteArray, hostFingerprint: ByteArray): ByteArray {
        require(mediaKey.size == 32 && hostFingerprint.size == 32) { "welcome carries two 32-byte values" }
        val out = mutableListOf<Byte>(20)
        out.appendBE16(udpPort)
        return out.toByteArray() + mediaKey + hostFingerprint
    }

    /**
     * The display-name rule, and it lives here because the wire has one rule
     * and two ends have to obey it.
     *
     * [Message.Hello] carries a name as 1…63 bytes of UTF-8, so a name that
     * does not fit in 63 bytes is not a name RoomWire can send at all. A
     * platform's own idea of a device name is no help: a Mac's is a String of
     * any length, and forty *characters* of it can be a hundred and sixty
     * bytes. So this is where a name is made to fit — trimmed, then whole code
     * points dropped from the end until the UTF-8 fits.
     *
     * Whole code points, never a cut inside one. Truncating by UTF-16 units
     * splits a surrogate pair, and a lone surrogate encodes to `?` or U+FFFD
     * depending on who does the encoding; truncating by bytes splits a
     * character and produces bytes the far end must refuse, which turns a long
     * name into a refused connection. Dropping the whole character is the only
     * answer both languages can give.
     *
     * The trimmed set is spelled out rather than taken from [String.trim],
     * because the platforms differ — Foundation counts U+00A0 as whitespace and
     * java.lang.Character does not — and a contract cannot have two answers.
     *
     * A name that is empty after trimming reads as `?`. The format needs at
     * least one byte, and a blank line where a device name should be is worse
     * to look at than a placeholder.
     *
     * An app is free to show a shorter limit in its text field — "40
     * characters" reads better to a person than "63 bytes" — but that is a hint
     * to a typist. This is the rule.
     */
    fun clampName(name: String): String {
        val trimmed = name.trim { it in WHITESPACE }
        val out = StringBuilder()
        var bytes = 0
        var i = 0
        while (i < trimmed.length) {
            val cp = trimmed.codePointAt(i)
            val chars = Character.toChars(cp)
            val width = String(chars).toByteArray(StandardCharsets.UTF_8).size
            if (bytes + width > MAX_NAME_BYTES) break
            out.append(chars)
            bytes += width
            i += Character.charCount(cp)
        }
        return if (out.isEmpty()) "?" else out.toString()
    }

    /** Space, tab, newline, carriage return, vertical tab, form feed. Nothing else. */
    private const val WHITESPACE = " \t\n\r\u000B\u000C"

    internal fun nameBytes(name: String): ByteArray = clampName(name).toByteArray(StandardCharsets.UTF_8)

    /** null for anything that is not well-formed UTF-8; String(bytes) would quietly substitute. */
    /**
     * internal rather than private: Transfer's offer carries a name and a mime
     * type off the same wire under the same rule, and one definition of "is
     * this really UTF-8" is the point.
     */
    internal fun strictUtf8(b: ByteArray, from: Int, to: Int): String? = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(b, from, to - from)).toString()
    } catch (e: CharacterCodingException) {
        null
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

    /**
     * null for text that is empty or will not fit, so a caller cannot put a
     * frame on the wire the far end is obliged to refuse. Split longer text
     * with [splitForTyping], which cuts where a character ends.
     */
    fun encodeTypeText(text: String): ByteArray? {
        val bytes = text.toByteArray(Charsets.UTF_8)
        if (bytes.size !in 1..MAX_TEXT_BYTES) return null
        return byteArrayOf(23, bytes.size.toByte()) + bytes
    }

    fun encodeKey(key: Key): ByteArray = byteArrayOf(24, key.raw.toByte())

    fun encodeTextFocused(focused: Boolean): ByteArray =
        byteArrayOf(25, if (focused) 1 else 0)

    /** [key] is 32 bytes by construction; anything else is a programming error. */
    fun encodeBulkReady(port: UShort, key: ByteArray): ByteArray {
        require(key.size == 32) { "a bulk key is 32 bytes" }
        require(port != 0u.toUShort()) { "a bulk port has to dial somewhere" }
        val out = mutableListOf<Byte>(26)
        out.appendBE16(port)
        return out.toByteArray() + key
    }

    /**
     * null for text that is empty or will not fit, so a caller cannot put a
     * frame on the wire the far end is obliged to refuse.
     */
    fun encodeClipboardText(text: String): ByteArray? {
        val bytes = text.toByteArray(Charsets.UTF_8)
        if (bytes.size !in 1..MAX_CLIPBOARD_BYTES) return null
        val out = mutableListOf<Byte>(27)
        out.appendBE16(bytes.size.toUShort())
        return out.toByteArray() + bytes
    }

    /**
     * [text] in pieces that each fit one message, split between code points so
     * a multi-byte character is never cut in half — half a character is not
     * UTF-8, and the far end would refuse the whole frame.
     */
    fun splitForTyping(text: String): List<String> {
        val out = mutableListOf<String>()
        val piece = StringBuilder()
        var bytes = 0
        var i = 0
        while (i < text.length) {
            val point = text.codePointAt(i)
            val chars = Character.charCount(point)
            val width = String(Character.toChars(point)).toByteArray(Charsets.UTF_8).size
            if (bytes + width > MAX_TEXT_BYTES) {
                out.add(piece.toString())
                piece.setLength(0)
                bytes = 0
            }
            piece.appendCodePoint(point)
            bytes += width
            i += chars
        }
        if (piece.isNotEmpty()) out.add(piece.toString())
        return out
    }

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
}

// Everything is big endian; there are no exceptions. Shared with the media
// lane's header and envelope and the control lane's framing.

internal fun ByteArray.u(o: Int): UByte = this[o].toUByte()

internal fun ByteArray.be16(o: Int): UShort =
    (((this[o].toInt() and 0xFF) shl 8) or (this[o + 1].toInt() and 0xFF)).toUShort()

internal fun ByteArray.be32(o: Int): UInt =
    ((this[o].toInt() and 0xFF).toUInt() shl 24) or
        ((this[o + 1].toInt() and 0xFF).toUInt() shl 16) or
        ((this[o + 2].toInt() and 0xFF).toUInt() shl 8) or
        (this[o + 3].toInt() and 0xFF).toUInt()

internal fun ByteArray.be64(o: Int): ULong =
    (be32(o).toULong() shl 32) or be32(o + 4).toULong()

internal fun MutableList<Byte>.appendPoint(x: Double, y: Double) {
    appendBE(x.coerceIn(0.0, 1.0).toFloat().toRawBits().toUInt())
    appendBE(y.coerceIn(0.0, 1.0).toFloat().toRawBits().toUInt())
}

internal fun MutableList<Byte>.appendBE64(v: ULong) {
    appendBE((v shr 32).toUInt())
    appendBE(v.toUInt())
}

internal fun MutableList<Byte>.appendBE16(v: UShort) {
    val i = v.toInt()
    add((i shr 8).toByte())
    add(i.toByte())
}

internal fun MutableList<Byte>.appendBE(v: UInt) {
    val i = v.toInt()
    add((i shr 24).toByte())
    add((i shr 16).toByte())
    add((i shr 8).toByte())
    add(i.toByte())
}

/**
 * A UUID as the 16 bytes its string form spells (RFC 4122 order).
 *
 * Note for anyone comparing these as strings across the two languages:
 * `UUID.toString()` is lowercase here and Swift's `uuidString` is uppercase, so
 * a cross-language string comparison has to normalise. Comparing the bytes,
 * as the wire does, has no such problem.
 */
internal fun uuidBytes(u: UUID): ByteArray =
    ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()

/** Sixteen bytes at [o] as a UUID, in RFC 4122 order. */
internal fun uuidAt(b: ByteArray, o: Int): UUID {
    val buf = ByteBuffer.wrap(b, o, 16)
    return UUID(buf.long, buf.long)
}
