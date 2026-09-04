package com.roomwire.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.fail
import java.io.File
import java.util.UUID

/**
 * protocol/vectors.txt is generated from the Swift implementation and read
 * here. Neither language owns the bytes.
 *
 * Every vector must be classified. A name this file has no construction for is
 * a failure and not a skip: silently passing over a vector is precisely the
 * drift the file exists to prevent, and it would do it quietly.
 */
class PacketVectorsTest {

    @TestFactory
    fun vectors(): List<DynamicTest> {
        val file = File(System.getProperty("vectors") ?: "../../protocol/vectors.txt")
        assertTrue(file.isFile, "vectors.txt not found at ${file.absolutePath}")

        val rows = file.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { line ->
            val f = line.split("\t")
            assertEquals(3, f.size, "malformed vector line: $line")
            Triple(f[0], f[1], f[2])
        }
        // A short read must fail loudly rather than report a green suite over
        // half the format.
        assertEquals(204, rows.size, "expected 204 vectors, parsed ${rows.size}")

        return rows.map { (name, verdict, hex) ->
            DynamicTest.dynamicTest("$verdict $name") { check(name, verdict, unhex(hex)) }
        }
    }

    private fun check(name: String, verdict: String, bytes: ByteArray) = when (verdict) {
        "ENCODE" -> {
            val built = encoded(name)
                ?: fail("ENCODE vector '$name' has no construction here — the port is missing it")
            assertEquals(hex(bytes), hex(built), "$name: encoded bytes differ")
            assertTrue(decodes(name, bytes), "$name: encoded bytes must also decode")
            // And decode to the right *values*, not merely parse. Without this
            // half a vector never asserted what the bytes meant, and every
            // field's offset on the decode side was unpinned: a media key read
            // at 4..36 instead of 3..35 is still a 32-byte slice and still
            // decodes, and the media lane simply never opens.
            reencoded(name, bytes)?.let {
                assertEquals(hex(bytes), hex(it), "$name: decoded and re-encoded to different bytes")
            }
        }
        "ACCEPT" -> assertTrue(decodes(name, bytes), "$name: refused bytes it must accept")
        "REJECT" -> assertFalse(decodes(name, bytes), "$name: accepted bytes it must refuse")
        else -> fail("unknown verdict '$verdict' for '$name'")
    }

    /**
     * Which decoder a vector is held to; the name's prefix says, exactly as in
     * PacketVectors.swift. Messages by default; `chunk.` the media header;
     * `seal.` the sealed datagram, opened with key 00…1f on lane 0 — except
     * `seal.wrongLane`, opened on lane 1, which is the point of it; `frame.`
     * the control lane's framing; `pairing.` is text with no decoder.
     */
    private fun decodes(name: String, bytes: ByteArray): Boolean = when {
        name.startsWith("chunk.") -> ChunkHeader.decode(bytes) != null
        name.startsWith("seal.") -> MediaSeal.open(bytes, mediaKey, if (name == "seal.wrongLane") 1u else 0u) != null
        name.startsWith("frame.") -> Framing.Decoder().feed(bytes) != null
        name.startsWith("pairing.") -> true
        name.startsWith("transfer.") -> Transfer.decode(bytes) != null
        // A fresh opener per vector, expecting counter 1 — which is why every
        // bulk ENCODE vector is sealed by a fresh sealer, so the vectors do not
        // have to be replayed in order to mean anything.
        name.startsWith("bulk.") ->
            Bulk.Opener(mediaKey, Bulk.Lane.HOST_TO_VIEWER).open(bytes) != null
        name.startsWith("commit.") ->
            bytes.size == 48 && Pairing.opens(bytes.copyOfRange(0, 32), uuidFrom(bytes, 32))
        else -> Packet.decodeMessage(bytes) != null
    }

    /** Decode, then encode again from what came out. Must be the same bytes. */
    private fun reencoded(name: String, bytes: ByteArray): ByteArray? = when {
        name.startsWith("chunk.") -> ChunkHeader.decode(bytes)?.let { ChunkHeader.encode(it) }
        name.startsWith("seal.") -> MediaSeal.open(bytes, mediaKey, 0u)
            ?.let { MediaSeal.seal(it.first, it.second, mediaKey, 0u) }
        name.startsWith("frame.") -> Framing.Decoder().feed(bytes)
            ?.singleOrNull()?.let { Framing.encode(it) }
        name.startsWith("pairing.") || name.startsWith("commit.") -> null
        name.startsWith("transfer.") -> Transfer.decode(bytes)?.let { Transfer.encode(it) }
        // Not round-tripped: sealing again would use counter 2 and produce
        // different bytes by design. The tag already proves the bytes.
        name.startsWith("bulk.") -> null
        else -> when (val m = Packet.decodeMessage(bytes)) {
            null -> null
            is Packet.Message.Video -> m.frame.let {
                Packet.encode(
                    it.payload, it.sps, it.pps, it.keyframe, it.recovery, it.droppable,
                    it.sentMs, it.sequence, it.baseSequence, it.ltrToken,
                )
            }
            is Packet.Message.Cursor -> Packet.encodeCursor(m.seq, m.sentMs, m.x, m.y)
            is Packet.Message.CursorHidden -> Packet.encodeCursorHidden(m.seq)
            is Packet.Message.TypeText -> Packet.encodeTypeText(m.text)
            is Packet.Message.Key -> Packet.encodeKey(m.key)
            is Packet.Message.TextFocused -> Packet.encodeTextFocused(m.focused)
            is Packet.Message.Mark -> Packet.encodeMark(m.kind, m.x, m.y)
            is Packet.Message.RelayedMark -> Packet.encodeRelayedMark(m.slot, m.kind, m.x, m.y)
            is Packet.Message.Reaction -> Packet.encodeReaction(m.kind)
            is Packet.Message.Telemetry -> Packet.encodeTelemetry(
                m.frames, m.kilobytes, m.maxGapMs, m.p95GapMs, m.skipped, m.gapDropped,
            )
            Packet.Message.NeedKeyframe -> Packet.needKeyframeMessage
            Packet.Message.Identify -> Packet.identifyMessage
            is Packet.Message.AckReference -> Packet.encodeAckReference(m.token)
            Packet.Message.NeedRefresh -> Packet.needRefreshMessage
            is Packet.Message.Flight -> Packet.encodeFlight(m.records)
            is Packet.Message.Probe -> Packet.encodeProbe(m.samples)
            is Packet.Message.Input -> Packet.encodeInput(m.buttons, m.x, m.y)
            is Packet.Message.Scroll -> Packet.encodeScroll(m.dx, m.dy)
            Packet.Message.RequestControl -> Packet.requestControlMessage
            is Packet.Message.ControlGranted -> Packet.encodeControlGranted(m.granted)
            is Packet.Message.SystemGesture -> Packet.encodeSystemGesture(m.kind)
            is Packet.Message.Hello -> Packet.encodeHello(m.commitment, m.udpPort, m.name)
            is Packet.Message.Welcome -> Packet.encodeWelcome(m.udpPort, m.mediaKey, m.hostFingerprint)
            is Packet.Message.HostNonce -> Packet.encodeHostNonce(m.nonce)
            is Packet.Message.Reveal -> Packet.encodeReveal(m.token)
        }
    }

    // The inputs live in both languages; the bytes live in vectors.txt. Inputs
    // drifting apart is exactly what a byte mismatch catches, so these mirror
    // Checks/PacketVectors.swift call for call.
    private fun encoded(name: String): ByteArray? = when (name) {
        "video.keyframe" -> Packet.encode(
            payload, sps, pps, keyframe = true,
            sentMs = 0xA1B2C3D4u, sequence = 41.toUShort(), baseSequence = 20.toUShort(),
        )
        // Recovery: restarts a broken chain. Sequence at its wrap point on purpose.
        "video.delta.recovery" -> Packet.encode(
            payload, null, null, keyframe = false, recovery = true,
            sentMs = 7u, sequence = 0xFFFF.toUShort(), baseSequence = 0xFFFE.toUShort(),
        )
        "video.delta.ltr" -> Packet.encode(
            payload, null, null, keyframe = false,
            sentMs = 9u, sequence = 3.toUShort(), baseSequence = 2.toUShort(),
            ltrToken = 0xDEADBEEFCAFEF00DuL,
        )
        // The enhancement layer: baseSequence stays behind the frame it hangs off.
        "video.delta.droppable" -> Packet.encode(
            payload, null, null, keyframe = false, droppable = true,
            sentMs = 11u, sequence = 8.toUShort(), baseSequence = 4.toUShort(),
        )
        "video.keyframe.ltr" -> Packet.encode(
            payload, sps, pps, keyframe = true,
            sentMs = 1u, sequence = 0.toUShort(), baseSequence = 0.toUShort(), ltrToken = 1uL,
        )
        "video.keyframe.spsOnly" -> Packet.encode(
            payload, sps, null, keyframe = true,
            sentMs = 2u, sequence = 1.toUShort(), baseSequence = 1.toUShort(),
        )

        "cursor" -> Packet.encodeCursor(0x1234.toUShort(), 0x89ABCDEFu, 0.25, 0.75)
        "cursor.topLeft" -> Packet.encodeCursor(0.toUShort(), 0u, 0.0, 0.0)
        "cursor.bottomRight" -> Packet.encodeCursor(0xFFFF.toUShort(), 0xFFFFFFFFu, 1.0, 1.0)
        "cursorHidden" -> Packet.encodeCursorHidden(0x0102.toUShort())

        "mark.point" -> Packet.encodeMark(Packet.Mark.POINT, 0.5, 0.5)
        "mark.draw" -> Packet.encodeMark(Packet.Mark.DRAW, 0.125, 0.875)
        "mark.lift" -> Packet.encodeMark(Packet.Mark.LIFT, 1.0, 0.0)
        "mark.clear" -> Packet.encodeMark(Packet.Mark.CLEAR, 0.0, 1.0)
        // Encode clamps rather than refuses: a coordinate this far out is our
        // own arithmetic overshooting, not a hostile peer.
        "mark.clamped.high" -> Packet.encodeMark(Packet.Mark.POINT, 7.0, 3.0)
        "mark.clamped.low" -> Packet.encodeMark(Packet.Mark.POINT, -2.0, -0.5)

        "relayedMark.slot0" -> Packet.encodeRelayedMark(0u, Packet.Mark.DRAW, 0.25, 0.5)
        "relayedMark.slot7" -> Packet.encodeRelayedMark(7u, Packet.Mark.POINT, 0.75, 0.25)

        "reaction.hand" -> Packet.encodeReaction(Packet.Reaction.HAND)
        "reaction.yes" -> Packet.encodeReaction(Packet.Reaction.YES)
        "reaction.no" -> Packet.encodeReaction(Packet.Reaction.NO)
        "reaction.tooSmall" -> Packet.encodeReaction(Packet.Reaction.TOO_SMALL)

        "telemetry" -> Packet.encodeTelemetry(1800, 40_000, 250, 45, 12, 3)
        // Every field saturates rather than wraps: a count that wrapped would
        // read as a link that healed. Long.MAX_VALUE is Swift's Int.max.
        "telemetry.clamped" -> Packet.encodeTelemetry(
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
            Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE,
        )

        "needKeyframe" -> Packet.needKeyframeMessage
        "needRefresh" -> Packet.needRefreshMessage
        "identify" -> Packet.identifyMessage
        "ackReference" -> Packet.encodeAckReference(0xDEADBEEFCAFEF00DuL)

        "flight.empty" -> Packet.encodeFlight(emptyList())
        "flight.three" -> Packet.encodeFlight(
            listOf(
                Packet.FlightRecord(100.toUShort(), 0, Packet.FlightRecord.shown),
                Packet.FlightRecord(101.toUShort(), -35, Packet.FlightRecord.skipped),
                Packet.FlightRecord(
                    102.toUShort(), 0x7FFF,
                    Packet.FlightRecord.gapDropped or Packet.FlightRecord.keyframe,
                ),
            ),
        )
        // Sixty records in, forty-eight out, and it is the newest that survive.
        "flight.capped" -> Packet.encodeFlight(
            (0 until 60).map {
                Packet.FlightRecord(it.toUShort(), it.toShort(), Packet.FlightRecord.shown)
            },
        )

        "probe.two" -> Packet.encodeProbe(
            listOf(
                Packet.ProbeSample(drawn = true, ms = 1000u, x = 0.0, y = 1.0, seq = 5.toUShort()),
                Packet.ProbeSample(drawn = false, ms = 1016u, x = 0.5, y = 0.25, seq = 6.toUShort()),
            ),
        )
        // NaN reads as zero on both sides; the infinities clamp to the ends
        // rather than being caught with it. Swift traps here and Kotlin throws
        // if either is got wrong, so this vector is the one that proves the two
        // guards agree instead of merely both existing.
        "probe.hostileCoordinates" -> Packet.encodeProbe(
            listOf(
                Packet.ProbeSample(
                    drawn = true, ms = 1u,
                    x = Double.NaN, y = Double.POSITIVE_INFINITY, seq = 1.toUShort(),
                ),
                Packet.ProbeSample(
                    drawn = false, ms = 2u,
                    x = Double.NEGATIVE_INFINITY, y = Double.NaN, seq = 2.toUShort(),
                ),
            ),
        )

        // buttons is the whole state, not an edge — bit0 left, bit1 right.
        "input.noButtons" -> Packet.encodeInput(0u, 0.5, 0.5)
        "input.left" -> Packet.encodeInput(1u, 0.1, 0.2)
        "input.right" -> Packet.encodeInput(2u, 0.3, 0.4)
        "input.both" -> Packet.encodeInput(3u, 1.0, 1.0)
        // Encode masks the undefined bits away; decode refuses them.
        "input.maskedToThree" -> Packet.encodeInput(0xFFu, 0.0, 0.0)

        "scroll.positive" -> Packet.encodeScroll(120, 45)
        "scroll.negative" -> Packet.encodeScroll(-120, -45)
        "scroll.extremes" -> Packet.encodeScroll(Short.MIN_VALUE, Short.MAX_VALUE)

        "requestControl" -> Packet.requestControlMessage
        "controlGranted.true" -> Packet.encodeControlGranted(true)
        "controlGranted.false" -> Packet.encodeControlGranted(false)

        "systemGesture.missionControl" -> Packet.encodeSystemGesture(Packet.SystemGesture.MISSION_CONTROL)
        "systemGesture.appWindows" -> Packet.encodeSystemGesture(Packet.SystemGesture.APP_WINDOWS)
        "systemGesture.spaceLeft" -> Packet.encodeSystemGesture(Packet.SystemGesture.SPACE_LEFT)
        "systemGesture.spaceRight" -> Packet.encodeSystemGesture(Packet.SystemGesture.SPACE_RIGHT)

        // Typing. The length byte counts bytes and the text is characters, so
        // the multi-byte cases are the ones that matter: "héllo" is five
        // characters and six bytes, "ok 👍" four characters and seven.
        "typeText.ascii" -> Packet.encodeTypeText("hello")
        "typeText.oneByteChar" -> Packet.encodeTypeText("a")
        "typeText.multiByte" -> Packet.encodeTypeText("héllo")
        "typeText.emoji" -> Packet.encodeTypeText("ok \uD83D\uDC4D")
        "typeText.newline" -> Packet.encodeTypeText("a\nb")
        "typeText.maxLength" -> Packet.encodeTypeText("x".repeat(255))

        "key.backspace" -> Packet.encodeKey(Packet.Key.BACKSPACE)
        "key.enter" -> Packet.encodeKey(Packet.Key.ENTER)
        "key.tab" -> Packet.encodeKey(Packet.Key.TAB)
        "key.escape" -> Packet.encodeKey(Packet.Key.ESCAPE)
        "key.left" -> Packet.encodeKey(Packet.Key.LEFT)
        "key.right" -> Packet.encodeKey(Packet.Key.RIGHT)
        "key.up" -> Packet.encodeKey(Packet.Key.UP)
        "key.down" -> Packet.encodeKey(Packet.Key.DOWN)

        "textFocused.true" -> Packet.encodeTextFocused(true)
        "textFocused.false" -> Packet.encodeTextFocused(false)

        // The transfer codec. The two length fields in an offer are the only
        // thing separating a multi-byte name from an empty mime type, so those
        // are the cases worth pinning.
        "transfer.offer" -> Transfer.encode(
            Transfer.Frame.Offered(
                Transfer.Offer(
                    7u, 0x0102_0304_0506_0708uL, 0x1122_3344_5566_7788uL,
                    headHash, false, "holiday.jpg", "image/jpeg",
                ),
            ),
        )
        "transfer.offer.utf8" -> Transfer.encode(
            Transfer.Frame.Offered(
                Transfer.Offer(1u, 5uL, 0uL, headHash, false, "h\u00e9\uD83D\uDC4D.txt", ""),
            ),
        )
        "transfer.offer.clipboard" -> Transfer.encode(
            Transfer.Frame.Offered(
                Transfer.Offer(2u, 11uL, 0uL, headHash, true, "clipboard", "text/plain"),
            ),
        )
        "transfer.accept" -> Transfer.encode(Transfer.Frame.Accept(7u, 0xDEAD_BEEFuL))
        "transfer.accept.zero" -> Transfer.encode(Transfer.Frame.Accept(7u, 0uL))
        "transfer.reject" -> Transfer.encode(Transfer.Frame.Rejected(7u, Transfer.Reject.NO_SPACE))
        "transfer.data" -> Transfer.encode(
            Transfer.Frame.Data(7u, byteArrayOf(1, 2, 3, 4)),
        )
        "transfer.done" -> Transfer.encode(Transfer.Frame.Done(7u, wholeHash))
        "transfer.cancel" -> Transfer.encode(
            Transfer.Frame.Cancel(7u, Transfer.Reject.DECLINED),
        )
        "transfer.bye" -> Transfer.encode(Transfer.Frame.Bye)

        // A fresh sealer each, so each is counter 1.
        "bulk.bye" -> Bulk.Sealer(mediaKey, Bulk.Lane.HOST_TO_VIEWER)
            .seal(Transfer.encode(Transfer.Frame.Bye))
        "bulk.data" -> Bulk.Sealer(mediaKey, Bulk.Lane.HOST_TO_VIEWER)
            .seal(Transfer.encode(Transfer.Frame.Data(3u, byteArrayOf(9, 8, 7))))

        // The token is a UUID in RFC 4122 byte order — the same bytes its
        // string form spells — so both sides can key a trust store by the string.
        "hello" -> Packet.encodeHello(commitment, 0xC001u, "Ada’s Pixel")
        "hello.longName" -> Packet.encodeHello(commitment, 1u, "n".repeat(63))
        // A name is made to fit by the protocol, not by whatever the platform
        // stored. Forty emoji is 160 bytes; the clamp drops whole characters
        // until it fits, which is fifteen of them — a UTF-16 truncation would
        // split a surrogate pair here and a byte truncation would split a
        // character, and both produce a hello the far end must refuse.
        "hello.clamped.emoji" -> Packet.encodeHello(commitment, 1u, "\uD83D\uDE00".repeat(40))
        "hello.clamped.exactly63" -> Packet.encodeHello(commitment, 1u, "é".repeat(31) + "a")
        "hello.clamped.overByOne" -> Packet.encodeHello(commitment, 1u, "é".repeat(32))
        "hello.clamped.trimmed" -> Packet.encodeHello(commitment, 1u, "  Ada's Mac \t\n")
        "hello.clamped.blank" -> Packet.encodeHello(commitment, 1u, " \t\r\n ")
        "welcome" -> Packet.encodeWelcome(0xD002u, mediaKey, ByteArray(32) { (0x40 + it).toByte() })
        "hostNonce" -> Packet.encodeHostNonce(hostNonce)
        "reveal" -> Packet.encodeReveal(token)

        "chunk.video" -> ChunkHeader.encode(videoFields)
        "chunk.message" -> ChunkHeader.encode(messageFields)
        "chunk.ping" -> ChunkHeader.encode(pingFields)

        // ChaCha20-Poly1305 is deterministic in key, nonce, header and body. Key
        // 00…1f, lane 0 (host to viewer).
        "seal.video" -> MediaSeal.seal(videoFields, ByteArray(16) { it.toByte() }, mediaKey, 0u)
        "seal.message" -> MediaSeal.seal(messageFields, Packet.needKeyframeMessage, mediaKey, 0u)
        "seal.ping" -> MediaSeal.seal(pingFields, ByteArray(0), mediaKey, 0u)
        // A counter with its top half set: the only vector that would notice a
        // 32-bit read, or a signed one on the JVM.
        "seal.counterMax" -> MediaSeal.seal(
            ChunkHeader.Fields(ChunkHeader.Kind.VIDEO, ULong.MAX_VALUE, 0x01020304u, 2u, 150u),
            ByteArray(16) { it.toByte() }, mediaKey, 0u,
        )

        // Six characters both screens show; here as the ASCII they are.
        "pairing.code" -> Pairing.code(
            ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 },
            UUID(0x3333333333333333L, 0x3333333333333333L), hostNonce,
        ).toByteArray(Charsets.US_ASCII)
        // A commitment and the token it opens, as 48 bytes.
        "commit.matches" -> commitment + uuidBytesOf(token)

        "frame.control" -> Framing.encode(Packet.needKeyframeMessage)

        else -> null
    }

    private companion object {
        val sps = byteArrayOf(0x67, 0x64, 0x00, 0x1f)
        val pps = byteArrayOf(0x68, 0xeb.toByte(), 0xe3.toByte(), 0xcb.toByte())
        val payload = byteArrayOf(0x00, 0x00, 0x00, 0x05, 0x65, 0x01, 0x02, 0x03, 0x04)

        val token: UUID = UUID.fromString("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
        val commitment: ByteArray = Pairing.commitment(token)
        val hostNonce = ByteArray(16) { (0x50 + it).toByte() }

        fun uuidBytesOf(u: UUID): ByteArray =
            java.nio.ByteBuffer.allocate(16).putLong(u.mostSignificantBits)
                .putLong(u.leastSignificantBits).array()

        fun uuidFrom(b: ByteArray, o: Int): UUID {
            val buf = java.nio.ByteBuffer.wrap(b, o, 16)
            return UUID(buf.long, buf.long)
        }
        val mediaKey = ByteArray(32) { it.toByte() }

        /** The two hashes an offer carries, matching PacketVectors.swift. */
        val headHash = ByteArray(32) { (0xA0 + it).toByte() }
        val wholeHash = ByteArray(32) { (0xB0 + it).toByte() }
        val videoFields = ChunkHeader.Fields(ChunkHeader.Kind.VIDEO, 7uL, 0x01020304u, 2u.toUShort(), 150u.toUShort())
        val messageFields = ChunkHeader.Fields(ChunkHeader.Kind.MESSAGE, 8uL, 0u, 0u.toUShort(), 1u.toUShort())
        val pingFields = ChunkHeader.Fields(ChunkHeader.Kind.PING, 9uL, 0u, 0u.toUShort(), 1u.toUShort())

        fun unhex(s: String) = ByteArray(s.length / 2) {
            s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}
