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
        assertEquals(127, rows.size, "expected 127 vectors, parsed ${rows.size}")

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
        else -> Packet.decodeMessage(bytes) != null
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

        // The token is a UUID in RFC 4122 byte order — the same bytes its
        // string form spells — so both sides can key a trust store by the string.
        "hello" -> Packet.encodeHello(token, 0xC001u, "Ada’s Pixel")
        "hello.longName" -> Packet.encodeHello(token, 1u, "n".repeat(63))
        "welcome" -> Packet.encodeWelcome(0xD002u, mediaKey, ByteArray(32) { (0x40 + it).toByte() })

        "chunk.video" -> ChunkHeader.encode(videoFields)
        "chunk.message" -> ChunkHeader.encode(messageFields)
        "chunk.ping" -> ChunkHeader.encode(pingFields)

        // ChaCha20-Poly1305 is deterministic in key, nonce, header and body. Key
        // 00…1f, lane 0 (host to viewer).
        "seal.video" -> MediaSeal.seal(videoFields, ByteArray(16) { it.toByte() }, mediaKey, 0u)
        "seal.message" -> MediaSeal.seal(messageFields, Packet.needKeyframeMessage, mediaKey, 0u)
        "seal.ping" -> MediaSeal.seal(pingFields, ByteArray(0), mediaKey, 0u)

        // Six characters both screens show; here as the ASCII they are.
        "pairing.code" -> Pairing.code(
            ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 },
            UUID(0x3333333333333333L, 0x3333333333333333L),
        ).toByteArray(Charsets.US_ASCII)

        "frame.control" -> Framing.encode(Packet.needKeyframeMessage)

        else -> null
    }

    private companion object {
        val sps = byteArrayOf(0x67, 0x64, 0x00, 0x1f)
        val pps = byteArrayOf(0x68, 0xeb.toByte(), 0xe3.toByte(), 0xcb.toByte())
        val payload = byteArrayOf(0x00, 0x00, 0x00, 0x05, 0x65, 0x01, 0x02, 0x03, 0x04)

        val token: UUID = UUID.fromString("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
        val mediaKey = ByteArray(32) { it.toByte() }
        val videoFields = ChunkHeader.Fields(ChunkHeader.Kind.VIDEO, 7uL, 0x01020304u, 2u.toUShort(), 150u.toUShort())
        val messageFields = ChunkHeader.Fields(ChunkHeader.Kind.MESSAGE, 8uL, 0u, 0u.toUShort(), 1u.toUShort())
        val pingFields = ChunkHeader.Fields(ChunkHeader.Kind.PING, 9uL, 0u, 0u.toUShort(), 1u.toUShort())

        fun unhex(s: String) = ByteArray(s.length / 2) {
            s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}
