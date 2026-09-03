package com.roomwire.transport

import com.roomwire.protocol.Packet
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.util.UUID

/**
 * The fake exists so an app's viewer can be tested with nothing in the room, so
 * what is asserted here is the part an app depends on: the state sequence, the
 * clock it runs on, and that what it emits is real `Packet` bytes rather than
 * something shaped like them.
 *
 * Everything runs on `runTest`'s virtual clock. If any wait in FakeViewer were a
 * wall-clock timer instead of a `delay` on the supplied scope, these tests would
 * hang rather than pass — which is the check that matters most.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FakeViewerTest {

    @Test
    fun `browse then join reaches connected through every state`() = runTest {
        val viewer = FakeViewer(backgroundScope)
        assertEquals(ViewerState.Idle, viewer.state.value)

        viewer.startBrowsing()
        assertEquals(ViewerState.Browsing, viewer.state.value)
        assertTrue(viewer.hosts.value.isEmpty(), "a host before discovery has run")
        advanceTimeBy(301)
        assertEquals(listOf(DiscoveredHost("Fake Mac", 1, "Fake Mac")), viewer.hosts.value)

        val host = viewer.hosts.value.first()
        viewer.join(host, UUID.randomUUID(), "Pixel")
        assertEquals(ViewerState.Connecting(host), viewer.state.value)

        advanceTimeBy(101)
        val waiting = assertInstanceOf(ViewerState.AwaitingApproval::class.java, viewer.state.value)
        assertEquals("ABC234", waiting.code)
        assertTrue(!waiting.hostChanged, "a fake host has never changed its certificate")

        advanceTimeBy(1500)
        val connected = assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value)
        assertEquals("Fake Mac", connected.session.peer.displayName)
        assertEquals(64, connected.session.peer.fingerprintHex.length, "a fingerprint is 32 bytes of hex")
    }

    @Test
    fun `what a connected session emits decodes as packets`() = runTest {
        val viewer = FakeViewer(backgroundScope)
        val seen = mutableListOf<Packet.Message>()
        viewer.startBrowsing()
        advanceTimeBy(301)
        viewer.join(viewer.hosts.value.first(), UUID.randomUUID(), "Pixel")
        advanceTimeBy(1601)

        val session = assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value).session
        session.onPacket = { bytes ->
            // Nothing shaped like a packet: the real decoder, or the test fails.
            seen += Packet.decodeMessage(bytes) ?: error("emitted bytes that do not decode")
        }
        advanceTimeBy(3100)

        val cursors = seen.filterIsInstance<Packet.Message.Cursor>()
        assertTrue(cursors.size > 150, "60 Hz for three seconds is ~180 cursors, saw ${cursors.size}")
        // Round a circle of radius 0.35 about the centre: every point on it, and
        // both extremes reached within one turn.
        assertTrue(
            cursors.all { hypotFromCentre(it) in 0.34..0.36 },
            "a cursor left the circle it is supposed to trace",
        )
        assertTrue(cursors.any { it.x > 0.84 } && cursors.any { it.x < 0.16 }, "the circle never came round")

        val marks = seen.filterIsInstance<Packet.Message.RelayedMark>()
        assertEquals(1, marks.size, "exactly one relayed mark, at one second")
        assertEquals(Packet.Mark.POINT, marks.first().kind)
        assertEquals(0u.toUByte(), marks.first().slot)

        assertEquals(
            listOf(true), seen.filterIsInstance<Packet.Message.ControlGranted>().map { it.granted },
            "control is granted once, at three seconds",
        )
    }

    @Test
    fun `send is recorded and a keyframe request replays the fixture`() = runTest {
        val fixture = fixture(frames = 3)
        val viewer = FakeViewer(backgroundScope, video = { ByteArrayInputStream(fixture) })
        viewer.startBrowsing()
        advanceTimeBy(301)
        viewer.join(viewer.hosts.value.first(), UUID.randomUUID(), "Pixel")
        advanceTimeBy(1601)
        val session = assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value).session

        var keyframes = 0
        session.onPacket = { bytes ->
            val message = Packet.decodeMessage(bytes)
            if (message is Packet.Message.Video && message.frame.keyframe) keyframes += 1
        }
        advanceTimeBy(200)
        assertTrue(keyframes >= 1, "the fixture must start with a keyframe")

        session.send(Packet.needKeyframeMessage, Reliability.RELIABLE)
        session.send(Packet.encodeMark(Packet.Mark.DRAW, 0.25, 0.75))
        assertEquals(2, viewer.sent.size, "send must record what it was given")
        assertEquals(8, viewer.sent.first().first().toInt(), "the first send was a keyframe request")

        val before = keyframes
        advanceTimeBy(200)
        assertTrue(keyframes > before, "a keyframe request must replay the fixture from its keyframe")
    }

    @Test
    fun `browsing resumes after a failure and leaving cancels a pending join`() = runTest {
        val viewer = FakeViewer(backgroundScope)
        viewer.startBrowsing()
        advanceTimeBy(301)
        val host = viewer.hosts.value.first()

        // Stream A's controller drops back to browsing from a failure, so
        // startBrowsing has to be valid there and valid twice.
        viewer.startBrowsing()
        viewer.startBrowsing()
        assertEquals(ViewerState.Browsing, viewer.state.value)

        // Leaving while waiting for the presenter cancels the join: the answer,
        // whenever it comes, must arrive to nobody.
        viewer.join(host, UUID.randomUUID(), "Pixel")
        advanceTimeBy(101)
        assertInstanceOf(ViewerState.AwaitingApproval::class.java, viewer.state.value)
        viewer.leave()
        assertEquals(ViewerState.Browsing, viewer.state.value)
        advanceTimeBy(5000)
        assertEquals(ViewerState.Browsing, viewer.state.value, "a cancelled join still connected")

        // And a second join after that one still works.
        viewer.join(host, UUID.randomUUID(), "Pixel")
        advanceTimeBy(1601)
        assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value)
    }

    @Test
    fun `a join can be made to fail, and browsing resumes from there`() = runTest {
        val viewer = FakeViewer(backgroundScope)
        viewer.startBrowsing()
        advanceTimeBy(301)
        val host = viewer.hosts.value.first()

        viewer.failNextJoin("declined")
        viewer.join(host, UUID.randomUUID(), "Pixel")
        advanceTimeBy(101)
        assertInstanceOf(ViewerState.AwaitingApproval::class.java, viewer.state.value)
        advanceTimeBy(1500)
        assertEquals(ViewerState.Failed("declined"), viewer.state.value)

        // Failed is not a dead viewer: the way back is to look again.
        viewer.startBrowsing()
        assertEquals(ViewerState.Browsing, viewer.state.value)

        // And the failure was consumed — the next join connects.
        viewer.join(host, UUID.randomUUID(), "Pixel")
        advanceTimeBy(1601)
        assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value)
    }

    @Test
    fun `a changed host certificate reaches the approval state`() = runTest {
        val viewer = FakeViewer(backgroundScope, hostChanged = true)
        viewer.startBrowsing()
        advanceTimeBy(301)
        viewer.join(viewer.hosts.value.first(), UUID.randomUUID(), "Pixel")
        advanceTimeBy(101)

        val waiting = assertInstanceOf(ViewerState.AwaitingApproval::class.java, viewer.state.value)
        assertTrue(waiting.hostChanged, "the warning a re-keyed host has to raise")
        // It is a warning and not a refusal: approval still completes.
        advanceTimeBy(1500)
        assertInstanceOf(ViewerState.Connected::class.java, viewer.state.value)
    }

    private fun hypotFromCentre(c: Packet.Message.Cursor): Double =
        kotlin.math.hypot(c.x - 0.5, c.y - 0.5)

    /** `[u32 length][Packet bytes]` repeated, first frame a keyframe, 33 ms apart. */
    private fun fixture(frames: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (i in 0 until frames) {
            val frame = Packet.encode(
                payload = byteArrayOf(0, 0, 0, 5, 0x65, 1, 2, 3, 4),
                sps = if (i == 0) byteArrayOf(0x67, 0x64, 0x00, 0x1f) else null,
                pps = if (i == 0) byteArrayOf(0x68, 0xeb.toByte(), 0xe3.toByte(), 0xcb.toByte()) else null,
                keyframe = i == 0,
                sentMs = (i * 33).toUInt(),
                sequence = i.toUShort(),
                baseSequence = i.toUShort(),
            )
            out.write(byteArrayOf((frame.size ushr 24).toByte(), (frame.size ushr 16).toByte(),
                                  (frame.size ushr 8).toByte(), frame.size.toByte()))
            out.write(frame)
        }
        return out.toByteArray()
    }
}
