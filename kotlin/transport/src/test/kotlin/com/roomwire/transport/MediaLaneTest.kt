package com.roomwire.transport

import com.roomwire.protocol.ChunkHeader
import com.roomwire.protocol.Chunker
import com.roomwire.protocol.MediaSeal
import com.roomwire.protocol.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * The real media lane against a real socket. `DatagramChannel` is plain JVM, so
 * the whole receive path — open, replay, reassemble — runs on a laptop with no
 * phone and no Mac, which is the half of the Android transport most likely to
 * be wrong and the half a device test would be slowest to find.
 *
 * The other end is a bare socket sealing as the host would, so what is being
 * tested is this side's agreement with the wire and not with itself.
 */
class MediaLaneTest {

    private val key = ByteArray(32) { it.toByte() }

    private class Host(port: Int) {
        val channel: DatagramChannel = DatagramChannel.open().apply {
            bind(InetSocketAddress(0))
            connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
        }
        val port: Int get() = (channel.localAddress as InetSocketAddress).port
        fun send(datagram: ByteArray) {
            channel.write(ByteBuffer.wrap(datagram))
        }
        fun close() = channel.close()
    }

    @Test
    fun `a frame in slices comes back whole, and out of order still comes back whole`() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val lane = MediaLane(scope)
        val host = Host(lane.port)
        val sealer = MediaSeal.Sealer(key, MediaSeal.Role.HOST)

        val frames = mutableListOf<ByteArray>()
        val arrived = CountDownLatch(2)
        lane.onPacket = { frames.add(it); arrived.countDown() }
        lane.connect(InetAddress.getLoopbackAddress(), host.port, key)

        // 200 KB is a keyframe's order of magnitude: 147 slices, well past
        // anything a single datagram could carry.
        val frame = ByteArray(200_000).also { Random(7).nextBytes(it) }.also { it[0] = 1 }
        val slices = Chunker.slice(frame)!!
        assertTrue(slices.size > 100, "a 200 KB frame should be many slices, was ${slices.size}")
        for ((i, body) in slices.withIndex()) {
            host.send(sealer.seal(ChunkHeader.Kind.VIDEO, body, 1u, i.toUShort(), slices.size.toUShort()))
        }

        // And again backwards. UDP reorders; the reassembler is what makes that
        // stop mattering.
        val second = ByteArray(50_000).also { Random(9).nextBytes(it) }.also { it[0] = 1 }
        val secondSlices = Chunker.slice(second)!!
        for (i in secondSlices.indices.reversed()) {
            host.send(sealer.seal(ChunkHeader.Kind.VIDEO, secondSlices[i], 2u, i.toUShort(), secondSlices.size.toUShort()))
        }

        assertTrue(arrived.await(10, TimeUnit.SECONDS), "frames never arrived: got ${frames.size}")
        assertArrayEquals(frame, frames[0], "the in-order frame came back changed")
        assertArrayEquals(second, frames[1], "the reordered frame came back changed")

        lane.close(); host.close(); scope.cancel()
    }

    @Test
    fun `a small message arrives whole and a ping delivers nothing`() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val lane = MediaLane(scope)
        val host = Host(lane.port)
        val sealer = MediaSeal.Sealer(key, MediaSeal.Role.HOST)

        val packets = mutableListOf<ByteArray>()
        val arrived = CountDownLatch(1)
        val live = CountDownLatch(1)
        lane.onLive = { live.countDown() }
        lane.onPacket = { packets.add(it); arrived.countDown() }
        lane.connect(InetAddress.getLoopbackAddress(), host.port, key)

        // A ping proves the lane and delivers nothing to the app.
        host.send(sealer.seal(ChunkHeader.Kind.PING, ByteArray(0)))
        assertTrue(live.await(5, TimeUnit.SECONDS), "a ping did not bring the lane up")

        val cursor = Packet.encodeCursor(7u, 1234u, 0.25, 0.75)
        host.send(sealer.seal(ChunkHeader.Kind.MESSAGE, cursor))
        assertTrue(arrived.await(5, TimeUnit.SECONDS), "the message never arrived")
        assertEquals(1, packets.size, "a ping was delivered to the app")
        assertArrayEquals(cursor, packets[0])

        lane.close(); host.close(); scope.cancel()
    }

    @Test
    fun `forged and replayed datagrams deliver nothing`() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val lane = MediaLane(scope)
        val host = Host(lane.port)
        val sealer = MediaSeal.Sealer(key, MediaSeal.Role.HOST)

        val packets = mutableListOf<ByteArray>()
        val arrived = CountDownLatch(1)
        lane.onPacket = { packets.add(it); arrived.countDown() }
        lane.connect(InetAddress.getLoopbackAddress(), host.port, key)

        // Sealed under another key.
        val stranger = MediaSeal.Sealer(ByteArray(32) { 0x5A }, MediaSeal.Role.HOST)
        host.send(stranger.seal(ChunkHeader.Kind.MESSAGE, Packet.needKeyframeMessage))
        // Sealed on the lane this end sends on rather than receives on, which
        // is what one shared lane constant would produce at both ends.
        host.send(MediaSeal.seal(
            ChunkHeader.Fields(ChunkHeader.Kind.MESSAGE, 1uL, 0u, 0u, 1u),
            Packet.needKeyframeMessage, key, 1u,
        ))
        // A bit flipped in the tag.
        val tampered = sealer.seal(ChunkHeader.Kind.MESSAGE, Packet.needKeyframeMessage)
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
        host.send(tampered)
        // Random bytes.
        host.send(ByteArray(200).also { Random(3).nextBytes(it) })

        // Then one real one, twice. The second is a replay.
        val real = sealer.seal(ChunkHeader.Kind.MESSAGE, Packet.identifyMessage)
        host.send(real)
        assertTrue(arrived.await(5, TimeUnit.SECONDS), "the genuine datagram never arrived")
        host.send(real)
        Thread.sleep(300)

        assertEquals(1, packets.size, "something forged or replayed was delivered: ${packets.size}")
        assertArrayEquals(Packet.identifyMessage, packets[0])

        lane.close(); host.close(); scope.cancel()
    }
}
