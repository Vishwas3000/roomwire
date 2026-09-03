package com.roomwire.transport

import com.roomwire.protocol.ChunkHeader
import com.roomwire.protocol.MediaSeal
import com.roomwire.protocol.Reassembler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

/**
 * The viewer's end of the media lane. No Android in it — `DatagramChannel` is
 * plain JVM — so this runs, and is tested, on a laptop.
 *
 * The socket is bound before `hello` is sent, because `hello` has to carry the
 * port: the host dials the viewer, which is what spares every viewer from
 * needing a listener anybody has to find. Once `welcome` names the host's port
 * the channel is *connected* to it, so the kernel drops anything from anywhere
 * else before it ever reaches this code.
 */
class MediaLane(private val scope: CoroutineScope) {
    /** A whole `Packet` message: a reassembled frame, or a small message that fitted one datagram. */
    var onPacket: ((ByteArray) -> Unit)? = null

    /** The first datagram that opened. Until one does, the lane is only half proven. */
    var onLive: (() -> Unit)? = null

    private val channel: DatagramChannel = DatagramChannel.open().apply {
        bind(InetSocketAddress(0))
    }

    /** What goes in the hello. */
    val port: Int get() = (channel.localAddress as InetSocketAddress).port

    private var sealer: MediaSeal.Sealer? = null
    private var opener: MediaSeal.Opener? = null
    private val reassembler = Reassembler()
    private var reader: Job? = null
    private var pinger: Job? = null
    @Volatile private var live = false

    /**
     * Called once `welcome` has been read and checked. The key is this
     * session's and only this session's — a key kept from a previous connection
     * would be used again with a counter that restarts at 1.
     */
    fun connect(host: java.net.InetAddress, hostPort: Int, key: ByteArray) {
        channel.connect(InetSocketAddress(host, hostPort))
        sealer = MediaSeal.Sealer(key, MediaSeal.Role.VIEWER)
        opener = MediaSeal.Opener(key, MediaSeal.Role.VIEWER)
        reader = scope.launch(Dispatchers.IO) { read() }
        // The host is already pinging; answering is what makes the lane
        // two-way. A NAT or a firewall between the two shows up exactly here.
        pinger = scope.launch {
            while (isActive && !live) {
                ping()
                delay(1000)
            }
        }
    }

    fun ping() {
        write(sealer?.seal(ChunkHeader.Kind.PING, ByteArray(0)) ?: return)
    }

    /** False when the message does not fit one datagram; the caller then uses the control lane. */
    fun send(message: ByteArray): Boolean {
        if (message.size > ChunkHeader.BODY) return false
        write(sealer?.seal(ChunkHeader.Kind.MESSAGE, message) ?: return false)
        return true
    }

    fun close() {
        pinger?.cancel()
        reader?.cancel()
        try {
            channel.close()
        } catch (e: IOException) {
            // Closing a socket that is already gone is not a failure.
        }
    }

    private fun write(datagram: ByteArray) {
        try {
            channel.write(ByteBuffer.wrap(datagram))
        } catch (e: IOException) {
            // A datagram that could not be handed to the kernel is a datagram
            // lost, which this lane is built to survive.
        }
    }

    private suspend fun read() {
        val buffer = ByteBuffer.allocateDirect(ChunkHeader.DATAGRAM_MAX)
        while (scope.isActive) {
            buffer.clear()
            val got = try {
                channel.read(buffer)
            } catch (e: IOException) {
                return
            }
            if (got <= 0) return
            buffer.flip()
            val datagram = ByteArray(got)
            buffer.get(datagram)
            val (fields, body) = opener?.open(datagram) ?: continue
            if (!live) {
                live = true
                onLive?.invoke()
            }
            when (fields.kind) {
                // Slices in, whole frames out, and only frames newer than the
                // last delivered. A frame with a hole in it is never handed up
                // late: recovering the picture is the encoder's job.
                ChunkHeader.Kind.VIDEO ->
                    reassembler.absorb(fields, body, System.nanoTime() / 1e9)?.let { onPacket?.invoke(it) }
                ChunkHeader.Kind.MESSAGE -> if (body.isNotEmpty()) onPacket?.invoke(body)
                ChunkHeader.Kind.PING -> Unit
            }
        }
    }
}
