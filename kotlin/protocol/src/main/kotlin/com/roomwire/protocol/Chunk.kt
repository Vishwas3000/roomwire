package com.roomwire.protocol

/**
 * A port of swift/Sources/RoomWireProtocol/Chunk.swift.
 *
 * One datagram on the media lane: a 17-byte cleartext header, the body under
 * ChaCha20-Poly1305 with that header as associated data, then the 16-byte tag.
 *
 *   [0]      kind: 0 a slice of a video frame, 1 a whole small message, 2 a ping
 *   [1..8]   counter: per sender, per session, from 1, +1 every datagram. The
 *            AEAD nonce and the replay window both hang off it, and the key it
 *            is used under lives exactly as long as it does — see MediaSeal.
 *   [9..12]  frame id: video only — per connection, +1 per frame sent. Ignored
 *            for a message or a ping, and *not* checked: neither end has any use
 *            for it there, so there is nothing for a decoder to enforce.
 *   [13..14] index of this slice within its frame
 *   [15..16] slices in the frame: 1…512 for video, exactly 1 for anything else
 *
 * 1400 bytes is the datagram ceiling: a real-time stream never leans on IP
 * fragmentation. What the header and the tag leave for the body is 1367.
 */
object ChunkHeader {
    const val SIZE = 17
    const val DATAGRAM_MAX = 1400
    const val TAG = 16
    const val BODY = DATAGRAM_MAX - SIZE - TAG   // 1367
    /** 512 slices is 700 KB, past anything the encoder produces; more is refused. */
    val MAX_CHUNKS: UShort = 512u

    /**
     * 3 is deliberately unallocated: it is the byte the `chunk.unknownKind`
     * vector uses to prove an unknown kind is refused. A grouped parity would
     * have to be a new kind (5) — a receiver that knows only 4 would apply a
     * group's parity to the whole frame and deliver a corrupt one.
     */
    enum class Kind(val raw: UByte) {
        VIDEO(0u), MESSAGE(1u), PING(2u),
        /** The XOR of one frame's slices; `index` carries the last slice's length. */
        PARITY(4u);

        companion object {
            fun of(raw: UByte): Kind? = Kind.entries.firstOrNull { it.raw == raw }
        }
    }

    data class Fields(val kind: Kind, val counter: ULong, val frameId: UInt, val index: UShort, val count: UShort)

    fun encode(f: Fields): ByteArray {
        val out = mutableListOf<Byte>(f.kind.raw.toByte())
        out.appendBE64(f.counter)
        out.appendBE(f.frameId)
        out.appendBE16(f.index)
        out.appendBE16(f.count)
        return out.toByteArray()
    }

    /**
     * Reads the header off the front of a datagram. Network input: the kind
     * must be one we know and the count 1…512; then what index means, and what
     * count may be, depends on the kind — a slice's index falls inside the
     * count, a parity's index is a slice length inside the body, and a message
     * or ping is exactly one chunk at index 0.
     */
    fun decode(d: ByteArray): Fields? {
        if (d.size < SIZE) return null
        val kind = Kind.of(d.u(0)) ?: return null
        val index = d.be16(13)
        val count = d.be16(15)
        if (count < 1u || count > MAX_CHUNKS) return null
        val ok = when (kind) {
            Kind.VIDEO -> index < count
            Kind.PARITY -> index >= 1u && index.toInt() <= BODY
            Kind.MESSAGE, Kind.PING -> count == 1u.toUShort() && index == 0u.toUShort()
        }
        if (!ok) return null
        return Fields(kind, d.be64(1), d.be32(9), index, count)
    }
}

/**
 * Cuts a frame into bodies of at most [ChunkHeader.BODY] bytes. The headers are
 * the transport's to write — counter and frame id are per peer — so a frame is
 * sliced once and sealed once per viewer.
 *
 * null for an empty frame, or one that would need more than 512 slices — which
 * is 699,904 bytes, and a 5K keyframe at high quality can exceed it. **A caller
 * that gets null must ask the encoder for another keyframe and say so in a log,
 * not return quietly**: dropping the one frame the stream cannot start without,
 * silently, is the whole failure. `count` is a u16, so raising the cap later is
 * a sender-only change.
 */
object Chunker {
    fun slice(frame: ByteArray): List<ByteArray>? {
        if (frame.isEmpty()) return null
        val body = ChunkHeader.BODY
        val count = (frame.size + body - 1) / body
        if (count > ChunkHeader.MAX_CHUNKS.toInt()) return null
        return List(count) { i -> frame.copyOfRange(i * body, minOf((i + 1) * body, frame.size)) }
    }
}

/**
 * Puts slices back into frames. One per receiving connection, one thread.
 *
 * UDP reorders and loses; H.264 only decodes forward. So only a frame newer
 * than the last one delivered ever comes back, a frame missing a slice is never
 * delivered late, and a partial whose first slice is older than the deadline is
 * scrap. Frame ids wrap at 32 bits and compare by signed distance.
 */
class Reassembler {
    private class Partial(val count: Int, val firstSeen: Double, val slices: Array<ByteArray?>) {
        var have = 0
    }

    private val partials = HashMap<UInt, Partial>()
    private var lastDelivered: UInt? = null

    /** One slice in, possibly one whole frame out. */
    fun absorb(h: ChunkHeader.Fields, body: ByteArray, now: Double): ByteArray? {
        // Fields is public and anyone may build one: every bound is checked here too.
        if (h.count < 1u || h.count > ChunkHeader.MAX_CHUNKS || h.index >= h.count ||
            body.size > ChunkHeader.BODY
        ) return null
        lastDelivered?.let { if (!newer(h.frameId, it)) return null }

        partials.values.removeIf { now - it.firstSeen > DEADLINE }

        val partial = partials[h.frameId] ?: Partial(h.count.toInt(), now, arrayOfNulls(h.count.toInt()))
        // A liar (same id, different count) or a duplicate changes nothing.
        if (partial.count != h.count.toInt() || partial.slices[h.index.toInt()] != null) return null
        partial.slices[h.index.toInt()] = body
        partial.have += 1
        if (partial.have != partial.count) {
            partials[h.frameId] = partial
            // Room for eight. The one furthest behind goes first.
            while (partials.size > MAX_PARTIALS) {
                partials.remove(partials.keys.reduce { a, b -> if (newer(a, b)) b else a })
            }
            return null
        }

        // Complete. Everything older is now history it would be wrong to show.
        partials.keys.removeIf { !newer(it, h.frameId) }
        lastDelivered = h.frameId
        val out = java.io.ByteArrayOutputStream()
        for (s in partial.slices) out.write(s!!)
        return out.toByteArray()
    }

    companion object {
        const val DEADLINE = 0.1
        const val MAX_PARTIALS = 8

        /** Frame ids are 32 bits and wrap; "newer" is the signed distance. */
        fun newer(a: UInt, b: UInt): Boolean = (a - b).toInt() > 0
    }
}

/**
 * Which counters have already been seen, over a sliding window of the most
 * recent [size]. Consulted only *after* a datagram's tag has verified: a forged
 * counter must not be able to mark a real datagram as already seen. Counter 0
 * is never valid — senders start at 1.
 */
class ReplayWindow(size: Int = 1024) {
    private val seen = BooleanArray(maxOf(1, size))
    private var highest = 0uL

    fun admit(counter: ULong): Boolean {
        if (counter == 0uL) return false
        val size = seen.size.toULong()
        if (counter > highest) {
            // The window slides forward: every slot it passes over is fresh again.
            if (counter - highest >= size) {
                seen.fill(false)
            } else {
                var c = highest + 1u
                while (c <= counter) {
                    seen[(c % size).toInt()] = false
                    c++
                }
            }
            highest = counter
        } else if (highest - counter >= size) {
            return false
        }
        val slot = (counter % size).toInt()
        if (seen[slot]) return false
        seen[slot] = true
        return true
    }
}
