package com.roomwire.protocol

import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A port of swift/Sources/RoomWireProtocol/MediaSeal.swift.
 *
 * The media lane's envelope: ChaCha20-Poly1305 over the body, with the 17-byte
 * header as associated data so a header cannot be re-pointed at another frame
 * without the tag failing.
 *
 * Nonce = lane ‖ counter, twelve bytes. Lane 0 is host to viewer, 1 viewer to
 * host, so the two directions never share a nonce under one key; the counter
 * never repeats within a direction; and the key is minted fresh in every
 * welcome — **per session, not per viewer** — so a reconnecting viewer never
 * restarts a counter under a key that has already used it.
 *
 * Use [Sealer] and [Opener] rather than the two primitives below. They exist
 * because every way of getting this wrong is a way of getting it *quietly*
 * wrong, and all of them are one plausible line of transport code:
 *
 *  - Both ends sealing lane 0, which one shared `val lane = 0u` does. Two
 *    directions, one keystream, one counter sequence each: the two streams XOR
 *    to plaintext. [Role] is why the lane is derived and never passed.
 *  - Two send paths sharing a counter without a lock. A ping from a heartbeat
 *    and video off the encoder both sit on the sending lane and both need the
 *    next counter; if they can read the same one, that is the same nonce twice.
 *    The sealer allocates it atomically, and callers never see it.
 *  - Consulting the replay window before the tag verifies. An off-path attacker
 *    then sprays forged datagrams, fills all 1024 slots, and locks out the real
 *    ones. The opener owns its window and reaches it only after [open] has
 *    succeeded, so the order cannot be written the wrong way round.
 */
object MediaSeal {
    /**
     * Which end of the lane this is. Both lane numbers follow from it, which is
     * the point: a lane is never a parameter anybody can pass wrongly.
     */
    enum class Role {
        HOST, VIEWER;

        /** The lane this end seals on. Host to viewer is 0. */
        val sendingLane: UInt get() = if (this == HOST) 0u else 1u

        /** The lane this end expects to receive on. */
        val receivingLane: UInt get() = if (this == HOST) 1u else 0u
    }

    /**
     * The outbound half: owns the counter, hands back a finished datagram.
     * Safe to call from any thread — a heartbeat and an encoder both do.
     */
    class Sealer(private val key: ByteArray, role: Role) {
        private val lane = role.sendingLane
        private val counter = java.util.concurrent.atomic.AtomicLong(0)

        /**
         * [body] must be at most [ChunkHeader.BODY] bytes; slicing a frame to
         * that size is [Chunker.slice]'s job.
         */
        fun seal(
            kind: ChunkHeader.Kind,
            body: ByteArray,
            frameId: UInt = 0u,
            index: UShort = 0u,
            count: UShort = 1u,
        ): ByteArray {
            require(body.size <= ChunkHeader.BODY) { "a body past the datagram ceiling" }
            val next = counter.incrementAndGet().toULong()
            // A u64 at sixty frames a second is about sixty-five thousand
            // years, so this cannot happen — and if it does, reusing a nonce is
            // not the way to carry on.
            check(next != 0uL) { "the media lane's counter wrapped" }
            return seal(ChunkHeader.Fields(kind, next, frameId, index, count), body, key, lane)
        }
    }

    /**
     * The inbound half: bounds, then the tag, then — and only then — the replay
     * window. One per receiving connection, one thread.
     */
    class Opener(key: ByteArray, role: Role, window: Int = 1024) {
        private val lane = role.receivingLane
        private val seen = ReplayWindow(window)
        private val spec = SecretKeySpec(key, "ChaCha20")
        // One Cipher kept across datagrams, as BulkSeal.Opener does. The
        // provider lookup in Cipher.getInstance was being paid on every
        // datagram — at 180 a second on a phone whose access point delivers
        // them seventy at a time, that lookup was the drain rate of the
        // receive loop.
        //
        // `var`, because of one thing BulkSeal never meets: the JDK refuses to
        // re-init a ChaCha20-Poly1305 Cipher under the key *and nonce* it last
        // used, in either direction. BulkSeal's counter is its own and never
        // repeats. This lane's counter is read off the datagram, so a forged
        // or replayed one carrying counter N, followed by the genuine N, would
        // have the genuine one refused — the transcripts' wrongLane scenario
        // is exactly that sequence. On that path, and only that path, the
        // instance is replaced.
        private var cipher = cipher()

        /**
         * null for anything that does not open or has been seen before. The
         * order is the contract the transcripts pin: bounds, then the header,
         * then the tag, and the replay window last — so a forged counter costs
         * an attacker nothing and buys them nothing.
         */
        @Synchronized
        fun open(datagram: ByteArray): Pair<ChunkHeader.Fields, ByteArray>? {
            if (datagram.size < ChunkHeader.SIZE + ChunkHeader.TAG || datagram.size > ChunkHeader.DATAGRAM_MAX) return null
            val h = ChunkHeader.decode(datagram) ?: return null
            val iv = IvParameterSpec(nonce(lane, h.counter))
            val body = try {
                try {
                    cipher.init(Cipher.DECRYPT_MODE, spec, iv)
                } catch (e: InvalidKeyException) {
                    // The key is ours and always valid, so this can only be the
                    // repeated-nonce refusal described above.
                    cipher = cipher()
                    cipher.init(Cipher.DECRYPT_MODE, spec, iv)
                }
                cipher.updateAAD(datagram, 0, ChunkHeader.SIZE)
                cipher.doFinal(datagram, ChunkHeader.SIZE, datagram.size - ChunkHeader.SIZE)
            } catch (e: GeneralSecurityException) {
                return null
            }
            if (!seen.admit(h.counter)) return null
            return h to body
        }
    }
    fun nonce(lane: UInt, counter: ULong): ByteArray {
        val out = ArrayList<Byte>(12)
        out.appendBE(lane)
        out.appendBE64(counter)
        return out.toByteArray()
    }

    fun seal(h: ChunkHeader.Fields, body: ByteArray, key: ByteArray, lane: UInt): ByteArray {
        val header = ChunkHeader.encode(h)
        val cipher = cipher()
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(lane, h.counter)))
        cipher.updateAAD(header)
        // JCE writes the tag after the ciphertext, which is the wire order.
        return header + cipher.doFinal(body)
    }

    /**
     * null for anything that does not open: too short, too long, a header we
     * refuse, or a tag that does not match. Nothing says which; a datagram is
     * not owed a reason. This does *not* consult a replay window: [Opener]
     * does, after.
     */
    fun open(datagram: ByteArray, key: ByteArray, lane: UInt): Pair<ChunkHeader.Fields, ByteArray>? {
        if (datagram.size < ChunkHeader.SIZE + ChunkHeader.TAG || datagram.size > ChunkHeader.DATAGRAM_MAX) return null
        val h = ChunkHeader.decode(datagram) ?: return null
        return try {
            val cipher = cipher()
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce(lane, h.counter)))
            cipher.updateAAD(datagram, 0, ChunkHeader.SIZE)
            h to cipher.doFinal(datagram, ChunkHeader.SIZE, datagram.size - ChunkHeader.SIZE)
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    // The static seal/open below build a fresh Cipher per call. They serve the
    // vectors and the tests, where one call is one call; the live receive path
    // is Opener above, which keeps its own.
    /** The JDK names it one way, Android's Conscrypt the other. */
    private fun cipher(): Cipher = try {
        Cipher.getInstance("ChaCha20-Poly1305")
    } catch (e: GeneralSecurityException) {
        Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
    }
}
