package com.roomwire.protocol

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A port of swift/Sources/RoomWireProtocol/BulkSeal.swift, held to the Swift
 * side by protocol/vectors.txt.
 *
 * The bulk lane's envelope: one AEAD frame per write on an ordered stream. The
 * media lane's envelope is next door and this is not it, because both of the
 * obvious reuses are wrong — [ChunkHeader] describes a datagram carved out of a
 * video frame, and [Framing]'s decoder shifts its whole buffer per frame and
 * caps at 8 MiB, which here would be 8 MiB of unverified attacker-chosen data
 * held before anything authenticates it.
 *
 * Lanes 2 and 3, so a media key arriving here by mistake still cannot collide
 * in nonce space. The counter is not on the wire: TCP delivers in order or not
 * at all, so the receiver knows what it must be and checks equality, which
 * catches reordering, duplication, loss and splicing in one comparison.
 * The length is the associated data, so tampering is caught on the frame it
 * happened to.
 *
 * Truncation is not defended here and cannot be — see [Transfer].
 */
object Bulk {
    /**
     * The most file data one frame carries. Large on purpose, and on this
     * platform especially: JCE allocates and looks up a provider per `Cipher`,
     * so at datagram sizes the lookups cost more than the encryption.
     */
    const val CHUNK = 262_144

    /** Room for a message's own fields on top of a full chunk. */
    const val MAX_PLAINTEXT = CHUNK + 64
    const val TAG = 16

    /** What the length prefix says: plaintext plus tag. */
    const val MAX_BODY = MAX_PLAINTEXT + TAG

    /** One byte of plaintext — a `bye` — plus the tag. */
    const val MIN_BODY = 1 + TAG

    /**
     * Which direction this end seals on. Never a parameter a caller passes:
     * two ends sealing the same lane under one key is the whole disaster.
     */
    enum class Lane(val raw: UInt) {
        HOST_TO_VIEWER(2u),
        VIEWER_TO_HOST(3u);

        val opposite: Lane get() = if (this == HOST_TO_VIEWER) VIEWER_TO_HOST else HOST_TO_VIEWER
    }

    /** The outbound half. Owns the counter; returns a frame, length included. */
    class Sealer(key: ByteArray, private val lane: Lane) {
        private val spec = SecretKeySpec(key, "ChaCha20")
        // One Cipher for the life of this direction. The JDK only refuses to
        // re-init under a key *and nonce* it has already seen, and the counter
        // never repeats, so re-initing per frame is allowed — and it is the
        // difference between four provider lookups per megabyte and seven
        // hundred and fifty.
        private val cipher = cipher()
        private var counter = 0UL

        @Synchronized
        fun seal(plaintext: ByteArray): ByteArray {
            require(plaintext.isNotEmpty() && plaintext.size <= MAX_PLAINTEXT) {
                "a bulk frame is 1..$MAX_PLAINTEXT bytes of plaintext"
            }
            counter += 1UL
            check(counter != 0UL) { "the bulk lane's counter wrapped" }

            val head = ByteArray(4)
            writeBE32(head, 0, (plaintext.size + TAG).toUInt())
            cipher.init(
                Cipher.ENCRYPT_MODE, spec,
                IvParameterSpec(MediaSeal.nonce(lane.raw, counter)),
            )
            cipher.updateAAD(head)
            return head + cipher.doFinal(plaintext)
        }
    }

    /**
     * The inbound half. null is always fatal to the connection — there is no
     * frame this can refuse and still be talking to the same peer.
     */
    class Opener(key: ByteArray, private val lane: Lane) {
        private val spec = SecretKeySpec(key, "ChaCha20")
        private val cipher = cipher()
        private var expected = 0UL

        /** [frame] is a whole frame from [Decoder], length prefix included. */
        @Synchronized
        fun open(frame: ByteArray): ByteArray? {
            if (frame.size < 4 + MIN_BODY || frame.size > 4 + MAX_BODY) return null
            // The length must describe exactly what arrived. A decoder that
            // agrees is not enough: this is the value being authenticated, so
            // it is checked where it is used.
            if (readBE32(frame, 0).toInt() != frame.size - 4) return null

            expected += 1UL
            return try {
                cipher.init(
                    Cipher.DECRYPT_MODE, spec,
                    IvParameterSpec(MediaSeal.nonce(lane.raw, expected)),
                )
                cipher.updateAAD(frame, 0, 4)
                cipher.doFinal(frame, 4, frame.size - 4)
            } catch (e: GeneralSecurityException) {
                null
            }
        }
    }

    /**
     * Whole frames out of whatever arrived, without copying the tail back to
     * the front on every one. [Framing.Decoder] keeps its buffer packed by
     * shifting; here the read cursor moves and the buffer is compacted only
     * once it is spent.
     */
    class Decoder {
        private var buffer = ByteArray(64 * 1024)
        private var end = 0
        private var read = 0

        /**
         * null means the stream is not speaking this protocol — a length that
         * could not be one of ours — and the only answer is to close it.
         */
        fun feed(bytes: ByteArray, count: Int = bytes.size): List<ByteArray>? {
            if (end + count > buffer.size) {
                var size = buffer.size
                while (size < end + count) size *= 2
                buffer = buffer.copyOf(size)
            }
            System.arraycopy(bytes, 0, buffer, end, count)
            end += count

            val out = ArrayList<ByteArray>()
            while (end - read >= 4) {
                val length = readBE32(buffer, read).toInt()
                if (length < MIN_BODY || length > MAX_BODY) return null
                if (end - read < 4 + length) break
                out.add(buffer.copyOfRange(read, read + 4 + length))
                read += 4 + length
            }
            if (read == end) {
                read = 0
                end = 0
            } else if (read >= 1 shl 20) {
                // Only once the wasted front is worth a copy.
                System.arraycopy(buffer, read, buffer, 0, end - read)
                end -= read
                read = 0
            }
            return out
        }
    }

    /** The JDK names it one way, Android's Conscrypt the other. */
    private fun cipher(): Cipher = try {
        Cipher.getInstance("ChaCha20-Poly1305")
    } catch (e: GeneralSecurityException) {
        Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
    }

    private fun writeBE32(out: ByteArray, at: Int, v: UInt) {
        out[at] = (v shr 24).toByte()
        out[at + 1] = (v shr 16).toByte()
        out[at + 2] = (v shr 8).toByte()
        out[at + 3] = v.toByte()
    }

    private fun readBE32(b: ByteArray, at: Int): UInt =
        (b[at].toUInt() and 0xFFu shl 24) or
            (b[at + 1].toUInt() and 0xFFu shl 16) or
            (b[at + 2].toUInt() and 0xFFu shl 8) or
            (b[at + 3].toUInt() and 0xFFu)
}
