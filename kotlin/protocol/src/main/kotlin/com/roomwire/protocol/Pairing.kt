package com.roomwire.protocol

import java.security.MessageDigest
import java.util.UUID

/**
 * A port of swift/Sources/RoomWireProtocol/Pairing.swift.
 *
 * The six characters both screens show while a new viewer waits to be
 * approved: SHA-256(hostFp ‖ viewerFp ‖ token) in RFC 4648 base32 (A–Z, 2–7),
 * the first six characters. Thirty bits, no glyph that reads two ways, and
 * nothing worth guessing at — there is no secret behind it to lock anyone out of.
 */
object Pairing {
    fun code(hostFingerprint: ByteArray, viewerFingerprint: ByteArray, token: UUID): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(hostFingerprint)
        md.update(viewerFingerprint)
        md.update(uuidBytes(token))
        return base32(md.digest()).take(6)
    }

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** RFC 4648 without padding: five bits at a time, high bits first. */
    internal fun base32(bytes: ByteArray): String {
        val out = StringBuilder()
        var acc = 0
        var bits = 0
        for (b in bytes) {
            acc = (acc shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(ALPHABET[(acc shr bits) and 31])
            }
            acc = acc and ((1 shl bits) - 1)
        }
        if (bits > 0) out.append(ALPHABET[(acc shl (5 - bits)) and 31])
        return out.toString()
    }
}

/**
 * The control lane's frames: `[length u32][bytes]`, length 1…8 MiB. TCP is a
 * byte stream; this is what makes it messages again. The cap is what stops a
 * peer claiming a 4 GB frame and being handed the buffer for it.
 */
object Framing {
    const val MAX_LENGTH = 8_388_608

    /** An empty message has no frame — the far end reads a zero length as a broken stream. */
    fun encode(message: ByteArray): ByteArray {
        require(message.isNotEmpty() && message.size <= MAX_LENGTH) { "a frame is 1…8 MiB" }
        val out = ArrayList<Byte>(4)
        out.appendBE(message.size.toUInt())
        return out.toByteArray() + message
    }

    /**
     * Feed it whatever arrived; get back every complete frame, in order. null
     * means the stream is not speaking this protocol — a zero or oversized
     * length — and the only right answer is to close it.
     */
    class Decoder {
        private var buffer = ByteArray(0)

        fun feed(bytes: ByteArray): List<ByteArray>? {
            buffer += bytes
            val out = ArrayList<ByteArray>()
            var o = 0
            while (buffer.size - o >= 4) {
                val length = buffer.be32(o).toLong()
                if (length < 1 || length > MAX_LENGTH) return null
                if (buffer.size - o < 4 + length) break
                out.add(buffer.copyOfRange(o + 4, o + 4 + length.toInt()))
                o += 4 + length.toInt()
            }
            // ponytail: O(n) copy per feed; a ring buffer if the control lane
            // ever carries more than a few frames a second.
            buffer = buffer.copyOfRange(o, buffer.size)
            return out
        }
    }
}
