package com.roomwire.protocol

import java.security.MessageDigest
import java.util.UUID

/**
 * A port of swift/Sources/RoomWireProtocol/Pairing.swift.
 *
 * The six characters both screens show while a new viewer waits to be
 * approved: SHA-256(hostFp ‖ viewerFp ‖ token ‖ hostNonce) in RFC 4648 base32
 * (A–Z, 2–7), the first six characters. Thirty bits, and no glyph that reads
 * two ways.
 *
 * **Guessing it is not the attack, and it is worth spelling out what is.** A
 * machine in the middle holds two TLS connections: one to the Mac, where it
 * plays the viewer, and one to the phone, where it plays the host. It does not
 * have to guess either code — it has to make the two codes *equal*, and if it
 * can choose its own contribution to each after seeing everything else, it can
 * grind for a collision. Both halves are then pure SHA-256 with no certificates
 * needed: on the Mac leg it varies the nonce it sends, and on the phone leg it
 * re-mints its own self-signed certificate, which trust-on-first-use obliges
 * the phone to accept. Two independently steerable 30-bit values meet in the
 * middle at about 2^15 tries each — which measured at 0.05 seconds on one core,
 * offline, with both screens then showing the same six characters.
 *
 * So neither side is allowed to choose last. The viewer commits first, in
 * hello, to SHA-256 of a token it has not sent; the host then sends its nonce;
 * only then does the viewer reveal the token, and the host closes the
 * connection if it does not hash to what was committed. Neither contribution
 * can be chosen in response to the other, which leaves an attacker one 2^-30
 * shot per attempt instead of a search — and six characters is then genuinely
 * enough.
 *
 * A longer code was the obvious alternative and it does not work: resisting a
 * two-sided birthday search needs double the bits, so twelve characters buys
 * 2^30 per side, which is GPU-seconds, and nobody compares twelve characters
 * off two screens. Committing is what short authenticated strings do instead,
 * and it costs two small messages.
 */
object Pairing {
    fun code(
        hostFingerprint: ByteArray,
        viewerFingerprint: ByteArray,
        token: UUID,
        hostNonce: ByteArray,
    ): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(hostFingerprint)
        md.update(viewerFingerprint)
        md.update(uuidBytes(token))
        md.update(hostNonce)
        return base32(md.digest()).take(6)
    }

    /** What hello carries in place of the token: SHA-256 of it, 32 bytes. */
    fun commitment(token: UUID): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(uuidBytes(token))

    /**
     * Whether a revealed token is the one that was committed to. The host
     * closes the connection when this is false: a viewer that cannot produce
     * the preimage of its own commitment is either broken or steering.
     */
    fun opens(commitment: ByteArray, token: UUID): Boolean =
        commitment.size == 32 && commitment.contentEquals(commitment(token))

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
            // Only when something was actually consumed. Re-slicing on every
            // feed is what turns an 8 MiB frame arriving in kilobyte reads into
            // tens of gigabytes of copying.
            if (o > 0) buffer = buffer.copyOfRange(o, buffer.size)
            return out
        }
    }
}
