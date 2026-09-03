package com.roomwire.protocol

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A port of swift/Sources/RoomWireProtocol/MediaSeal.swift.
 *
 * The media lane's envelope: ChaCha20-Poly1305 over the body, with the 17-byte
 * header as associated data so a header cannot be re-pointed at another frame
 * without the tag failing. Nonce = lane ‖ counter, twelve bytes: lane 0 is host
 * to viewer, 1 viewer to host, and the key is fresh per viewer per session.
 */
object MediaSeal {
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
     * not owed a reason.
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

    // ponytail: a fresh Cipher per datagram. The JDK refuses to re-init one
    // for encryption under a key and nonce it has seen, so sharing means a
    // pool keyed by direction; do that if profiling ever points here.
    /** The JDK names it one way, Android's Conscrypt the other. */
    private fun cipher(): Cipher = try {
        Cipher.getInstance("ChaCha20-Poly1305")
    } catch (e: GeneralSecurityException) {
        Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
    }
}
