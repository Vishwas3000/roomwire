package com.roomwire.protocol

/**
 * A port of swift/Sources/RoomWireProtocol/Transfer.swift, held to the Swift
 * side by protocol/vectors.txt.
 *
 * What moves over the bulk lane, as bytes. No sockets and no files here — this
 * is the format and the rules, so both ends can be held to the same vectors and
 * neither has to be running to test it.
 *
 * A message space of its own, one byte wide, entirely separate from [Packet].
 * That is the load-bearing decision: an unknown Packet id drops the whole
 * session on both ends, so every message that lives here is one that can never
 * cost a version handshake.
 */
object Transfer {
    /**
     * How much of a file the offer's hash covers. Whole-file hashing before the
     * first byte moves would stall a large send for seconds; this is instant,
     * and the whole-file hash in [Frame.Done] is computed while streaming.
     */
    const val HEAD_WINDOW = 65_536
    const val MAX_NAME = 1024
    const val MAX_MIME = 255

    enum class Reject(val raw: UByte) {
        DECLINED(0u), NO_SPACE(1u), TOO_BIG(2u), BUSY(3u), GONE(4u);

        companion object {
            fun of(raw: UByte): Reject? = entries.firstOrNull { it.raw == raw }
        }
    }

    data class Offer(
        val id: UShort,
        val size: ULong,
        /**
         * The source's modification time. Part of what identifies a partial on
         * resume, so a changed original is not silently stitched onto the bytes
         * of the old one.
         */
        val mtimeMs: ULong,
        /** SHA-256 of the first [HEAD_WINDOW] bytes, or of the whole file if smaller. */
        val headHash: ByteArray,
        /** Paste it rather than saving it. */
        val isClipboard: Boolean,
        val name: String,
        val mime: String,
    ) {
        // ByteArray in a data class: equals/hashCode must be written out or two
        // identical offers compare unequal, which the vectors would catch and
        // nothing else would.
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Offer) return false
            return id == other.id && size == other.size && mtimeMs == other.mtimeMs &&
                headHash.contentEquals(other.headHash) && isClipboard == other.isClipboard &&
                name == other.name && mime == other.mime
        }

        override fun hashCode(): Int {
            var out = id.hashCode()
            out = 31 * out + size.hashCode()
            out = 31 * out + mtimeMs.hashCode()
            out = 31 * out + headHash.contentHashCode()
            out = 31 * out + isClipboard.hashCode()
            out = 31 * out + name.hashCode()
            out = 31 * out + mime.hashCode()
            return out
        }
    }

    sealed interface Frame {
        data class Offered(val offer: Transfer.Offer) : Frame

        /**
         * The receiver chooses where to resume. The offset appears exactly
         * once, here, and never on [Data] — so no sender can seek a file handle
         * it does not own.
         */
        data class Accept(val id: UShort, val offset: ULong) : Frame

        data class Rejected(val id: UShort, val reason: Reject) : Frame

        /** Position is implicit: sequential from what [Accept] asked for. */
        class Data(val id: UShort, val bytes: ByteArray) : Frame {
            override fun equals(other: Any?): Boolean =
                other is Data && id == other.id && bytes.contentEquals(other.bytes)

            override fun hashCode(): Int = 31 * id.hashCode() + bytes.contentHashCode()
        }

        /**
         * The whole-file hash. A transfer is complete when this arrives and the
         * hash matches, and at no other time — it is the only thing separating
         * "the sender finished" from "somebody cut the connection".
         */
        class Done(val id: UShort, val sha256: ByteArray) : Frame {
            override fun equals(other: Any?): Boolean =
                other is Done && id == other.id && sha256.contentEquals(other.sha256)

            override fun hashCode(): Int = 31 * id.hashCode() + sha256.contentHashCode()
        }

        data class Cancel(val id: UShort, val reason: Reject) : Frame

        /** An orderly close, so its absence means "resume", never "done". */
        data object Bye : Frame
    }

    // MARK: - Encoding

    fun encode(frame: Frame): ByteArray = when (frame) {
        is Frame.Offered -> {
            val o = frame.offer
            val name = o.name.toByteArray(Charsets.UTF_8)
            val mime = o.mime.toByteArray(Charsets.UTF_8)
            require(name.size in 1..MAX_NAME) { "a name is 1..$MAX_NAME bytes" }
            require(mime.size <= MAX_MIME) { "a mime type is at most $MAX_MIME bytes" }
            require(o.headHash.size == 32) { "a head hash is 32 bytes" }
            val out = ArrayList<Byte>(54 + name.size + 2 + mime.size)
            out.add(1)
            out.appendBE16(o.id)
            out.appendBE64(o.size)
            out.appendBE64(o.mtimeMs)
            o.headHash.forEach { out.add(it) }
            out.add(if (o.isClipboard) 1 else 0)
            out.appendBE16(name.size.toUShort())
            name.forEach { out.add(it) }
            out.appendBE16(mime.size.toUShort())
            mime.forEach { out.add(it) }
            out.toByteArray()
        }
        is Frame.Accept -> {
            val out = ArrayList<Byte>(11)
            out.add(2); out.appendBE16(frame.id); out.appendBE64(frame.offset)
            out.toByteArray()
        }
        is Frame.Rejected -> {
            val out = ArrayList<Byte>(4)
            out.add(3); out.appendBE16(frame.id); out.add(frame.reason.raw.toByte())
            out.toByteArray()
        }
        is Frame.Data -> {
            require(frame.bytes.isNotEmpty() && frame.bytes.size <= Bulk.CHUNK) {
                "a data frame is 1..${Bulk.CHUNK} bytes"
            }
            val out = ByteArray(3 + frame.bytes.size)
            out[0] = 4
            out[1] = (frame.id.toInt() shr 8).toByte()
            out[2] = frame.id.toByte()
            System.arraycopy(frame.bytes, 0, out, 3, frame.bytes.size)
            out
        }
        is Frame.Done -> {
            require(frame.sha256.size == 32) { "a file hash is 32 bytes" }
            val out = ArrayList<Byte>(35)
            out.add(5); out.appendBE16(frame.id); frame.sha256.forEach { out.add(it) }
            out.toByteArray()
        }
        is Frame.Cancel -> {
            val out = ArrayList<Byte>(4)
            out.add(6); out.appendBE16(frame.id); out.add(frame.reason.raw.toByte())
            out.toByteArray()
        }
        Frame.Bye -> byteArrayOf(7)
    }

    // MARK: - Decoding

    /**
     * Strict, like everything else on this wire: exact lengths, real UTF-8,
     * known enum cases. null closes the connection.
     */
    fun decode(plaintext: ByteArray): Frame? {
        if (plaintext.isEmpty()) return null
        val b = plaintext
        return when (b[0].toInt() and 0xFF) {
            1 -> {
                if (b.size < 54) return null
                if ((b[51].toInt() and 0xFF) > 1) return null
                val nameLen = be16(b, 52).toInt()
                if (nameLen !in 1..MAX_NAME || b.size < 54 + nameLen + 2) return null
                val name = Packet.strictUtf8(b, 54, 54 + nameLen) ?: return null
                val mimeAt = 54 + nameLen
                val mimeLen = be16(b, mimeAt).toInt()
                if (mimeLen > MAX_MIME || b.size != mimeAt + 2 + mimeLen) return null
                val mime = Packet.strictUtf8(b, mimeAt + 2, b.size) ?: return null
                Frame.Offered(
                    Offer(
                        id = be16(b, 1),
                        size = be64(b, 3),
                        mtimeMs = be64(b, 11),
                        headHash = b.copyOfRange(19, 51),
                        isClipboard = b[51].toInt() == 1,
                        name = name,
                        mime = mime,
                    ),
                )
            }
            2 -> if (b.size == 11) Frame.Accept(be16(b, 1), be64(b, 3)) else null
            3 -> {
                if (b.size != 4) return null
                val reason = Reject.of((b[3].toInt() and 0xFF).toUByte()) ?: return null
                Frame.Rejected(be16(b, 1), reason)
            }
            4 -> if (b.size > 3 && b.size <= 3 + Bulk.CHUNK) {
                Frame.Data(be16(b, 1), b.copyOfRange(3, b.size))
            } else {
                null
            }
            5 -> if (b.size == 35) Frame.Done(be16(b, 1), b.copyOfRange(3, 35)) else null
            6 -> {
                if (b.size != 4) return null
                val reason = Reject.of((b[3].toInt() and 0xFF).toUByte()) ?: return null
                Frame.Cancel(be16(b, 1), reason)
            }
            7 -> if (b.size == 1) Frame.Bye else null
            else -> null
        }
    }

    // MARK: - Names

    /**
     * A name safe to join onto a directory.
     *
     * [Offer.name] is chosen by the far end, so it is the one field in this
     * format an attacker fully controls, and the only thing standing between it
     * and somebody else's filesystem. Everything before the last separator
     * goes, both separators count, control characters go, and the result is
     * never empty, "." or ".." — the three values that make a join mean
     * something other than "a file in this directory".
     */
    fun safeName(raw: String): String {
        val cut = raw.split('/', '\\').lastOrNull() ?: ""
        val clean = cut.filter { !it.isISOControl() && it != ':' }.trim()
        if (clean.isEmpty() || clean == "." || clean == "..") return "received"
        return clean.take(200)
    }

    // MARK: - Readers

    private fun be16(b: ByteArray, at: Int): UShort =
        (((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)).toUShort()

    private fun be64(b: ByteArray, at: Int): ULong {
        var v = 0UL
        for (i in 0 until 8) v = (v shl 8) or (b[at + i].toULong() and 0xFFuL)
        return v
    }

    private fun ArrayList<Byte>.appendBE16(v: UShort) {
        add((v.toInt() shr 8).toByte())
        add(v.toByte())
    }

    private fun ArrayList<Byte>.appendBE64(v: ULong) {
        for (shift in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) add((v shr shift).toByte())
    }
}
