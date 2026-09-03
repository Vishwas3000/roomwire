package com.roomwire.transport

import com.roomwire.protocol.Packet
import com.roomwire.protocol.Pairing
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.UUID

/**
 * The pairing conversation, with no sockets in it.
 *
 * The order is the security property — commit, nonce, reveal — so what is
 * asserted here is that the order is actually enforced, that the code this side
 * computes is the one the other side computes from the same four inputs, and
 * that a host contradicting itself is refused rather than believed.
 */
class HandshakeTest {

    private val token: UUID = UUID.fromString("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
    private val viewerFp = ByteArray(32) { 0x22 }
    private val hostFp = ByteArray(32) { 0x11 }
    private val hostNonce = ByteArray(16) { (0x50 + it).toByte() }
    private val mediaKey = ByteArray(32) { it.toByte() }

    private fun handshake() = Handshake(token, "Pixel", viewerFp, hostFp)

    @Test
    fun `the full sequence reaches ready, and the code matches the other end`() {
        val h = handshake()

        // hello commits to the token rather than carrying it.
        val hello = assertInstanceOf(Handshake.Step.Send::class.java, h.hello(51234))
        val decoded = assertInstanceOf(Packet.Message.Hello::class.java, Packet.decodeMessage(hello.bytes))
        assertEquals(51234.toUShort(), decoded.udpPort)
        assertEquals("Pixel", decoded.name)
        assertTrue(
            decoded.commitment.contentEquals(Pairing.commitment(token)),
            "hello must carry SHA-256 of the token, never the token",
        )

        // The host's nonce arrives; only then is the token revealed.
        val afterNonce = h.receive(Packet.encodeHostNonce(hostNonce))
        val reveal = assertInstanceOf(Handshake.Step.Send::class.java, afterNonce[0])
        assertEquals(
            token,
            assertInstanceOf(Packet.Message.Reveal::class.java, Packet.decodeMessage(reveal.bytes)).token,
        )
        val shown = assertInstanceOf(Handshake.Step.ShowCode::class.java, afterNonce[1])
        // The same four inputs on the host give the same six characters. If they
        // did not, nobody comparing two screens would learn anything.
        assertEquals(Pairing.code(hostFp, viewerFp, token, hostNonce), shown.code)
        assertEquals(6, shown.code.length)

        val ready = assertInstanceOf(
            Handshake.Step.Ready::class.java,
            h.receive(Packet.encodeWelcome(40000u, mediaKey, hostFp)).single(),
        )
        assertEquals(40000, ready.hostPort)
        assertTrue(ready.mediaKey.contentEquals(mediaKey))
        assertTrue(h.welcomed)
    }

    @Test
    fun `a welcome whose fingerprint disagrees with TLS is refused`() {
        val h = handshake()
        h.hello(1)
        h.receive(Packet.encodeHostNonce(hostNonce))

        // The fingerprint in welcome is a cross-check, never a source. A host
        // that names a different certificate to the one it just proved it holds
        // has nothing to salvage.
        val fail = assertInstanceOf(
            Handshake.Step.Fail::class.java,
            h.receive(Packet.encodeWelcome(40000u, mediaKey, ByteArray(32) { 0x99.toByte() })).single(),
        )
        assertTrue(fail.reason.contains("certificate"), "said: ${fail.reason}")
        assertTrue(!h.welcomed)
    }

    @Test
    fun `a welcome before the nonce is out of turn and refused`() {
        val h = handshake()
        h.hello(1)
        // Skipping the nonce is how a host would try to have the viewer reveal
        // nothing and still connect — there would be no code to compare.
        assertInstanceOf(
            Handshake.Step.Fail::class.java,
            h.receive(Packet.encodeWelcome(40000u, mediaKey, hostFp)).single(),
        )
    }

    @Test
    fun `a second nonce is out of turn and refused`() {
        val h = handshake()
        h.hello(1)
        h.receive(Packet.encodeHostNonce(hostNonce))
        // Re-sending the nonce would let a host pick its half again after
        // seeing the reveal, which is exactly the search the commitment closes.
        assertInstanceOf(
            Handshake.Step.Fail::class.java,
            h.receive(Packet.encodeHostNonce(ByteArray(16) { 0x77 })).single(),
        )
    }

    @Test
    fun `closing before a welcome reads as a refusal`() {
        val h = handshake()
        h.hello(1)
        h.receive(Packet.encodeHostNonce(hostNonce))
        // There is no message for a refusal — sending one would tell an
        // unwanted viewer it was seen — so a close before welcome is the signal.
        assertEquals("declined", (h.closed() as Handshake.Step.Fail).reason)
        assertEquals(null, h.closed(), "the end happens once")
    }

    @Test
    fun `closing after a welcome is a disconnect and not a refusal`() {
        val h = handshake()
        h.hello(1)
        h.receive(Packet.encodeHostNonce(hostNonce))
        h.receive(Packet.encodeWelcome(40000u, mediaKey, hostFp))
        val fail = h.closed() as Handshake.Step.Fail
        assertTrue(fail.reason != "declined", "an approved session that drops was not declined")
    }

    @Test
    fun `bytes the host could not have meant end it`() {
        val h = handshake()
        h.hello(1)
        assertInstanceOf(Handshake.Step.Fail::class.java, h.receive(byteArrayOf(99, 1, 2)).single())
    }
}
