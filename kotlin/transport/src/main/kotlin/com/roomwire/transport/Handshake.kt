package com.roomwire.transport

import com.roomwire.protocol.Packet
import com.roomwire.protocol.Pairing
import java.util.UUID

/**
 * The viewer's half of the pairing conversation, with no socket in it.
 *
 * The sequence is the security property, so it is worth having somewhere it can
 * be read in one screen and tested without a phone: commit, then the host's
 * nonce, then reveal, then welcome. The viewer commits to a token it has not
 * sent; the host answers with sixteen bytes of its own; only then is the token
 * revealed. Neither side can choose its contribution after seeing the other's,
 * which is what makes six characters worth 2^-30 per attempt instead of a
 * collision search — see [Pairing.code].
 *
 * Everything this needs is passed in, and everything it decides comes back as a
 * [Step]. The transport does the sockets.
 */
internal class Handshake(
    private val token: UUID,
    private val name: String,
    private val viewerFingerprint: ByteArray,
    /** From the TLS handshake, never from `welcome`. */
    private val hostFingerprint: ByteArray,
) {
    sealed interface Step {
        /** Put these bytes on the control lane. */
        class Send(val bytes: ByteArray) : Step

        /** Both screens show this now, and the presenter is deciding. */
        data class ShowCode(val code: String) : Step

        /** Approved: open the media lane with this key, to this port. */
        class Ready(val mediaKey: ByteArray, val hostPort: Int) : Step

        /** Over. Nothing more will happen on this connection. */
        data class Fail(val reason: String) : Step
    }

    private enum class Stage { NEW, SAID_HELLO, REVEALED, WELCOMED, OVER }

    private var stage = Stage.NEW

    /** The first frame, once the UDP socket has a port to advertise. */
    fun hello(udpPort: Int): Step {
        check(stage == Stage.NEW) { "hello is the first thing said" }
        stage = Stage.SAID_HELLO
        return Step.Send(Packet.encodeHello(Pairing.commitment(token), udpPort.toUShort(), name))
    }

    fun receive(message: ByteArray): List<Step> {
        if (stage == Stage.OVER) return emptyList()
        return when (val decoded = Packet.decodeMessage(message)) {
            is Packet.Message.HostNonce -> {
                if (stage != Stage.SAID_HELLO) return over("the host sent its nonce out of turn")
                stage = Stage.REVEALED
                listOf(
                    // Revealing only now is the whole point: the host's half is
                    // already fixed, so neither side chose last.
                    Step.Send(Packet.encodeReveal(token)),
                    Step.ShowCode(
                        Pairing.code(hostFingerprint, viewerFingerprint, token, decoded.nonce),
                    ),
                )
            }

            is Packet.Message.Welcome -> {
                if (stage != Stage.REVEALED) return over("the host welcomed us out of turn")
                // The fingerprint here is a cross-check and never a source: the
                // one that counts came out of the TLS handshake, and the viewer
                // needed it before this message arrived in order to show the
                // code at all. A host contradicting itself has nothing to
                // salvage.
                if (!decoded.hostFingerprint.contentEquals(hostFingerprint)) {
                    return over("the host's certificate did not match its welcome")
                }
                stage = Stage.WELCOMED
                listOf(Step.Ready(decoded.mediaKey, decoded.udpPort.toInt()))
            }

            null -> over("the host sent something we could not read")

            else -> emptyList()   // anything else before the session is up is not ours to act on
        }
    }

    /**
     * The control lane closed. Before a welcome that is what a presenter saying
     * no looks like from here — there is no message for a refusal, because
     * sending one would tell an unwanted viewer that it was seen.
     */
    fun closed(): Step? {
        if (stage == Stage.OVER) return null
        val wasWelcomed = stage == Stage.WELCOMED
        stage = Stage.OVER
        return if (wasWelcomed) Step.Fail("the host closed the connection") else Step.Fail("declined")
    }

    /** True once the session is past approval, so the caller knows what a close means. */
    val welcomed: Boolean get() = stage == Stage.WELCOMED

    private fun over(reason: String): List<Step> {
        stage = Stage.OVER
        return listOf(Step.Fail(reason))
    }
}
