package com.roomwire.transport

import kotlinx.coroutines.flow.StateFlow
import java.util.UUID

/**
 * The viewer's side of RoomWire, as the little of it an app has to know.
 *
 * Two implementations, one interface. [AndroidViewer] is the real thing —
 * Bonjour, mutual TLS over TCP for control, ChaCha20-Poly1305 over UDP for
 * media. [FakeViewer] is plain Kotlin with no sockets and no `android.*`, so a
 * consuming app can build and test its entire viewer — browse, join, wait for
 * approval, draw a cursor, decode frames — on a laptop with nothing else in the
 * room. Both drive the same [state] machine, which is what makes the fake worth
 * having: a controller written against one works against the other.
 *
 * Everything is a [StateFlow] rather than a callback because the states arrive
 * from a network thread and are read by a UI that may not have been listening
 * when they did.
 */
interface RoomWireViewer {
    /** Hosts seen on this network, newest snapshot. Empty until browsing. */
    val hosts: StateFlow<List<DiscoveredHost>>

    val state: StateFlow<ViewerState>

    /**
     * Begin (or resume) discovery. Idempotent, and specifically valid from
     * [ViewerState.Failed] — a failed join is not a dead viewer, and the way
     * back is to look again.
     */
    fun startBrowsing()

    /** Stop discovery. Does not touch a session that is already up. */
    fun stopBrowsing()

    /**
     * Ask [host] to admit us. [token] is this viewer's pairing identity, kept
     * across sessions so a host that has approved us once does not ask again;
     * [name] is what the presenter sees, truncated past 63 UTF-8 bytes.
     */
    fun join(host: DiscoveredHost, token: UUID, name: String)

    /**
     * Leave, from wherever we are. From [ViewerState.AwaitingApproval] this
     * cancels the join outright — the presenter's answer, whenever it comes,
     * arrives to nobody.
     */
    fun leave()
}

/** Reliable rides the control lane (TCP); unreliable takes the media lane if it fits one datagram. */
enum class Reliability { RELIABLE, UNRELIABLE }

/**
 * A host on the local network. [name] is what to show; [version] is the TXT
 * record's protocol version, and only 1 is spoken today; [serviceName] is the
 * Bonjour instance name, which is what a join actually resolves.
 */
data class DiscoveredHost(val name: String, val version: Int, val serviceName: String) {
    /**
     * Filled in by discovery once the service resolves. Not part of the value —
     * two hosts are the same host if they have the same name and service name,
     * whatever address they happen to be on this minute — and not in the
     * constructor, because this type is what an app pattern-matches on and its
     * shape is frozen.
     */
    @Transient
    var address: java.net.InetAddress? = null

    @Transient
    var port: Int = 0
}

/**
 * The far end of a live session. [id] is the host's pairing identity as a
 * string; [fingerprintHex] is SHA-256 of its certificate, lowercase hex — the
 * thing that is pinned, and the thing whose change is worth telling a user about.
 */
data class Peer(val id: String, val displayName: String, val fingerprintHex: String)

sealed interface ViewerState {
    data object Idle : ViewerState

    data object Browsing : ViewerState

    data class Connecting(val host: DiscoveredHost) : ViewerState

    /**
     * Both screens now show [code], and the presenter has to say yes. Reading
     * the same six characters off both is what rules out a third machine on the
     * same network having completed a handshake with each of them separately.
     *
     * [hostChanged] is true when this host's name is one we have joined before
     * but the certificate behind it is not the one it had then. That is what a
     * machine impersonating a host we trust looks like, and it is also what a
     * reinstalled Mac looks like, so it is shown rather than refused.
     */
    data class AwaitingApproval(
        val host: DiscoveredHost,
        val code: String,
        val hostChanged: Boolean,
    ) : ViewerState

    data class Connected(val session: Session) : ViewerState

    data class Failed(val reason: String) : ViewerState
}

/** A live session: packets in, packets out, and a way to end it. */
interface Session {
    val peer: Peer

    /** Whole `Packet` messages, byte 0 first. Called off the main thread. */
    var onPacket: ((ByteArray) -> Unit)?

    fun send(bytes: ByteArray, mode: Reliability = Reliability.RELIABLE)

    fun leave()
}
