package com.roomwire.transport

import com.roomwire.protocol.Framing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * One TLS connection carrying length-prefixed `Packet` messages.
 *
 * No Android in here either: the socket comes from an [SSLSocketFactory] the
 * caller built, so the Keystore-backed one is [Identity]'s business and this is
 * plain JVM. A framing violation — a zero length, or one past 8 MiB — closes the
 * connection rather than being skipped, because a peer that is not speaking this
 * protocol is not one to resynchronise with.
 */
class ControlLane(
    private val scope: CoroutineScope,
    private val factory: SSLSocketFactory,
    /** Records the peer's leaf certificate during the handshake. */
    private val seen: RecordingTrustManager,
) {
    /** A whole message, byte 0 first. Off the main thread. */
    var onMessage: ((ByteArray) -> Unit)? = null

    /** The handshake finished; the argument is SHA-256 of the host's certificate. */
    var onReady: ((ByteArray) -> Unit)? = null

    /** Closed, for any reason, exactly once. */
    var onClosed: (() -> Unit)? = null

    private var socket: SSLSocket? = null
    private var reader: Job? = null

    /**
     * Everything waiting to go out, drained by exactly one writer.
     *
     * It used to be a coroutine per call on [Dispatchers.IO] — a multi-threaded
     * dispatcher — all writing to one socket's output stream with nothing
     * serialising them, and that is two bugs rather than one.
     *
     * Interleaving: two writes landing on two threads can split each other's
     * length-prefixed frames, and the far end closes a connection it can no
     * longer parse. Small messages survived on luck, each fitting inside one
     * TLS record.
     *
     * Ordering, which is the one that actually bit: `hello` is sent from
     * `onReady` and `reveal` from `onMessage`, enqueued in that order but then
     * raced onto separate threads. A `reveal` that overtakes its `hello` is,
     * from the host's side, a viewer talking out of turn — `Host.handle` reads
     * it as a protocol violation and drops the session. That is an
     * intermittent, unexplainable refusal to pair, and it is a race, so it
     * comes and goes with load.
     *
     * Unlimited rather than bounded: dropping or suspending a control message
     * to save memory would be trading a rare stall for a lost handshake, and
     * this lane carries nothing bulky.
     */
    private val outbox = Channel<ByteArray>(Channel.UNLIMITED)
    private var writer: Job? = null
    @Volatile private var closed = false

    /** The address the handshake actually reached, which is where the media lane goes. */
    val remoteAddress: InetAddress? get() = socket?.inetAddress

    /**
     * Why the lane ended, when it ended badly. `connect` returns the moment the
     * coroutine is launched, so everything that can actually go wrong — a
     * refused connect, a handshake the host rejected, a certificate neither end
     * would accept — happens after the caller has moved on. Without this the
     * viewer sits in Connecting forever and there is nothing, anywhere, saying
     * why. Not called for an ordinary close.
     */
    var onFailed: ((Throwable) -> Unit)? = null

    fun connect(host: InetAddress, port: Int, timeoutMs: Int = 15_000) {
        reader = scope.launch(Dispatchers.IO) {
            val decoder = Framing.Decoder()
            try {
                val open = (factory.createSocket() as SSLSocket).apply {
                    connect(InetSocketAddress(host, port), timeoutMs)
                    // TLS 1.3 only. There is nothing older to be compatible
                    // with — both ends of this protocol ship together.
                    enabledProtocols = arrayOf("TLSv1.3")
                    startHandshake()
                }
                socket = open
                // Started before onReady, so the hello that fires from it is
                // queued behind nothing and leaves first.
                writer = scope.launch(Dispatchers.IO) {
                    try {
                        for (message in outbox) {
                            open.outputStream.write(Framing.encode(message))
                            open.outputStream.flush()
                        }
                    } catch (e: IOException) {
                        close()
                    }
                }
                val fingerprint = seen.peerFingerprint
                    ?: throw IOException("the host presented no certificate")
                onReady?.invoke(fingerprint)

                val input = open.inputStream
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val got = input.read(buffer)
                    if (got < 0) break
                    val messages = decoder.feed(buffer.copyOf(got))
                        // Not this protocol. Close, and do not guess at the rest.
                        ?: break
                    for (message in messages) onMessage?.invoke(message)
                }
            } catch (e: Throwable) {
                // Throwable, not IOException: a Keystore that will not sign and
                // a certificate that will not parse are not IOExceptions, and
                // they used to vanish into the coroutine leaving the viewer
                // stuck on a screen that says Connecting.
                if (!closed) onFailed?.invoke(e)
            } finally {
                close()
            }
        }
    }

    /**
     * Any thread. Ordered: what is handed over first goes out first, because
     * one writer drains [outbox] and nothing else touches the stream.
     */
    fun send(message: ByteArray) {
        if (closed) return
        // trySend, not send: this is called from callbacks that cannot suspend,
        // and an unlimited channel refuses only once it is closed — which is
        // exactly the case where there is nowhere to write anyway.
        outbox.trySend(message)
    }

    fun close() {
        if (closed) return
        closed = true
        val doomed = socket
        socket = null
        outbox.close()
        writer?.cancel()
        writer = null
        // Closing an SSLSocket writes a close_notify alert, so it is network
        // I/O and cannot run on the caller's thread: leave() arrives straight
        // from a tap on Leave or Cancel, which is the main thread, and
        // StrictMode kills the process for it.
        //
        // A plain thread rather than scope.launch, because close() is usually
        // the last thing that happens before that scope is cancelled, and a
        // coroutine that never runs leaves the socket open and the reader
        // blocked on it forever.
        if (doomed != null) {
            Thread({
                try {
                    doomed.close()
                } catch (e: IOException) {
                    // Already gone.
                }
            }, "roomwire-control-close").start()
        }
        onClosed?.invoke()
    }
}

/**
 * Accepts every certificate and records the leaf's fingerprint.
 *
 * That is not a weakened check but a different one. There is no certificate
 * authority anywhere in RoomWire and there is not meant to be: two devices in a
 * room have no third party to appeal to, so nothing about a self-signed
 * certificate can be verified during a handshake and the decision moves to
 * where the evidence is. The viewer compares this fingerprint against what it
 * saw last time, and the pairing code covers the first time.
 */
class RecordingTrustManager : javax.net.ssl.X509TrustManager {
    @Volatile
    var peerFingerprint: ByteArray? = null
        private set

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        record(chain)
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        record(chain)
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    private fun record(chain: Array<out X509Certificate>?) {
        val leaf = chain?.firstOrNull() ?: return
        peerFingerprint = java.security.MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
    }
}

/**
 * Hands the Keystore's alias and key to the TLS stack for client
 * authentication. The key never leaves the Keystore — this passes a handle to
 * it, and the signing happens in there.
 */
class AliasKeyManager(
    private val alias: String,
    private val chain: Array<X509Certificate>,
    private val key: java.security.PrivateKey,
) : javax.net.ssl.X509ExtendedKeyManager() {
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out java.security.Principal>?, socket: Socket?) = alias
    override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: Socket?) = alias
    override fun getCertificateChain(alias: String?): Array<X509Certificate> = chain
    override fun getPrivateKey(alias: String?): java.security.PrivateKey = key
    override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?) = arrayOf(alias)
    override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?) = arrayOf(alias)
}
