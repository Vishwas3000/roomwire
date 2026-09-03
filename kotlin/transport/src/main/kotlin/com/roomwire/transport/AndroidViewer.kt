package com.roomwire.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import com.roomwire.protocol.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.net.InetAddress
import java.util.UUID

/**
 * The real viewer: Bonjour over [NsdManager], pairing over mutual TLS, and the
 * two lanes.
 *
 * Every state change is written from a coroutine and never synchronously from
 * the caller's thread, so [state] trails a call by a dispatch — exactly as
 * [FakeViewer] does. That is deliberate and it matters: an app's UI collects
 * this flow, so it trails by a dispatch anyway, and a real viewer that emitted
 * synchronously would let tests pass against the fake and fail on a phone.
 */
class AndroidViewer(
    private val context: Context,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) : RoomWireViewer {

    private val _hosts = MutableStateFlow<List<DiscoveredHost>>(emptyList())
    override val hosts: StateFlow<List<DiscoveredHost>> = _hosts.asStateFlow()

    private val _state = MutableStateFlow<ViewerState>(ViewerState.Idle)
    override val state: StateFlow<ViewerState> = _state.asStateFlow()

    private val nsd by lazy { context.getSystemService(Context.NSD_SERVICE) as NsdManager }
    private val knownHosts by lazy { KnownHosts(context) }
    private val identity by lazy { Identity.load() }

    private var multicast: WifiManager.MulticastLock? = null
    private var discovery: NsdManager.DiscoveryListener? = null
    private var joining: Job? = null
    private var session: LiveSession? = null

    /** Everything found so far, by service name, so a resolve can fill one in. */
    private val seen = LinkedHashMap<String, DiscoveredHost>()

    override fun startBrowsing() {
        if (state.value is ViewerState.Connected) return
        cancelJoin()
        scope.launch { _state.value = ViewerState.Browsing }
        if (discovery != null) return

        // Multicast is off by default to save the radio, and DNS-SD is
        // multicast. Without this the browse finds nothing at all and says so
        // in no way whatsoever.
        multicast = (context.getSystemService(Context.WIFI_SERVICE) as WifiManager)
            .createMulticastLock("roomwire").apply {
                setReferenceCounted(true)
                acquire()
            }

        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(type: String?) = Unit
            override fun onDiscoveryStopped(type: String?) = Unit
            override fun onStartDiscoveryFailed(type: String?, code: Int) = stopBrowsing()
            override fun onStopDiscoveryFailed(type: String?, code: Int) = Unit

            override fun onServiceFound(info: NsdServiceInfo) {
                resolve(info)
            }

            override fun onServiceLost(info: NsdServiceInfo) {
                scope.launch {
                    seen.remove(info.serviceName)
                    _hosts.value = seen.values.sortedBy { it.name }
                }
            }
        }
        discovery = listener
        nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
    }

    override fun stopBrowsing() {
        discovery?.let { runCatching { nsd.stopServiceDiscovery(it) } }
        discovery = null
        multicast?.let { if (it.isHeld) it.release() }
        multicast = null
        scope.launch {
            seen.clear()
            _hosts.value = emptyList()
            if (_state.value is ViewerState.Browsing) _state.value = ViewerState.Idle
        }
    }

    /**
     * [token] is a fresh random per attempt and is not an identity: it is
     * committed to in `hello` and revealed afterwards, and that is all it does.
     * What identifies this viewer is its certificate.
     */
    override fun join(host: DiscoveredHost, token: UUID, name: String) {
        cancelJoin()
        joining = scope.launch {
            _state.value = ViewerState.Connecting(host)
            val address = host.address
            Log.i(LOG, "join ${host.name} addr=$address port=${host.port}")
            if (address == null) {
                _state.value = ViewerState.Failed("that host has no address yet")
                return@launch
            }
            runCatching { open(host, address, token, Packet.clampName(name)) }
                .onFailure {
                    Log.w(LOG, "join failed: ${it::class.java.simpleName}: ${it.message}", it)
                    _state.value = ViewerState.Failed(it.message ?: "could not connect")
                }
        }
    }

    override fun leave() {
        cancelJoin()
        session?.close()
        session = null
        scope.launch {
            _state.value = if (discovery != null) ViewerState.Browsing else ViewerState.Idle
        }
    }

    // MARK: - One join, from the socket up

    private fun open(host: DiscoveredHost, address: InetAddress, token: UUID, name: String) {
        // The UDP socket first: its port has to go in the hello, because the
        // host dials the viewer rather than the other way round.
        val media = MediaLane(scope)
        val seen = RecordingTrustManager()
        val control = ControlLane(scope, identity.sslContext(seen), seen)
        val live = LiveSession(control, media)
        session = live

        media.onPacket = { packet -> live.onPacket?.invoke(packet) }
        media.onLive = {
            scope.launch {
                if (_state.value !is ViewerState.Connected) {
                    _state.value = ViewerState.Connected(live)
                }
            }
        }

        control.onReady = { hostFingerprint ->
            val handshake = Handshake(token, name, identity.fingerprint, hostFingerprint)
            live.handshake = handshake
            live.peer = Peer(
                id = host.serviceName,
                displayName = host.name,
                fingerprintHex = hostFingerprint.joinToString("") { "%02x".format(it) },
            )
            live.hostChanged = knownHosts.fingerprintOf(host.name)
                ?.let { it != live.peer.fingerprintHex } ?: false
            (handshake.hello(media.port) as? Handshake.Step.Send)?.let { control.send(it.bytes) }
        }
        control.onMessage = { message ->
            val handshake = live.handshake
            for (step in handshake?.receive(message) ?: emptyList()) {
                when (step) {
                    is Handshake.Step.Send -> control.send(step.bytes)
                    is Handshake.Step.ShowCode -> scope.launch {
                        _state.value = ViewerState.AwaitingApproval(host, step.code, live.hostChanged)
                    }
                    is Handshake.Step.Ready -> {
                        knownHosts.remember(host.name, live.peer.fingerprintHex)
                        media.connect(address, step.hostPort, step.mediaKey)
                    }
                    is Handshake.Step.Fail -> scope.launch {
                        live.close()
                        _state.value = ViewerState.Failed(step.reason)
                    }
                }
            }
            // Once the session is up, everything the transport does not consume
            // goes to the app whole.
            if (handshake?.welcomed == true && Packet.decodeMessage(message) != null) {
                live.onPacket?.invoke(message)
            }
        }
        control.onClosed = {
            val step = live.handshake?.closed()
            scope.launch {
                if (_state.value is ViewerState.Connected || step != null) {
                    live.close()
                    _state.value = ViewerState.Failed((step as? Handshake.Step.Fail)?.reason ?: "disconnected")
                }
            }
        }
        control.onFailed = { why ->
            Log.w(LOG, "control lane failed: ${why::class.java.simpleName}: ${why.message}", why)
            scope.launch {
                if (_state.value !is ViewerState.Connected) {
                    _state.value = ViewerState.Failed(why.message ?: "could not reach that Mac")
                }
            }
        }
        Log.i(LOG, "connecting to $address:${host.port}")
        control.connect(address, host.port)
        Log.i(LOG, "control lane handed the socket")
    }

    private fun cancelJoin() {
        joining?.cancel()
        joining = null
    }

    private fun resolve(info: NsdServiceInfo) {
        val callback = object : NsdManager.ServiceInfoCallback {
            override fun onServiceInfoCallbackRegistrationFailed(code: Int) = Unit
            override fun onServiceInfoCallbackUnregistered() = Unit
            override fun onServiceLost() = Unit

            override fun onServiceUpdated(updated: NsdServiceInfo) {
                val txt = updated.attributes
                // A host speaking a version we do not is one to leave alone
                // rather than half-understand. The TXT record is also how a
                // future hello v2 announces itself, before anyone connects.
                val version = txt["v"]?.toString(Charsets.UTF_8)?.toIntOrNull() ?: return
                if (version != PROTOCOL_VERSION) return
                val display = txt["name"]?.toString(Charsets.UTF_8) ?: updated.serviceName
                Log.i(LOG, "resolved ${updated.serviceName} v$version " +
                    "addrs=${updated.hostAddresses} port=${updated.port}")
                val address = updated.hostAddresses.firstOrNull() ?: return
                scope.launch {
                    seen[updated.serviceName] = DiscoveredHost(
                        name = display,
                        version = version,
                        serviceName = updated.serviceName,
                    ).also { it.address = address; it.port = updated.port }
                    _hosts.value = seen.values.sortedBy { it.name }
                }
            }
        }
        // resolveService is deprecated at 34 and this is the replacement: it
        // keeps reporting, so a host that changes address is followed rather
        // than remembered wrongly.
        if (Build.VERSION.SDK_INT >= 34) {
            nsd.registerServiceInfoCallback(info, { it.run() }, callback)
        }
    }

    /** One live session: the two lanes, and what the app holds while it lasts. */
    private inner class LiveSession(
        private val control: ControlLane,
        private val media: MediaLane,
    ) : Session {
        var handshake: Handshake? = null
        var hostChanged = false
        override var peer = Peer("", "", "")
        override var onPacket: ((ByteArray) -> Unit)? = null

        override fun send(bytes: ByteArray, mode: Reliability) {
            if (bytes.isEmpty()) return
            // A viewer has no video, so unreliable means one datagram if it
            // fits and the control lane if it does not.
            if (mode == Reliability.UNRELIABLE && media.send(bytes)) return
            control.send(bytes)
        }

        override fun leave() {
            this@AndroidViewer.leave()
        }

        fun close() {
            media.close()
            control.onClosed = null
            control.close()
        }
    }

    private companion object {
        const val LOG = "roomwire"
        const val SERVICE_TYPE = "_roomwire._tcp."
        const val PROTOCOL_VERSION = 1
    }
}
