package com.roomwire.transport

import com.roomwire.protocol.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.util.UUID
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * A [RoomWireViewer] with no network under it: the same states in the same
 * order, on a clock the caller owns.
 *
 * Every wait here is a `delay` on the [scope] handed in, and never a timer of
 * its own. That is the whole point of the constructor taking a scope: under
 * `runTest` the clock is virtual, so a 1.5-second approval and a 60 Hz cursor
 * cost a test no real time at all, and `advanceTimeBy` puts the viewer exactly
 * where the test wants it. Nothing in this file imports `android.*`, so it runs
 * on a laptop.
 *
 * The schedule, so a test can drive it:
 *
 *   startBrowsing()  →  Browsing, and 300 ms later one host, "Fake Mac"
 *   join()           →  Connecting at once, AwaitingApproval 100 ms later
 *                       (two writes to one StateFlow in the same breath would
 *                       conflate, and Connecting is a state worth seeing)
 *                       → Connected after [approvalDelayMs]
 *   connected        →  a cursor round a circle at 60 Hz, one relayed mark at
 *                       1 s, control granted at 3 s, and — given a [video]
 *                       fixture — frames paced by their own sentMs deltas
 *
 * @param approvalDelayMs how long the presenter takes to say yes.
 * @param video opens the fixture: `[u32 length][Packet bytes]` repeated. Called
 *   again each time it is looped or restarted, so it must open a fresh stream.
 */
class FakeViewer(
    private val scope: CoroutineScope,
    private val approvalDelayMs: Long = 1500,
    private val video: (() -> InputStream)? = null,
) : RoomWireViewer {

    private val _hosts = MutableStateFlow<List<DiscoveredHost>>(emptyList())
    override val hosts: StateFlow<List<DiscoveredHost>> = _hosts.asStateFlow()

    private val _state = MutableStateFlow<ViewerState>(ViewerState.Idle)
    override val state: StateFlow<ViewerState> = _state.asStateFlow()

    /** Everything [Session.send] was handed, in order. The reason to use a fake. */
    val sent: MutableList<ByteArray> = mutableListOf()

    private var browsing: Job? = null
    private var joining: Job? = null
    private var session: FakeSession? = null

    override fun startBrowsing() {
        // Valid from Failed, and from Browsing, and twice in a row: a viewer
        // that has to be thrown away after one refused join is not one an app
        // can hold in a view model.
        if (_state.value is ViewerState.Connected) return
        cancelJoin()
        _state.value = ViewerState.Browsing
        if (browsing?.isActive != true) {
            browsing = scope.launch {
                delay(300)
                _hosts.value = listOf(FAKE_HOST)
            }
        }
    }

    override fun stopBrowsing() {
        browsing?.cancel()
        browsing = null
        _hosts.value = emptyList()
        if (_state.value is ViewerState.Browsing) _state.value = ViewerState.Idle
    }

    override fun join(host: DiscoveredHost, token: UUID, name: String) {
        cancelJoin()
        _state.value = ViewerState.Connecting(host)
        joining = scope.launch {
            delay(100)
            _state.value = ViewerState.AwaitingApproval(host, CODE, hostChanged = false)
            delay(approvalDelayMs)
            val live = FakeSession(scope, sent, video)
            session = live
            _state.value = ViewerState.Connected(live)
            live.start()
        }
    }

    override fun leave() {
        cancelJoin()
        session?.leave()
        session = null
        _state.value = if (browsing?.isActive == true || _hosts.value.isNotEmpty()) {
            ViewerState.Browsing
        } else {
            ViewerState.Idle
        }
    }

    /** From AwaitingApproval this is what makes the presenter's answer arrive to nobody. */
    private fun cancelJoin() {
        joining?.cancel()
        joining = null
    }

    private companion object {
        val FAKE_HOST = DiscoveredHost("Fake Mac", 1, "Fake Mac")
        const val CODE = "ABC234"
    }
}

/**
 * What a live session looks like from the app's side, with a circle standing in
 * for a hand on a mouse. Emissions are whole `Packet` messages, byte 0 first,
 * exactly as they arrive off the media lane.
 */
class FakeSession(
    private val scope: CoroutineScope,
    /** Shared with the viewer that made this, so either name reads the same list. */
    val sent: MutableList<ByteArray>,
    private val video: (() -> InputStream)? = null,
) : Session {

    override val peer = Peer(
        id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
        displayName = "Fake Mac",
        fingerprintHex = "11".repeat(32),
    )

    override var onPacket: ((ByteArray) -> Unit)? = null

    private val jobs = mutableListOf<Job>()
    private var frames: Job? = null

    /** Called by [FakeViewer] once the state says Connected. */
    fun start() {
        jobs += scope.launch { cursor() }
        jobs += scope.launch {
            delay(1000)
            emit(Packet.encodeRelayedMark(0u, Packet.Mark.POINT, 0.5, 0.5))
        }
        jobs += scope.launch {
            delay(3000)
            emit(Packet.encodeControlGranted(true))
        }
        if (video != null) restartFrames()
    }

    override fun send(bytes: ByteArray, mode: Reliability) {
        sent += bytes
        // A viewer whose decoder has failed asks for a keyframe; the fixture
        // starts with one, so the honest answer is to play it again from the top.
        if (bytes.size == 1 && bytes[0] == NEED_KEYFRAME) restartFrames()
    }

    override fun leave() {
        frames?.cancel()
        frames = null
        jobs.forEach { it.cancel() }
        jobs.clear()
        onPacket = null
    }

    /**
     * 60 Hz round a circle: centre (0.5, 0.5), radius 0.35, three seconds
     * round. `sentMs` is the fake's own clock, which under `runTest` is the
     * virtual one, so a viewer's own pacing logic sees a metronome.
     */
    private suspend fun cursor() {
        var seq = 0
        var ms = 0L
        while (true) {
            val angle = 2 * PI * (ms % PERIOD_MS) / PERIOD_MS
            emit(
                Packet.encodeCursor(
                    seq.toUShort(), ms.toUInt(),
                    0.5 + 0.35 * cos(angle), 0.5 + 0.35 * sin(angle),
                ),
            )
            seq += 1
            ms += FRAME_MS
            delay(FRAME_MS)
        }
    }

    private fun restartFrames() {
        val open = video ?: return
        frames?.cancel()
        frames = scope.launch {
            // Read once: the fixture is a few megabytes and looping it should
            // not re-parse it every three seconds.
            val loaded = open().use { read(it) }
            if (loaded.isEmpty()) return@launch
            while (true) {
                var previous: UInt? = null
                for (frame in loaded) {
                    // Pace off the frames' own clock, so the fixture plays at
                    // the rate it was captured at rather than as fast as the
                    // loop can go. A wrap or a backwards stamp reads as 0.
                    val stamp = Packet.decode(frame)?.sentMs
                    if (previous != null && stamp != null) {
                        val gap = (stamp - previous).toLong()
                        if (gap in 1..1000) delay(gap)
                    }
                    if (stamp != null) previous = stamp
                    emit(frame)
                }
            }
        }
    }

    /** `[u32 length][Packet bytes]` repeated. A truncated tail is simply the end. */
    private fun read(stream: InputStream): List<ByteArray> {
        val input = DataInputStream(stream.buffered())
        val out = mutableListOf<ByteArray>()
        try {
            while (true) {
                val length = input.readInt()
                if (length <= 0 || length > MAX_FRAME) break
                val frame = ByteArray(length)
                input.readFully(frame)
                out += frame
            }
        } catch (e: EOFException) {
            // The fixture ended, which is the only way this loop is meant to stop.
        }
        return out
    }

    private fun emit(bytes: ByteArray) {
        onPacket?.invoke(bytes)
    }

    private companion object {
        const val FRAME_MS = 16L
        const val PERIOD_MS = 3000L
        const val MAX_FRAME = 8_388_608
        const val NEED_KEYFRAME: Byte = 8
    }
}
