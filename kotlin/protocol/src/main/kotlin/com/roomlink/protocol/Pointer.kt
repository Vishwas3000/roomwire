package com.roomlink.protocol

import kotlin.math.hypot
import kotlin.math.min

/**
 * A port of swift/Sources/RoomLinkProtocol/Pointer.swift. Behaviour is held to
 * the Swift side by protocol/transcripts.txt.
 *
 * The wire carries a **button mask**, not clicks. That is RFB's design and it
 * is the reason a dropped or reordered message heals: every message states the
 * whole truth, so the next one corrects the last. A desktop wants the edges, so
 * [PointerState] computes them on the host, where the previous state is known.
 * A finger has no buttons, so [TouchIntent] reads what the person meant from
 * time and distance on the viewer.
 */

/** What the host should be told, derived from what the viewer says is true now. Coordinates are in whatever space the caller feeds it. */
class PointerState {
    enum class Button { LEFT, RIGHT }

    sealed interface Action {
        /** Nothing is held; the pointer is just travelling. */
        data class Move(val at: Point) : Action
        /** A button is held and the pointer moved. Not a move — posting a move mid-drag does nothing at all. */
        data class Drag(val at: Point, val button: Button) : Action
        data class Down(val at: Point, val button: Button, val clicks: Int) : Action
        /** Carries the same count as the press it closes. */
        data class Up(val at: Point, val button: Button, val clicks: Int) : Action
    }

    companion object {
        const val LEFT: UByte = 1u
        const val RIGHT: UByte = 2u
        /** A second click only counts as a double if it lands near enough and soon enough. */
        const val DOUBLE_CLICK_INTERVAL = 0.5
        const val SLOP = 4.0

        private fun all(mask: UByte): List<Button> = buildList {
            if ((mask and LEFT) == LEFT) add(Button.LEFT)
            if ((mask and RIGHT) == RIGHT) add(Button.RIGHT)
        }
        private fun first(mask: UByte): Button? = all(mask).firstOrNull()
    }

    private var held: UByte = 0u
    private var at: Point? = null
    private var lastDown: Pair<Point, Double>? = null
    private var clicks = 1

    /** The viewer says: these buttons are down, and the pointer is here. */
    fun admit(buttons: UByte, point: Point, now: Double): List<Action> {
        val out = ArrayList<Action>()
        // The first message always counts as movement — the host pointer is
        // wherever the presenter left it, which is not where the finger is.
        val moved = at != point
        val pressed = (buttons.toInt() and held.toInt().inv() and 0xFF).toUByte()
        val released = (held.toInt() and buttons.toInt().inv() and 0xFF).toUByte()

        // Position first, so a press lands where the finger is. Whether that
        // movement is a move or a drag is decided by what was held *before*.
        if (moved) {
            val down = first(held)
            if (down != null) out.add(Action.Drag(point, down)) else out.add(Action.Move(point))
        }
        for (button in all(released)) {
            out.add(Action.Up(point, button, if (button == Button.LEFT) clicks else 1))
        }
        for (button in all(pressed)) {
            var count = 1
            if (button == Button.LEFT) {
                val ld = lastDown
                val near = ld != null && hypot(ld.first.x - point.x, ld.first.y - point.y) <= SLOP
                val soon = ld != null && now - ld.second <= DOUBLE_CLICK_INTERVAL
                clicks = if (near && soon) min(clicks + 1, 3) else 1
                lastDown = Pair(point, now)
                count = clicks
            }
            out.add(Action.Down(point, button, count))
        }

        held = buttons
        at = point
        return out
    }

    /** Whatever is still held, released where it stands. For a viewer that vanished mid-drag. */
    fun release(now: Double): List<Action> {
        val point = at
        if (held == 0u.toUByte() || point == null) return emptyList()
        return admit(0u, point, now)
    }
}

/**
 * A finger has no buttons and no hover, so what the person meant has to be read
 * from time and distance: a quick lift is a click, a hold is a right click, and
 * movement past a threshold is a drag. Positions are in the view's coordinates.
 */
class TouchIntent {
    data class Step(val buttons: UByte, val at: Point)

    enum class Phase { BEGAN, MOVED, ENDED, CANCELLED }

    companion object {
        /** Far enough that it was not just the hand settling on the glass. */
        const val DRAG_SLOP = 10.0
        const val HOLD_DELAY = 0.5
    }

    private var start: Point? = null
    private var touching = false
    private var dragging = false
    /** The hold already fired a right click; the lift owes nothing more. */
    private var spent = false

    /** True while a hold timer is worth having scheduled. */
    val awaitingHold: Boolean get() = touching && !dragging && !spent

    fun admit(phase: Phase, point: Point): List<Step> = when (phase) {
        Phase.BEGAN -> {
            start = point
            touching = true
            dragging = false
            spent = false
            // Send the pointer to the finger before anything is pressed.
            listOf(Step(0u, point))
        }
        Phase.MOVED -> {
            val s = start
            if (!touching || s == null) emptyList()
            else if (dragging) listOf(Step(PointerState.LEFT, point))
            else if (spent || hypot(point.x - s.x, point.y - s.y) <= DRAG_SLOP) listOf(Step(0u, point))
            else {
                dragging = true
                // Press at where the finger *started*: dragging a window has to
                // grab the titlebar that was touched.
                listOf(Step(PointerState.LEFT, s), Step(PointerState.LEFT, point))
            }
        }
        Phase.ENDED -> {
            if (!touching) emptyList()
            else {
                touching = false
                if (dragging) listOf(Step(0u, point))
                else if (spent) emptyList()
                else listOf(Step(PointerState.LEFT, point), Step(0u, point))
            }
        }
        Phase.CANCELLED -> {
            if (!touching) emptyList()
            else {
                touching = false
                if (dragging) listOf(Step(0u, point)) else emptyList()
            }
        }
    }

    /** The hold timer went off. Returns nothing if the finger already left or started dragging. */
    fun holdFired(): List<Step> {
        val s = start
        if (!awaitingHold || s == null) return emptyList()
        spent = true
        return listOf(Step(PointerState.RIGHT, s), Step(0u, s))
    }
}
