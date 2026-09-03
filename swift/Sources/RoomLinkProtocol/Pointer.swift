import CoreGraphics
import Foundation


/// Turning a viewer's finger into a pointer on the presenter's Mac.
///
/// Two state machines face each other across the link, and neither one is
/// where the interesting failure lives — that is in the translation.
///
/// The wire carries a **button mask**, not clicks. That is RFB's design
/// (RFC 6143) and it is the reason a dropped or reordered message heals: every
/// message states the whole truth, so the next one corrects the last. Click
/// and release *events* cannot do that — lose a release and the button is
/// stuck down until somebody notices, which on a link measured losing a fifth
/// of what it sends is a matter of when, not whether.
///
/// macOS wants the edges, so `PointerState` computes them here, on the host,
/// where the previous state is known.

// MARK: - Host: mask -> events

/// What the presenter's Mac should be told, derived from what the viewer says
/// is true now. Coordinates are in whatever space the caller feeds it; the
/// host feeds global display points, so the slop below is points.
public struct PointerState {
    public enum Button: Equatable { case left, right }

    public enum Action: Equatable {
        /// Nothing is held; the pointer is just travelling.
        case move(CGPoint)
        /// A button is held and the pointer moved. This is *not* a move —
        /// posting `mouseMoved` mid-drag silently does nothing at all, which
        /// is the single easiest way to ship a broken drag.
        case drag(CGPoint, Button)
        case down(CGPoint, Button, clicks: Int)
        /// Carries the same count as the press it closes — AppKit controls
        /// read `clickCount` off the release as often as off the press.
        case up(CGPoint, Button, clicks: Int)
    }

    public static let left: UInt8 = 1
    public static let right: UInt8 = 2

    /// A second click only counts as a double if it lands near enough and soon
    /// enough. Both bounds are the system's, in spirit: ~0.5 s and a few
    /// points. Two clicks in the same place a second apart are two clicks.
    public static let doubleClickInterval: TimeInterval = 0.5
    public static let slop: CGFloat = 4

    private var held: UInt8 = 0
    private var at: CGPoint?
    private var lastDown: (at: CGPoint, when: TimeInterval)?
    private var clicks = 1

    /// The viewer says: these buttons are down, and the pointer is here.
    public init() {}

    public mutating func admit(buttons mask: UInt8, at point: CGPoint, now: TimeInterval) -> [Action] {
        var out: [Action] = []
        // The first message always counts as movement — the host pointer is
        // wherever the presenter left it, which is not where the finger is.
        let moved = at != point
        let pressed = mask & ~held
        let released = held & ~mask

        // Position first, so a press lands where the finger is rather than
        // where the pointer happened to be sitting. Whether that movement is a
        // move or a drag is decided by what was held *before* this message:
        // during a release the button is still down for the travel.
        if moved {
            if let down = Self.first(in: held) {
                out.append(.drag(point, down))
            } else {
                out.append(.move(point))
            }
        }
        for button in Self.all(in: released) {
            out.append(.up(point, button, clicks: button == .left ? clicks : 1))
        }
        for button in Self.all(in: pressed) {
            var count = 1
            if button == .left {
                let near = lastDown.map { hypot($0.at.x - point.x, $0.at.y - point.y) <= Self.slop } ?? false
                let soon = lastDown.map { now - $0.when <= Self.doubleClickInterval } ?? false
                clicks = near && soon ? min(clicks + 1, 3) : 1
                lastDown = (point, now)
                count = clicks
            }
            out.append(.down(point, button, clicks: count))
        }

        held = mask
        at = point
        return out
    }

    /// Whatever is still held, released where it stands. For a viewer that
    /// vanished mid-drag: without this the button stays down on the host.
    public mutating func release(now: TimeInterval) -> [Action] {
        guard held != 0, let point = at else { return [] }
        return admit(buttons: 0, at: point, now: now)
    }

    private static func all(in mask: UInt8) -> [Button] {
        var out: [Button] = []
        if mask & left == left { out.append(.left) }
        if mask & right == right { out.append(.right) }
        return out
    }

    private static func first(in mask: UInt8) -> Button? { all(in: mask).first }
}

// MARK: - Viewer: finger -> mask

/// A finger has no buttons and no hover, so what the person meant has to be
/// read from time and distance: a quick lift is a click, a hold is a right
/// click, and movement past a threshold is a drag.
///
/// Positions are in the view's coordinates; the caller normalizes before
/// sending. `slop` is therefore in points on the phone's glass.
public struct TouchIntent {
    public struct Step: Equatable {
        public let buttons: UInt8
        public let at: CGPoint
        public init(buttons: UInt8, at: CGPoint) { self.buttons = buttons; self.at = at }
    }

    /// Far enough that it was not just the hand settling on the glass.
    public static let dragSlop: CGFloat = 10
    public static let holdDelay: TimeInterval = 0.5

    public enum Phase { case began, moved, ended, cancelled }

    private var start: CGPoint?
    private var touching = false
    private var dragging = false
    /// The hold already fired a right click; the lift owes nothing more.
    private var spent = false

    /// True while a hold timer is worth having scheduled.
    public init() {}

    public var awaitingHold: Bool { touching && !dragging && !spent }

    public mutating func admit(_ phase: Phase, at point: CGPoint) -> [Step] {
        switch phase {
        case .began:
            start = point
            touching = true
            dragging = false
            spent = false
            // Send the pointer to the finger before anything is pressed, so
            // the presenter's screen shows where the tap is about to land.
            return [Step(buttons: 0, at: point)]

        case .moved:
            guard touching, let start else { return [] }
            if dragging { return [Step(buttons: PointerState.left, at: point)] }
            guard !spent, hypot(point.x - start.x, point.y - start.y) > Self.dragSlop else {
                return [Step(buttons: 0, at: point)]
            }
            dragging = true
            // Press at where the finger *started*, not where it is now:
            // dragging a window has to grab the titlebar that was touched.
            return [Step(buttons: PointerState.left, at: start),
                    Step(buttons: PointerState.left, at: point)]

        case .ended:
            guard touching else { return [] }
            touching = false
            if dragging { return [Step(buttons: 0, at: point)] }
            if spent { return [] }
            return [Step(buttons: PointerState.left, at: point),
                    Step(buttons: 0, at: point)]

        case .cancelled:
            guard touching else { return [] }
            touching = false
            return dragging ? [Step(buttons: 0, at: point)] : []
        }
    }

    /// The hold timer went off. Returns nothing if the finger already left or
    /// started dragging — a timer that outlived its gesture is harmless, which
    /// saves every caller from having to cancel it precisely.
    public mutating func holdFired() -> [Step] {
        guard awaitingHold, let start else { return [] }
        spent = true
        return [Step(buttons: PointerState.right, at: start),
                Step(buttons: 0, at: start)]
    }
}
