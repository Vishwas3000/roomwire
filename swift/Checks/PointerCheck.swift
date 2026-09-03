import CoreGraphics
import Foundation

// A tap that lands as a click, a drag that actually drags, and a button that
// never gets stuck down. All three fail silently: a drag posted as a move does
// nothing at all and reports no error, and a release lost in the air leaves
// the presenter's mouse held down with no way to tell. Neither shows up in a
// compiler, and neither is pleasant to find on a phone.
// Run with:  ./check.sh

@main
enum PointerCheck {
    static func main() {
        movingWithNothingHeldIsAMove()
        movePrecedesADownSomewhereNew()
        aDragIsNeverAMove()
        aRepeatedMessageSaysNothing()
        aLostReleaseHealsOnTheNextMessage()
        releaseLetsGoOfWhateverWasHeld()
        twoQuickClicksCountAsTwo()
        aSlowSecondClickCountsAsOne()
        aDistantSecondClickCountsAsOne()
        rightAndLeftAreIndependent()

        aTapIsDownThenUp()
        aDragGrabsWhereTheFingerLanded()
        aHoldIsARightClick()
        movingCancelsTheHold()
        aHoldDoesNotAlsoClickOnLift()
        aStaleHoldTimerIsHarmless()

        print("pointer: all checks passed")
    }

    private static let origin = CGPoint(x: 100, y: 100)
    private static let elsewhere = CGPoint(x: 300, y: 220)

    // MARK: - Host: the mask becomes events

    private static func movingWithNothingHeldIsAMove() {
        var p = PointerState()
        let out = p.admit(buttons: 0, at: origin, now: 0)
        assert(out == [.move(origin)], "a plain move produced \(out)")
    }

    /// A press has to arrive at the finger, not where the presenter last left
    /// the pointer — otherwise the first tap of every session clicks whatever
    /// happened to be under the old position.
    private static func movePrecedesADownSomewhereNew() {
        var p = PointerState()
        let out = p.admit(buttons: PointerState.left, at: origin, now: 0)
        assert(out == [.move(origin), .down(origin, .left, clicks: 1)],
               "a press at a new place produced \(out)")
    }

    /// The silent one. `mouseMoved` posted while a button is held does nothing
    /// whatsoever — no error, no event, just a drag that mysteriously fails.
    private static func aDragIsNeverAMove() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        let out = p.admit(buttons: PointerState.left, at: elsewhere, now: 0.1)
        assert(out == [.drag(elsewhere, .left)], "moving mid-drag produced \(out)")
        for action in out {
            if case .move = action { assert(false, "a held button emitted a move") }
        }
    }

    /// The mask is a statement of fact, not an edge. Saying the same thing
    /// twice must not press anything twice.
    private static func aRepeatedMessageSaysNothing() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        let out = p.admit(buttons: PointerState.left, at: origin, now: 0.05)
        assert(out.isEmpty, "a repeated message produced \(out)")
    }

    /// The whole reason the wire carries state rather than clicks. If the
    /// message that released the button never arrives, the next one still
    /// says the button is up, and the host lets go.
    private static func aLostReleaseHealsOnTheNextMessage() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        // ...the release is lost in the air, and the next message is a plain
        // move with nothing held.
        let out = p.admit(buttons: 0, at: elsewhere, now: 0.4)
        assert(out.contains(.up(elsewhere, .left, clicks: 1)),
               "a lost release left the button down: \(out)")
        // The travel happened while the button was still held, so it is a drag.
        assert(out.first == .drag(elsewhere, .left), "release-with-motion produced \(out)")
    }

    /// A viewer that walks out of range mid-drag would otherwise leave the
    /// presenter's mouse held down with nobody to lift it.
    private static func releaseLetsGoOfWhateverWasHeld() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left | PointerState.right, at: origin, now: 0)
        let out = p.release(now: 0.5)
        assert(out.contains(.up(origin, .left, clicks: 1)), "left stayed down: \(out)")
        assert(out.contains(.up(origin, .right, clicks: 1)), "right stayed down: \(out)")
        assert(p.release(now: 0.6).isEmpty, "releasing twice pressed something")
    }

    private static func twoQuickClicksCountAsTwo() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        _ = p.admit(buttons: 0, at: origin, now: 0.05)
        let out = p.admit(buttons: PointerState.left, at: origin, now: 0.15)
        assert(out == [.down(origin, .left, clicks: 2)], "a double click produced \(out)")
    }

    private static func aSlowSecondClickCountsAsOne() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        _ = p.admit(buttons: 0, at: origin, now: 0.05)
        let out = p.admit(buttons: PointerState.left, at: origin, now: 2)
        assert(out == [.down(origin, .left, clicks: 1)],
               "two clicks a second apart were read as a double click: \(out)")
    }

    private static func aDistantSecondClickCountsAsOne() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        _ = p.admit(buttons: 0, at: origin, now: 0.05)
        let out = p.admit(buttons: PointerState.left, at: elsewhere, now: 0.15)
        assert(out.contains(.down(elsewhere, .left, clicks: 1)),
               "clicks in different places were read as a double click: \(out)")
    }

    private static func rightAndLeftAreIndependent() {
        var p = PointerState()
        _ = p.admit(buttons: PointerState.left, at: origin, now: 0)
        let out = p.admit(buttons: PointerState.left | PointerState.right, at: origin, now: 0.1)
        assert(out == [.down(origin, .right, clicks: 1)],
               "adding the right button disturbed the left: \(out)")
    }

    // MARK: - Viewer: the finger becomes a mask

    private static func aTapIsDownThenUp() {
        var t = TouchIntent()
        let began = t.admit(.began, at: origin)
        assert(began == [.init(buttons: 0, at: origin)],
               "touching down pressed something before it had to: \(began)")
        let ended = t.admit(.ended, at: origin)
        assert(ended == [.init(buttons: PointerState.left, at: origin),
                         .init(buttons: 0, at: origin)],
               "a tap produced \(ended)")
    }

    /// Dragging a window has to take hold of the titlebar the finger landed
    /// on, not wherever it had got to by the time the drag was recognised.
    private static func aDragGrabsWhereTheFingerLanded() {
        var t = TouchIntent()
        _ = t.admit(.began, at: origin)
        let nudge = CGPoint(x: origin.x + 3, y: origin.y)
        assert(t.admit(.moved, at: nudge) == [.init(buttons: 0, at: nudge)],
               "a small wobble started a drag")

        let out = t.admit(.moved, at: elsewhere)
        assert(out.first == .init(buttons: PointerState.left, at: origin),
               "the drag grabbed the wrong place: \(out)")
        assert(out.last == .init(buttons: PointerState.left, at: elsewhere),
               "the drag did not follow the finger: \(out)")

        let ended = t.admit(.ended, at: elsewhere)
        assert(ended == [.init(buttons: 0, at: elsewhere)], "the drag never let go: \(ended)")
    }

    private static func aHoldIsARightClick() {
        var t = TouchIntent()
        _ = t.admit(.began, at: origin)
        assert(t.awaitingHold, "nothing was waiting for the hold timer")
        let out = t.holdFired()
        assert(out == [.init(buttons: PointerState.right, at: origin),
                       .init(buttons: 0, at: origin)],
               "a hold produced \(out)")
    }

    private static func movingCancelsTheHold() {
        var t = TouchIntent()
        _ = t.admit(.began, at: origin)
        _ = t.admit(.moved, at: elsewhere)
        assert(!t.awaitingHold, "a drag was still waiting to become a right click")
        assert(t.holdFired().isEmpty, "a hold fired in the middle of a drag")
    }

    /// Otherwise a long press opens the context menu and then immediately
    /// left-clicks whatever item happened to be under the finger.
    private static func aHoldDoesNotAlsoClickOnLift() {
        var t = TouchIntent()
        _ = t.admit(.began, at: origin)
        _ = t.holdFired()
        let ended = t.admit(.ended, at: origin)
        assert(ended.isEmpty, "lifting after a right click also left-clicked: \(ended)")
    }

    /// The timer is scheduled on touch-down and nobody promises to cancel it
    /// in time. Firing late has to be free rather than a stray right click.
    private static func aStaleHoldTimerIsHarmless() {
        var t = TouchIntent()
        _ = t.admit(.began, at: origin)
        _ = t.admit(.ended, at: origin)
        assert(t.holdFired().isEmpty, "a timer outlived its gesture and right-clicked")
    }
}
