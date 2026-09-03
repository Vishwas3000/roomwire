import Foundation

/// Decides whether an arriving frame can be decoded, or is built on one that
/// never came. Pure decision, fed the numbers off the wire — same shape as
/// Pacer and BitrateGovernor — because getting it wrong is either a frozen
/// picture or a corrupt one, and neither is visible in a compiler.
///
/// The point it exists to make: **losing a frame and breaking the stream are
/// not the same event.** With temporal layers about half the frames are an
/// enhancement layer that nothing references, so losing one costs exactly
/// that frame. Only a hole in the frames others are *built on* makes what
/// follows undecodable. Treating every hole as fatal is what turned roughly
/// 5% packet loss into 22% of frames never reaching the screen.
///
/// Two counters, and the difference between them is the whole idea:
///   - `sequence` counts every frame, and measures what the link lost.
///   - `baseSequence` counts only frames others depend on. A base frame is
///     the next after the last; an enhancement frame names the base it was
///     built on. Either running ahead means a base frame never arrived.
///
/// **Deltas ride unreliable sends**, so frames arrive out of order and
/// occasionally twice. Every comparison here is therefore signed distance on
/// a wrapping counter, never equality: a frame that turns up late is stale,
/// which is a different thing from evidence that something was lost. Reading
/// "one behind" as "65,535 ahead" once cost a 65,535-iteration loop on the
/// main thread and a bitrate cut, from a single reordered packet.
public struct ChainGate {
    public enum Verdict: Equatable {
        /// Everything this frame needs has arrived.
        case decode
        /// Something it is built on never came. Undecodable, and so is
        /// everything after it until a frame that restarts the chain.
        case broken
        /// Older than what has already been decoded — a late or duplicated
        /// packet. Nothing to decode and nothing to repair: the picture has
        /// moved past it.
        case stale
    }

    /// True from the first missing base frame until something restores it.
    public private(set) var isBroken = true
    /// Frames that never arrived, whether or not losing them mattered.
    /// Measures the link.
    public private(set) var missing = 0
    /// Of those, the ones others were built on. Measures the damage — this
    /// is the number worth reacting to, because the rest were free.
    public private(set) var missingBase = 0

    private var lastBase: UInt16?
    private var nextSequence: UInt16?

    /// Starts broken on purpose: until a keyframe or recovery frame arrives
    /// there is no chain to be part of, and a delta decoded against nothing
    /// is corruption on glass rather than a dropped frame.
    public init() {}

    public mutating func reset() {
        isBroken = true
        missing = 0
        missingBase = 0
        lastBase = nil
        nextSequence = nil
    }

    /// Signed distance on a wrapping 16-bit counter: positive is ahead,
    /// negative is behind. The whole file depends on never confusing the two.
    private static func distance(_ a: UInt16, _ b: UInt16) -> Int {
        Int(Int16(bitPattern: a &- b))
    }

    /// `restores` is a keyframe or a flagged recovery frame — either one
    /// starts the chain again from itself.
    public mutating func admit(sequence: UInt16, baseSequence: UInt16,
                        droppable: Bool, restores: Bool) -> Verdict {
        if restores {
            isBroken = false
            lastBase = baseSequence
            nextSequence = sequence &+ 1
            return .decode
        }

        // Is this frame older than where the stream has already got to? Both
        // counters have to agree it is current, because either can be the one
        // that went backwards.
        let ahead = nextSequence.map { Self.distance(sequence, $0) } ?? 0
        if ahead < 0 { return .stale }

        guard let last = lastBase else {
            // Nothing to measure against yet, and no chain established.
            nextSequence = sequence &+ 1
            return .broken
        }
        let baseAhead = Self.distance(baseSequence, last)

        if droppable {
            // Built on a base already in hand: fine whenever it turns up.
            // Built on one further ahead: that base never arrived.
            if baseAhead < 0 { return .stale }
            if baseAhead > 0 { isBroken = true; missingBase += baseAhead }
        } else {
            // The next base frame should be exactly one on.
            if baseAhead <= 0 { return .stale }
            if baseAhead > 1 { isBroken = true; missingBase += baseAhead - 1 }
            lastBase = baseSequence          // only ever forward
        }

        // Counted only once the frame is known to be current, so a duplicate
        // cannot invent loss.
        if ahead > 0 { missing += ahead }
        nextSequence = sequence &+ 1

        return isBroken ? .broken : .decode
    }
}
