import Foundation

// Packet.decode is the app's only trust boundary: it parses bytes off the
// network. Run with:  ./check.sh

@main
enum PacketCheck {
    static func main() {
        let sps = Data([0x67, 0x64, 0x00, 0x1f])
        let pps = Data([0x68, 0xeb, 0xe3, 0xcb])
        let payload = Data([0x00, 0x00, 0x00, 0x05, 0x65, 0x01, 0x02, 0x03, 0x04])

        // Keyframe carries the parameter sets.
        let key = Packet.encode(payload: payload, sps: sps, pps: pps, keyframe: true,
                                sentMs: 0xA1B2C3D4, sequence: 41, baseSequence: 20)
        guard let a = Packet.decode(key) else { fatalError("keyframe did not decode") }
        assert(a.keyframe)
        assert(a.sentMs == 0xA1B2C3D4, "send time round trip")
        assert(a.ltrToken == nil, "token conjured from nothing")
        assert(a.sequence == 41 && a.baseSequence == 20, "sequence round trip")
        assert(!a.droppable, "a keyframe must never be marked droppable")
        assert(!a.recovery, "recovery conjured from nothing")
        assert(a.sps == sps, "SPS round trip")
        assert(a.pps == pps, "PPS round trip")
        assert(a.payload == payload, "payload round trip")

        // Delta frames carry none.
        let delta = Packet.encode(payload: payload, sps: nil, pps: nil, keyframe: false,
                                  recovery: true, sentMs: 7, sequence: 0xFFFF, baseSequence: 0xFFFE)
        guard let b = Packet.decode(delta) else { fatalError("delta did not decode") }
        assert(!b.keyframe)
        assert(b.sentMs == 7)
        assert(b.recovery && b.sequence == 0xFFFF && b.baseSequence == 0xFFFE, "recovery delta round trip")
        assert(b.sps == nil && b.pps == nil)
        assert(b.payload == payload)

        // A long-term reference carries its acknowledgement token.
        let ltr = Packet.encode(payload: payload, sps: nil, pps: nil, keyframe: false,
                                sentMs: 9, sequence: 3, baseSequence: 2, ltrToken: 0xDEAD_BEEF_CAFE_F00D)
        guard let l = Packet.decode(ltr) else { fatalError("LTR frame did not decode") }
        assert(l.ltrToken == 0xDEAD_BEEF_CAFE_F00D, "token round trip")
        assert(l.payload == payload, "LTR payload round trip")
        for n in 0 ..< ltr.count {
            _ = Packet.decode(ltr.prefix(n))   // truncations return nil, never crash
        }
        // An enhancement-layer frame says so, and it round-trips.
        let spare = Packet.encode(payload: payload, sps: nil, pps: nil, keyframe: false,
                                  droppable: true, sentMs: 11, sequence: 8, baseSequence: 4)
        guard let d = Packet.decode(spare) else { fatalError("droppable frame did not decode") }
        assert(d.droppable, "droppable flag lost")
        assert(d.baseSequence == 4, "base sequence lost on a droppable frame")
        assert(!d.keyframe && !d.recovery, "droppable bit bled into the other markers")

        // Marker bits beyond the three defined are refused off the network.
        var badMarker = ltr
        badMarker[5] = 8
        assert(Packet.decode(badMarker) == nil, "unknown marker bits accepted")

        // A length header that overruns the buffer must be refused, not trusted.
        var lying = Data([1, 0, 0, 0, 0, 0, 0, 9, 0, 4])   // flags, time, marker, seq, base
        lying.append(contentsOf: [0x7f, 0xff, 0xff, 0xff])
        lying.append(contentsOf: [UInt8](repeating: 0, count: 16))
        assert(Packet.decode(lying) == nil, "oversized SPS length accepted")

        // Header present but no payload behind it.
        let headerOnly = Packet.encode(payload: Data(), sps: sps, pps: pps, keyframe: true,
                                       sentMs: 0, sequence: 0, baseSequence: 0)
        assert(Packet.decode(headerOnly) == nil, "empty payload accepted")

        // Every truncation of a valid packet must return nil rather than crash.
        for n in 0 ..< key.count {
            _ = Packet.decode(key.prefix(n))
        }

        // The pointer rides the same wire as tiny typed messages.
        let move = Packet.encodeCursor(seq: 42, sentMs: 987_654, x: 0.25, y: 0.75)
        guard case let .cursor(seq, sentMs, cx, cy)? = Packet.decodeMessage(move) else {
            fatalError("cursor did not decode")
        }
        assert(seq == 42 && sentMs == 987_654, "cursor lost its sequence or clock")
        assert(abs(cx - 0.25) < 1e-6 && abs(cy - 0.75) < 1e-6, "cursor round trip")
        guard case .cursorHidden(let hiddenSeq)? = Packet.decodeMessage(Packet.encodeCursorHidden(seq: 9)) else {
            fatalError("cursor-hidden did not decode")
        }
        assert(hiddenSeq == 9, "cursor-hidden seq round trip")
        guard case .video(let viaMessage)? = Packet.decodeMessage(key), viaMessage.keyframe else {
            fatalError("video did not route through decodeMessage")
        }
        // Encode clamps, so a sender bug cannot put the pointer off-screen.
        guard case let .cursor(_, _, clampedX, _)? =
            Packet.decodeMessage(Packet.encodeCursor(seq: 0, sentMs: 0, x: 7, y: -3)) else {
            fatalError("clamped cursor did not decode")
        }
        assert(clampedX == 1, "clamp")

        // Hostile coordinates are refused: NaN, out of range, wrong size.
        assert(Packet.decodeMessage(Data([2, 0, 0, 0, 0, 0, 0, 0x7F, 0xC0, 0, 0, 0, 0, 0, 0])) == nil,
               "NaN accepted")
        assert(Packet.decodeMessage(Data([2, 0, 0, 0, 0, 0, 0, 0x3F, 0xC0, 0, 0, 0, 0, 0, 0])) == nil,
               "x=1.5 accepted")
        assert(Packet.decodeMessage(Data([2, 0, 0])) == nil, "truncated cursor accepted")
        assert(Packet.decodeMessage(Data([3, 0, 0, 0])) == nil, "oversized hide accepted")
        assert(Packet.decodeMessage(Data([9, 1, 2, 3])) == nil, "unknown type accepted")

        // The pointer probe: both timelines round-trip, positions to within
        // what 16 bits of normalized fixed point can hold.
        let probe = [Packet.ProbeSample(drawn: false, ms: 0, x: 0.25, y: 0.75, seq: 41),
                     Packet.ProbeSample(drawn: true, ms: 123_456, x: 0.5, y: 0.125, seq: 42)]
        guard case .probe(let back)? = Packet.decodeMessage(Packet.encodeProbe(probe)) else {
            fatalError("probe did not decode")
        }
        assert(back.count == 2, "probe sample count changed")
        for (i, original) in probe.enumerated() {
            assert(back[i].drawn == original.drawn, "probe sample \(i) changed which timeline it was on")
            assert(back[i].ms == original.ms, "probe sample \(i) lost its clock")
            assert(back[i].seq == original.seq, "probe sample \(i) lost its sequence")
            assert(abs(back[i].x - original.x) < 1e-4 && abs(back[i].y - original.y) < 1e-4,
                   "probe sample \(i) moved: \(back[i].x),\(back[i].y)")
        }
        // Bounds: a count that does not match the body, and a timeline byte
        // that is neither of the two.
        assert(Packet.decodeMessage(Data([13, 2, 0])) == nil, "short probe accepted")
        assert(Packet.decodeMessage(Data([13, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) == nil,
               "probe with an unknown timeline accepted")

        // Random bytes must never trip a bounds check.
        var rng = SystemRandomNumberGenerator()
        for _ in 0 ..< 5000 {
            let size = Int.random(in: 0 ... 64, using: &rng)
            _ = Packet.decodeMessage(Data((0 ..< size).map { _ in UInt8.random(in: 0 ... 255, using: &rng) }))
        }

        // Back-channel round trips.
        for kind in [Packet.Mark.point, .draw, .lift, .clear] {
            guard case .mark(let k, let x, let y)? =
                    Packet.decodeMessage(Packet.encodeMark(kind, x: 0.25, y: 0.75)) else {
                fatalError("mark did not decode")
            }
            assert(k == kind && abs(x - 0.25) < 1e-6 && abs(y - 0.75) < 1e-6, "mark round trip")

            guard case .relayedMark(let slot, let rk, _, _)? =
                    Packet.decodeMessage(Packet.encodeRelayedMark(slot: 7, kind: kind, x: 0, y: 1)) else {
                fatalError("relayed mark did not decode")
            }
            assert(slot == 7 && rk == kind, "relayed mark round trip")
        }

        for reaction in Packet.Reaction.allCases {
            guard case .reaction(let r)? = Packet.decodeMessage(Packet.encodeReaction(reaction)) else {
                fatalError("reaction did not decode")
            }
            assert(r == reaction, "reaction round trip")
        }

        // A kind or reaction byte we do not know must be refused outright: a
        // garbled byte should not conjure a mark at some arbitrary spot.
        assert(Packet.decodeMessage(Data([4, 99, 0, 0, 0, 0, 0, 0, 0, 0])) == nil, "unknown mark kind accepted")
        assert(Packet.decodeMessage(Data([6, 99])) == nil, "unknown reaction accepted")

        // Coordinates off the unit square, and a wrong length, are both refused.
        var infinite = Data([4, 0])
        infinite.append(contentsOf: [0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        assert(Packet.decodeMessage(infinite) == nil, "infinite mark coordinate accepted")
        assert(Packet.decodeMessage(Data([4, 0, 0, 0, 0])) == nil, "short mark accepted")
        assert(Packet.decodeMessage(Data([5, 0, 0, 0, 0])) == nil, "short relayed mark accepted")

        guard case .telemetry(let frames, let kilobytes, let maxGap, let p95Gap, let skipped, let gapDropped)? =
                Packet.decodeMessage(Packet.encodeTelemetry(frames: 1234, kilobytes: 5_000_000,
                                                            maxGapMs: 512, p95GapMs: 41, skipped: 9,
                                                            gapDropped: 3)) else {
            fatalError("telemetry did not decode")
        }
        assert(frames == 1234 && kilobytes == 5_000_000, "telemetry round trip")
        assert(maxGap == 512 && p95Gap == 41 && skipped == 9 && gapDropped == 3, "arrival texture round trip")
        // A gap too long for 16 bits arrives as the worst it can say, not garbage.
        guard case .telemetry(_, _, let clampedGap, _, _, _)? =
                Packet.decodeMessage(Packet.encodeTelemetry(frames: 1, kilobytes: 1, maxGapMs: 90_000,
                                                            p95GapMs: 0, skipped: 0, gapDropped: 0)) else {
            fatalError("clamped telemetry did not decode")
        }
        assert(clampedGap == 65_535, "gap clamp")
        assert(Packet.decodeMessage(Data([7, 0, 0, 0])) == nil, "short telemetry accepted")
        assert(Packet.decodeMessage(Data([7] + [UInt8](repeating: 0, count: 19))) == nil,
               "one-byte-short telemetry accepted")
        assert(Packet.decodeMessage(Data([7] + [UInt8](repeating: 0, count: 21))) == nil,
               "overlong telemetry accepted")

        guard case .needKeyframe? = Packet.decodeMessage(Packet.needKeyframeMessage) else {
            fatalError("keyframe request did not decode")
        }
        assert(Packet.decodeMessage(Data([8, 0])) == nil, "overlong keyframe request accepted")

        guard case .identify? = Packet.decodeMessage(Packet.identifyMessage) else {
            fatalError("identify did not decode")
        }
        assert(Packet.decodeMessage(Data([9, 0])) == nil, "overlong identify accepted")

        guard case .ackReference(let token)? =
                Packet.decodeMessage(Packet.encodeAckReference(token: 0x0102_0304_0506_0708)) else {
            fatalError("reference ack did not decode")
        }
        assert(token == 0x0102_0304_0506_0708, "reference ack round trip")
        assert(Packet.decodeMessage(Data([10] + [UInt8](repeating: 0, count: 7))) == nil,
               "short reference ack accepted")
        assert(Packet.decodeMessage(Data([10] + [UInt8](repeating: 0, count: 9))) == nil,
               "overlong reference ack accepted")

        guard case .needRefresh? = Packet.decodeMessage(Packet.needRefreshMessage) else {
            fatalError("refresh request did not decode")
        }
        assert(Packet.decodeMessage(Data([11, 0])) == nil, "overlong refresh request accepted")

        let records = [
            Packet.FlightRecord(sequence: 7, latenessMs: -12, flags: Packet.FlightRecord.shown),
            Packet.FlightRecord(sequence: 8, latenessMs: 312,
                                flags: Packet.FlightRecord.skipped | Packet.FlightRecord.keyframe),
            Packet.FlightRecord(sequence: 9, latenessMs: 0x7FFF, flags: Packet.FlightRecord.gapDropped),
        ]
        guard case .flight(let back)? = Packet.decodeMessage(Packet.encodeFlight(records)) else {
            fatalError("flight batch did not decode")
        }
        assert(back == records, "flight round trip")
        // Only the newest 48 survive an oversized batch.
        let many = (0 ..< 60).map { Packet.FlightRecord(sequence: UInt16($0), latenessMs: 0, flags: 1) }
        guard case .flight(let capped)? = Packet.decodeMessage(Packet.encodeFlight(many)) else {
            fatalError("capped flight batch did not decode")
        }
        assert(capped.count == 48 && capped.first?.sequence == 12 && capped.last?.sequence == 59,
               "flight cap kept the wrong end")
        // A count byte that disagrees with the body is refused.
        assert(Packet.decodeMessage(Data([12, 2, 0, 0, 0, 0, 1])) == nil, "short flight accepted")
        assert(Packet.decodeMessage(Data([12, 1] + [UInt8](repeating: 0, count: 10))) == nil,
               "overlong flight accepted")
        assert(Packet.decodeMessage(Data([12, 49] + [UInt8](repeating: 0, count: 245))) == nil,
               "oversized flight count accepted")

        // Control. These decode into injected mouse events on somebody else's
        // Mac, so the refusals below matter more than the round trips above.
        guard case .input(let buttons, let ix, let iy)? =
                Packet.decodeMessage(Packet.encodeInput(buttons: 3, x: 0.25, y: 0.75)) else {
            fatalError("input did not decode")
        }
        assert(buttons == 3, "input buttons round trip")
        assert(abs(ix - 0.25) < 0.0001 && abs(iy - 0.75) < 0.0001, "input position round trip")

        // An off-screen coordinate is what confines a click to the shared
        // screen; encode clamps it and decode refuses it outright.
        guard case .input(_, let clampedX, let clampedY)? =
                Packet.decodeMessage(Packet.encodeInput(buttons: 1, x: -2, y: 9)) else {
            fatalError("clamped input did not decode")
        }
        assert(clampedX == 0 && clampedY == 1, "input position was not clamped")
        assert(Packet.decodeMessage(Data([14, 1, 0x7F, 0xC0, 0, 0, 0, 0, 0, 0]) as Data) == nil,
               "input at NaN accepted")
        assert(Packet.decodeMessage(Data([14, 1, 0x3F, 0x80, 0, 1, 0, 0, 0, 0])) == nil,
               "input off the unit square accepted")
        // Unknown button bits mean something we do not understand, from a peer
        // holding the presenter's mouse.
        assert(Packet.decodeMessage(Data([14, 4] + [UInt8](repeating: 0, count: 8))) == nil,
               "input with unknown buttons accepted")
        assert(Packet.decodeMessage(Data([14, 1, 0, 0, 0])) == nil, "short input accepted")
        assert(Packet.decodeMessage(Data([14] + [UInt8](repeating: 0, count: 8))) == nil,
               "one-byte-short input accepted")
        assert(Packet.decodeMessage(Data([14] + [UInt8](repeating: 0, count: 10))) == nil,
               "overlong input accepted")

        guard case .scroll(let dx, let dy)? =
                Packet.decodeMessage(Packet.encodeScroll(dx: -40, dy: 300)) else {
            fatalError("scroll did not decode")
        }
        assert(dx == -40 && dy == 300, "scroll deltas round trip, signed")
        assert(Packet.decodeMessage(Data([15, 0, 0, 0])) == nil, "short scroll accepted")
        assert(Packet.decodeMessage(Data([15, 0, 0, 0, 0, 0])) == nil, "overlong scroll accepted")

        guard case .requestControl? = Packet.decodeMessage(Packet.requestControlMessage) else {
            fatalError("control request did not decode")
        }
        assert(Packet.decodeMessage(Data([16, 0])) == nil, "overlong control request accepted")

        guard case .controlGranted(true)? =
                Packet.decodeMessage(Packet.encodeControlGranted(true)) else {
            fatalError("control grant did not decode")
        }
        guard case .controlGranted(false)? =
                Packet.decodeMessage(Packet.encodeControlGranted(false)) else {
            fatalError("control revoke did not decode")
        }
        assert(Packet.decodeMessage(Data([17, 2])) == nil, "control grant with a junk flag accepted")
        assert(Packet.decodeMessage(Data([17])) == nil, "short control grant accepted")
        assert(Packet.decodeMessage(Data([17, 1, 0])) == nil, "overlong control grant accepted")

        for kind in Packet.SystemGesture.allCases {
            guard case .systemGesture(let back)? =
                    Packet.decodeMessage(Packet.encodeSystemGesture(kind)) else {
                fatalError("system gesture \(kind) did not decode")
            }
            assert(back == kind, "system gesture round trip")
        }
        assert(Packet.decodeMessage(Data([18, 99])) == nil, "unknown system gesture accepted")
        assert(Packet.decodeMessage(Data([18])) == nil, "short system gesture accepted")
        assert(Packet.decodeMessage(Data([18, 0, 0])) == nil, "overlong system gesture accepted")

        // Nothing is allocated past 18 yet, and an unknown id must not be
        // mistaken for the nearest one that happens to be the right length.
        assert(Packet.decodeMessage(Data([19, 1])) == nil, "unallocated message id accepted")

        print("packet checks passed")
    }
}
