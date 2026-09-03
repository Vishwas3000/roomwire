import Foundation

/// One H.264 access unit on the wire.
///
///   [0]      flags, bit0 = keyframe (also the message type: video is 0 or 1)
///   [1..4]   sender's steady clock when it was sent, milliseconds (big endian)
///   [5]      marker: bit0 = an LTR token follows, bit1 = recovery frame — it
///            restarts a broken chain, so a viewer that saw a gap may decode it
///            bit2 = nothing depends on this frame (temporal enhancement
///            layer), so losing it costs only itself
///   [6..13]  LTR acknowledgement token (big endian, only when marker bit0)
///   [next 2] sequence number (big endian, wraps) — every frame, so the
///            viewer can measure real loss
///   [next 2] base sequence (big endian, wraps) — counts only frames others
///            depend on. A hole *here* is what breaks decoding; a hole in the
///            sequence above with this one intact lost nothing that mattered
///   [...]    SPS length (4 bytes, big endian, 0 = absent)
///   [...]    SPS
///   [...]    PPS length (4 bytes, big endian, 0 = absent)
///   [...]    PPS
///   [...]    AVCC payload (4-byte length-prefixed NAL units)
///
/// Parameter sets ride along with every keyframe so a viewer who joins late
/// can start decoding from the next keyframe without any handshake.
public enum Packet {
    /// One frame's fate on a viewer, five bytes on the wire.
    public struct FlightRecord: Equatable {
        /// What became of the frame. Shown and skipped come from the pacer;
        /// gap-dropped frames never reached it (their lateness reads 0x7FFF).
        public static let shown: UInt8 = 1
        public static let skipped: UInt8 = 2
        public static let gapDropped: UInt8 = 4
        public static let keyframe: UInt8 = 8
        public static let recovery: UInt8 = 16

        public let sequence: UInt16
        public let latenessMs: Int16
        public let flags: UInt8

        public init(sequence: UInt16, latenessMs: Int16, flags: UInt8) {
            self.sequence = sequence; self.latenessMs = latenessMs; self.flags = flags
        }
    }

    /// One moment in the pointer probe, eleven bytes on the wire. Either a
    /// position arriving off the network or one actually drawn on glass —
    /// the two timelines whose difference is the whole question.
    public struct ProbeSample: Equatable {
        /// True: drawn this display frame. False: arrived in a packet.
        public let drawn: Bool
        /// The viewer's own clock, milliseconds since its first sample. One
        /// timeline across every batch, so they stitch back together.
        public let ms: UInt32
        /// Normalized within the watched screen, as sent.
        public let x: Double
        public let y: Double
        /// The cursor packet this reflects — ties a drawn frame back to the
        /// position it was chasing.
        public let seq: UInt16

        public init(drawn: Bool, ms: UInt32, x: Double, y: Double, seq: UInt16) {
            self.drawn = drawn; self.ms = ms; self.x = x; self.y = y; self.seq = seq
        }
    }

    public struct Decoded {
        public let keyframe: Bool
        /// The sender's steady clock at the moment of sending, wrapped to 32
        /// bits. Meaningless across machines on its own — the viewer anchors it
        /// against its own clock to tell an on-schedule frame from a stale one.
        public let sentMs: UInt32
        /// This frame restarts a broken chain — the first one encoded after a
        /// refresh or keyframe request — so a viewer sitting on a sequence gap
        /// may decode it even though frames before it never came.
        public let recovery: Bool
        /// Counts every frame the encoder emitted for this screen. A hole
        /// means loss (the host dropping under pressure today; the radio, once
        /// deltas ride unreliable sends).
        public let sequence: UInt16
        /// Counts only the frames others are built on. A hole here is what
        /// actually breaks decoding — a hole in `sequence` with this one
        /// unbroken lost an enhancement frame and nothing else.
        public let baseSequence: UInt16
        /// Nothing references this frame, so losing it costs only itself.
        public let droppable: Bool
        /// Set when the encoder marked this frame a long-term reference. The
        /// viewer echoes it back once the frame has decoded, and recovery can
        /// then be a small P-frame against it instead of a keyframe.
        public let ltrToken: UInt64?
        public let sps: Data?
        public let pps: Data?
        public let payload: Data
    }

    /// What a viewer can mark on the screen they are watching.
    public enum Mark: UInt8 {
        case point = 0   // pointer moved here
        case draw = 1    // stroke point, joins the one before it
        case lift = 2    // pointer lifted or stroke finished
        case clear = 3   // take back everything this viewer drew
    }

    /// A viewer's one-tap answer back to the presenter.
    public enum Reaction: UInt8, CaseIterable {
        case hand = 0, yes = 1, no = 2, tooSmall = 3
    }

    /// The three-finger swipes a Mac trackpad already means something by. They
    /// travel as intentions rather than as the keystrokes they become, because
    /// what a Mac does with three fingers is the Mac's business — the phone
    /// only reports the hand.
    public enum SystemGesture: UInt8, CaseIterable {
        case missionControl = 0, appWindows = 1, spaceLeft = 2, spaceRight = 3
    }

    /// The keys that produce no text, and therefore cannot ride in `typeText`.
    ///
    /// Deliberately short. Everything a person types is characters and goes as
    /// text; this is only the keys that *do* something rather than insert
    /// something. Adding a full keycode table would mean shipping a keymap and
    /// agreeing on one across two platforms, to gain keys a phone has no way to
    /// press.
    public enum Key: UInt8, CaseIterable {
        case backspace = 0, enter = 1, tab = 2, escape = 3
        case left = 4, right = 5, up = 6, down = 7
    }

    /// Everything either end can receive. Byte 0 tells them apart:
    /// 0/1 video (bit0 = keyframe), 2 pointer position, 3 pointer gone,
    /// 4 a viewer's mark, 5 that mark relayed to the other viewers,
    /// 6 a reaction, 7 a viewer's own count of what reached it, 8 a viewer
    /// asking for a keyframe, 9 the presenter asking this screen to identify
    /// itself, 10 a viewer confirming it decoded a long-term reference, 11 a
    /// viewer that saw a sequence gap asking for a cheap recovery frame, 12 a
    /// viewer's per-frame flight records for the last second, 13 the pointer
    /// probe's paired timelines, 14 a controlling viewer's pointer, 15 its
    /// scrolling, 16 a viewer asking for control, 17 the presenter's answer.
    ///
    /// Coordinates are always normalized within the watched screen, so they
    /// survive any difference in resolution or zoom between the two ends.
    ///
    /// The pointer is not baked into the video. It rides these tiny messages at
    /// 60 Hz so it stays fluid when frames lag, and is drawn by the viewer.
    public enum Message {
        case video(Decoded)
        /// seq: rejects a stale or reordered packet — unlike video this rides
        /// unreliable delivery, so packets can arrive out of order.
        /// sentMs: the host's steady clock when the pointer was *sampled*.
        /// The pump is regular to within a millisecond but arrival is not, so
        /// this is what lets the viewer replay the motion on the clock it was
        /// made on rather than the clock it happened to reach the phone on.
        case cursor(seq: UInt16, sentMs: UInt32, x: Double, y: Double)
        case cursorHidden(seq: UInt16)
        case mark(kind: Mark, x: Double, y: Double)                     // viewer -> host
        case relayedMark(slot: UInt8, kind: Mark, x: Double, y: Double) // host -> viewers
        case reaction(Reaction)                                         // viewer -> host
        /// Counts are cumulative since the viewer joined — the host holds
        /// what it sent, so comparing the two measures loss instead of
        /// guessing at it. The gaps are the last second's arrival spacing on
        /// the viewer: how the link felt, which a count alone cannot show.
        /// skipped = frames its pacer decoded but did not show, cumulative.
        /// gapDropped = frames lost to a sequence hole, cumulative — real
        /// loss the host's own send-backlog counter cannot see for itself.
        case telemetry(frames: Int, kilobytes: Int, maxGapMs: Int, p95GapMs: Int,
                       skipped: Int, gapDropped: Int)                   // viewer -> host
        /// Nothing decodes until the next keyframe, and they are no longer sent
        /// on a timer, so a viewer whose decoder has failed has to say so.
        case needKeyframe                                               // viewer -> host
        /// The presenter tapped this screen on the plan view. Which phone in
        /// the room is showing it is otherwise guesswork.
        case identify                                                   // host -> viewer
        /// This long-term reference decoded here; the encoder may now lean on
        /// it for cheap recovery.
        case ackReference(token: UInt64)                                // viewer -> host
        /// Frames went missing but nothing was flushed: a recovery frame
        /// against a reference this viewer still holds is enough. A flushed
        /// decoder asks for a keyframe (8) instead — its references are gone.
        case needRefresh                                                // viewer -> host
        /// The last second, frame by frame: what arrived, how late against
        /// the sender's clock, and what became of it. The host writes these
        /// into the session's flight file, where a hiccup's period and phase
        /// can be read instead of guessed at.
        case flight(records: [FlightRecord])                            // viewer -> host
        /// Dev-only, off unless DP_CURSOR_PROBE is set at both ends. The host
        /// drives the pointer along a known circle instead of sampling the
        /// mouse; the viewer reports back both what arrived and what it drew,
        /// frame by frame, so the two timelines can be laid against the
        /// circle they were supposed to trace. See CursorProbe.swift.
        case probe(samples: [ProbeSample])                              // viewer -> host
        /// A controlling viewer's pointer. `buttons` is the *whole state* —
        /// bit0 left, bit1 right — not a click, so a message lost or arriving
        /// out of order is corrected by the next one rather than leaving a
        /// button held down on the presenter's Mac forever. See Control.swift.
        case input(buttons: UInt8, x: Double, y: Double)                // viewer -> host
        /// Pixel deltas, as a finger on glass describes them.
        case scroll(dx: Int16, dy: Int16)                               // viewer -> host
        /// A viewer asking for the pointer. The presenter answers, or does
        /// not — nothing a viewer sends can grant this to itself.
        case requestControl                                             // viewer -> host
        /// Granted or taken away. Sent on every change, including the
        /// automatic ones: leaving, being moved to another screen, or the
        /// presenter simply touching their own mouse.
        case controlGranted(Bool)                                       // host -> viewer
        /// Three fingers, meaning what they mean on a trackpad.
        case systemGesture(SystemGesture)                               // viewer -> host
        /// Text for the presenter's Mac to type, exactly as given.
        ///
        /// Characters rather than keystrokes, because that is what the sender
        /// actually has: a phone's soft keyboard reports what was composed, not
        /// which keys were pressed, and for most of the world's scripts those
        /// are not the same question. macOS types a string directly, so no
        /// keymap has to be agreed on or shipped. Non-empty, and at most
        /// `maxTextBytes` of UTF-8 — the sender splits anything longer on a
        /// character boundary.
        case typeText(String)                                           // viewer -> host
        /// A key that does something rather than inserting something.
        case key(Key)                                                   // viewer -> host
        /// The first frame on the control lane, within five seconds of TLS
        /// coming up.
        ///
        /// `commitment` is SHA-256 of a token the viewer has *not* sent yet.
        /// That ordering is the whole point and it is what makes six characters
        /// enough — see `Pairing.code`. The token itself arrives later, in
        /// `reveal`, and the host tears the connection down if it does not hash
        /// to this.
        ///
        /// The token is **not** an identity and nothing may be keyed on it. It
        /// is a fresh random per attempt whose only job is to be committed to
        /// and then revealed. What identifies a peer is
        /// SHA-256 of its certificate, which is the only thing TLS actually
        /// proved anything about.
        ///
        /// `udpPort` is where the viewer is already listening for the media
        /// lane: the host dials it, so no viewer ever needs a listener the host
        /// can find. Port 0 dials nowhere and is refused. The name is 1…63
        /// bytes of UTF-8, shown to the presenter when asked to approve; more
        /// than that is truncated on the way out and refused on the way in.
        case hello(commitment: Data, udpPort: UInt16, name: String)     // viewer -> host
        /// The host's answer, sent only once the viewer is approved: where the
        /// host's own end of the media lane sits, a **fresh 32-byte key per
        /// session**, and the SHA-256 of the host's own certificate.
        ///
        /// Fresh per session, and never cached against a remembered viewer. A
        /// key that outlives its control connection is a key used twice with
        /// counters that restart at 1 — the same keystream over two different
        /// frames, which XORs to plaintext, and the Poly1305 block with it, so
        /// it is forgery and not merely disclosure. An attacker who can reset
        /// the cleartext TCP connection chooses when that happens, and a phone
        /// going to sleep does it unprompted. So: minted in every `welcome`,
        /// destroyed when the control lane closes.
        ///
        /// `hostFingerprint` is a cross-check and not a source. The viewer
        /// already has the host's fingerprint from the TLS handshake — it needs
        /// it before this message arrives, to show the pairing code while
        /// approval is still pending — so this field must be *compared* against
        /// that and the session torn down if it differs. Adopting the value
        /// from here would be trusting the thing being checked.
        case welcome(udpPort: UInt16, mediaKey: Data, hostFingerprint: Data) // host -> viewer
        /// Sixteen fresh bytes from the host, sent before approval so the
        /// viewer can show the code while the presenter is still deciding.
        ///
        /// This is the host's half of the pairing code, and it arrives after
        /// the viewer has already committed. Without it the code is a value one
        /// side gets to choose last, which is not a comparison of anything.
        case hostNonce(Data)                                            // host -> viewer
        /// The token `hello` committed to. The host hashes it, checks it
        /// against the commitment, and closes on a mismatch.
        case reveal(token: UUID)                                        // viewer -> host
    }

    /// The most a display name may occupy on the wire, in UTF-8 bytes.
    public static let maxNameBytes = 63
    /// One byte carries the length, so 255 is the ceiling the format gives.
    /// Typing is not bulk transfer; a burst longer than this is several
    /// messages, split by the sender where a character ends.
    public static let maxTextBytes = 255

    public static func decodeMessage(_ data: Data) -> Message? {
        switch data.first {
        case 0, 1:
            return decode(data).map(Message.video)
        case 2:
            let b = [UInt8](data)
            guard b.count == 15, let point = point(b, 7) else { return nil }
            return .cursor(seq: be16(b, 1), sentMs: be32(b, 3), x: point.x, y: point.y)
        case 3:
            let b = [UInt8](data)
            guard b.count == 3 else { return nil }
            return .cursorHidden(seq: be16(b, 1))
        case 4:
            let b = [UInt8](data)
            guard b.count == 10, let kind = Mark(rawValue: b[1]),
                  let point = point(b, 2) else { return nil }
            return .mark(kind: kind, x: point.x, y: point.y)
        case 5:
            let b = [UInt8](data)
            guard b.count == 11, let kind = Mark(rawValue: b[2]),
                  let point = point(b, 3) else { return nil }
            return .relayedMark(slot: b[1], kind: kind, x: point.x, y: point.y)
        case 6:
            let b = [UInt8](data)
            guard b.count == 2, let reaction = Reaction(rawValue: b[1]) else { return nil }
            return .reaction(reaction)
        case 7:
            let b = [UInt8](data)
            guard b.count == 21 else { return nil }
            return .telemetry(frames: Int(be32(b, 1)), kilobytes: Int(be32(b, 5)),
                              maxGapMs: Int(be16(b, 9)), p95GapMs: Int(be16(b, 11)),
                              skipped: Int(be32(b, 13)), gapDropped: Int(be32(b, 17)))
        case 8:
            return data.count == 1 ? .needKeyframe : nil
        case 9:
            return data.count == 1 ? .identify : nil
        case 10:
            let b = [UInt8](data)
            guard b.count == 9 else { return nil }
            return .ackReference(token: be64(b, 1))
        case 11:
            return data.count == 1 ? .needRefresh : nil
        case 12:
            let b = [UInt8](data)
            guard b.count >= 2, b[1] <= 48, b.count == 2 + Int(b[1]) * 5 else { return nil }
            var records: [FlightRecord] = []
            for i in 0 ..< Int(b[1]) {
                let o = 2 + i * 5
                records.append(FlightRecord(sequence: be16(b, o),
                                            latenessMs: Int16(bitPattern: be16(b, o + 2)),
                                            flags: b[o + 4]))
            }
            return .flight(records: records)
        case 13:
            let b = [UInt8](data)
            guard b.count >= 2, b[1] <= 64, b.count == 2 + Int(b[1]) * 11 else { return nil }
            var samples: [ProbeSample] = []
            for i in 0 ..< Int(b[1]) {
                let o = 2 + i * 11
                guard b[o] <= 1 else { return nil }
                samples.append(ProbeSample(drawn: b[o] == 0, ms: be32(b, o + 1),
                                           x: Double(be16(b, o + 5)) / 65535,
                                           y: Double(be16(b, o + 7)) / 65535,
                                           seq: be16(b, o + 9)))
            }
            return .probe(samples: samples)
        case 14:
            let b = [UInt8](data)
            // Unknown button bits are refused rather than masked off: a peer
            // that means something we do not understand is not one to guess at
            // while holding the presenter's mouse.
            guard b.count == 10, b[1] <= 3, let point = point(b, 2) else { return nil }
            return .input(buttons: b[1], x: point.x, y: point.y)
        case 15:
            let b = [UInt8](data)
            guard b.count == 5 else { return nil }
            return .scroll(dx: Int16(bitPattern: be16(b, 1)), dy: Int16(bitPattern: be16(b, 3)))
        case 16:
            return data.count == 1 ? .requestControl : nil
        case 17:
            let b = [UInt8](data)
            guard b.count == 2, b[1] <= 1 else { return nil }
            return .controlGranted(b[1] == 1)
        case 18:
            let b = [UInt8](data)
            guard b.count == 2, let kind = SystemGesture(rawValue: b[1]) else { return nil }
            return .systemGesture(kind)
        case 19:
            let b = [UInt8](data)
            // The name length is a byte the peer wrote; the frame must be
            // exactly what it claims, the port must dial somewhere, and the
            // name must be text — a byte sequence that is not UTF-8 is not a
            // name we can show anyone.
            guard b.count >= 36, (1 ... maxNameBytes).contains(Int(b[35])),
                  b.count == 36 + Int(b[35]) else { return nil }
            let port = be16(b, 33)
            guard port != 0, let name = String(validating: b[36...], as: UTF8.self) else { return nil }
            return .hello(commitment: Data(b[1 ..< 33]), udpPort: port, name: name)
        case 20:
            let b = [UInt8](data)
            guard b.count == 67 else { return nil }
            let port = be16(b, 1)
            guard port != 0 else { return nil }
            return .welcome(udpPort: port, mediaKey: Data(b[3 ..< 35]), hostFingerprint: Data(b[35 ..< 67]))
        case 23:
            let b = [UInt8](data)
            // Same shape as a name, and refused the same way: the frame must be
            // exactly the length it claims, and bytes that are not UTF-8 are
            // not text anyone can type.
            guard b.count >= 3, (1 ... maxTextBytes).contains(Int(b[1])),
                  b.count == 2 + Int(b[1]),
                  let text = String(validating: b[2...], as: UTF8.self) else { return nil }
            return .typeText(text)
        case 24:
            let b = [UInt8](data)
            guard b.count == 2, let which = Key(rawValue: b[1]) else { return nil }
            return .key(which)
        case 21:
            let b = [UInt8](data)
            guard b.count == 17 else { return nil }
            return .hostNonce(Data(b[1 ..< 17]))
        case 22:
            let b = [UInt8](data)
            guard b.count == 17 else { return nil }
            return .reveal(token: uuid(b, 1))
        default:
            return nil
        }
    }

    /// `commitment` is 32 bytes — `Pairing.commitment(for:)` makes one. The
    /// name is cut to `maxNameBytes` of UTF-8 on a scalar boundary, so a long
    /// name loses its tail rather than the whole hello being refused at the far
    /// end. An empty name reads as "?": the format needs one byte.
    public static func encodeHello(commitment: Data, udpPort: UInt16, name: String) -> Data {
        precondition(commitment.count == 32, "a commitment is SHA-256, which is 32 bytes")
        var out = Data([19])
        out += commitment
        out.appendBE16(udpPort)
        let name = nameBytes(name)
        out.append(UInt8(name.count))
        out.append(contentsOf: name)
        return out
    }

    /// Sixteen bytes, and they must be fresh for every viewer that connects.
    public static func encodeHostNonce(_ nonce: Data) -> Data {
        precondition(nonce.count == 16, "a host nonce is 16 bytes")
        return Data([21]) + nonce
    }

    public static func encodeReveal(token: UUID) -> Data {
        var out = Data([22])
        out.append(contentsOf: withUnsafeBytes(of: token.uuid) { [UInt8]($0) })
        return out
    }

    /// Sixteen bytes at `o` as a UUID, in RFC 4122 order — the same bytes its
    /// string form spells.
    static func uuid(_ b: [UInt8], _ o: Int) -> UUID {
        Data(b[o ..< o + 16]).withUnsafeBytes { UUID(uuid: $0.load(as: uuid_t.self)) }
    }

    /// `mediaKey` and `hostFingerprint` are 32 bytes each; anything else is a
    /// programming error at the host, not network input, and traps.
    public static func encodeWelcome(udpPort: UInt16, mediaKey: Data, hostFingerprint: Data) -> Data {
        precondition(mediaKey.count == 32 && hostFingerprint.count == 32, "welcome carries two 32-byte values")
        var out = Data([20])
        out.appendBE16(udpPort)
        out += mediaKey
        out += hostFingerprint
        return out
    }

    /// The display-name rule, and it lives here because the wire has one rule
    /// and two ends have to obey it.
    ///
    /// `hello` carries a name as 1…63 bytes of UTF-8, so a name that does not
    /// fit in 63 bytes is not a name RoomWire can send at all. A platform's own
    /// idea of a device name is no help: a Mac's is a `String` of any length,
    /// and forty *characters* of it can be a hundred and sixty bytes. So this is
    /// where a name is made to fit — trimmed, then whole code points dropped
    /// from the end until the UTF-8 fits.
    ///
    /// Whole code points, never a cut inside one. A truncation that lands in
    /// the middle of a multi-byte character produces bytes the far end must
    /// refuse, which turns a long name into a refused connection; on the JVM it
    /// produces a lone surrogate, which encodes as `?` or U+FFFD depending on
    /// who does it. Dropping the whole character is the only answer both
    /// languages can give.
    ///
    /// The trimmed set is spelled out rather than taken from either platform's
    /// notion of whitespace, because those differ — Foundation counts U+00A0 as
    /// whitespace and `java.lang.Character` does not, and a contract cannot
    /// have two answers.
    ///
    /// A name that is empty after trimming reads as `?`. The format needs at
    /// least one byte, and a blank line where a device name should be is worse
    /// to look at than a placeholder.
    ///
    /// An app is free to show a shorter limit in its text field — "40
    /// characters" reads better to a person than "63 bytes" — but that is a
    /// hint to a typist. This is the rule.
    public static func clampName(_ name: String) -> String {
        let trimmed = name.trimmingCharacters(in: whitespace)
        var out = "", bytes = 0
        for scalar in trimmed.unicodeScalars {
            let width = String(scalar).utf8.count
            if bytes + width > maxNameBytes { break }
            out.unicodeScalars.append(scalar)
            bytes += width
        }
        return out.isEmpty ? "?" : out
    }

    /// Space, tab, newline, carriage return, vertical tab, form feed. Nothing else.
    static let whitespace = CharacterSet(charactersIn: " \t\n\r\u{0B}\u{0C}")

    static func nameBytes(_ name: String) -> [UInt8] { Array(clampName(name).utf8) }

    /// Two big-endian floats at `o`. Network input: a hostile coordinate would
    /// park a layer at infinity, so anything off the unit square is refused.
    private static func point(_ b: [UInt8], _ o: Int) -> (x: Double, y: Double)? {
        let x = Float(bitPattern: be32(b, o))
        let y = Float(bitPattern: be32(b, o + 4))
        guard x.isFinite, y.isFinite, (0 ... 1).contains(x), (0 ... 1).contains(y) else { return nil }
        return (Double(x), Double(y))
    }

    public static func encodeMark(_ kind: Mark, x: Double, y: Double) -> Data {
        var out = Data([4, kind.rawValue])
        out.appendPoint(x, y)
        return out
    }

    public static func encodeRelayedMark(slot: UInt8, kind: Mark, x: Double, y: Double) -> Data {
        var out = Data([5, slot, kind.rawValue])
        out.appendPoint(x, y)
        return out
    }

    public static func encodeReaction(_ reaction: Reaction) -> Data {
        Data([6, reaction.rawValue])
    }

    /// Kilobytes rather than bytes: a 32-bit count of bytes runs out after
    /// about two hours at 4 Mbit/s, which is shorter than a long meeting.
    public static func encodeTelemetry(frames: Int, kilobytes: Int, maxGapMs: Int, p95GapMs: Int,
                                skipped: Int, gapDropped: Int) -> Data {
        var out = Data([7])
        out.appendBE(UInt32(clamping: frames))
        out.appendBE(UInt32(clamping: kilobytes))
        out.appendBE16(UInt16(clamping: maxGapMs))
        out.appendBE16(UInt16(clamping: p95GapMs))
        out.appendBE(UInt32(clamping: skipped))
        out.appendBE(UInt32(clamping: gapDropped))
        return out
    }

    public static func encodeCursor(seq: UInt16, sentMs: UInt32, x: Double, y: Double) -> Data {
        var out = Data([2])
        out.appendBE16(seq)
        out.appendBE(sentMs)
        out.appendPoint(x, y)
        return out
    }

    public static func encodeCursorHidden(seq: UInt16) -> Data {
        var out = Data([3])
        out.appendBE16(seq)
        return out
    }

    public static func encodeAckReference(token: UInt64) -> Data {
        var out = Data([10])
        out.appendBE64(token)
        return out
    }

    public static let needKeyframeMessage = Data([8])
    public static let needRefreshMessage = Data([11])

    /// At 30 fps a second is ~30 records; 48 leaves room for a burst. More
    /// than that and the oldest go — the analysis wants texture, not bulk.
    public static func encodeFlight(_ records: [FlightRecord]) -> Data {
        let kept = records.suffix(48)
        var out = Data([12, UInt8(kept.count)])
        for r in kept {
            out.appendBE16(r.sequence)
            out.appendBE16(UInt16(bitPattern: r.latenessMs))
            out.append(r.flags)
        }
        return out
    }
    /// Positions are normalized, so 16 bits of fixed point resolves finer
    /// than any screen — and keeps a sample at eleven bytes.
    public static func encodeProbe(_ samples: [ProbeSample]) -> Data {
        let kept = samples.prefix(64)
        var out = Data([13, UInt8(kept.count)])
        for s in kept {
            out.append(s.drawn ? 0 : 1)
            out.appendBE(s.ms)
            out.appendBE16(quantized(s.x))
            out.appendBE16(quantized(s.y))
            out.appendBE16(s.seq)
        }
        return out
    }

    /// A normalized coordinate as 16-bit fixed point.
    ///
    /// The NaN test is doing real work, and only NaN needs it. Clamping does
    /// not remove NaN: `min` and `max` return the other operand only when a
    /// comparison is true, and every comparison with NaN is false, so a NaN
    /// walks through both untouched. `Int(Double.nan)` then traps.
    ///
    /// This is the only place in the file that turns a coordinate into an
    /// integer — everywhere else a hostile Double becomes a harmless bit
    /// pattern that the far end refuses. A probe sample is diagnostics, and
    /// diagnostics do not get to take the app down, so NaN reads as zero.
    ///
    /// Testing `isFinite` here instead would be the tempting version and it is
    /// wrong: it also catches the infinities, which the clamp already handles
    /// correctly — max(+inf, 0) is +inf and min(+inf, 1) is 1 — and would send
    /// a pointer at the far right edge as one at the far left.
    private static func quantized(_ v: Double) -> UInt16 {
        guard !v.isNaN else { return 0 }
        return UInt16(clamping: Int((Swift.min(Swift.max(v, 0), 1) * 65535).rounded()))
    }

    /// Reuses `appendPoint`'s clamp and `point`'s refusal of anything off the
    /// unit square. That guard was written so a hostile coordinate could not
    /// park a layer at infinity; it now also confines an injected click to the
    /// screen actually being shared, which is a good deal more load-bearing.
    public static func encodeInput(buttons: UInt8, x: Double, y: Double) -> Data {
        var out = Data([14, buttons & 3])
        out.appendPoint(x, y)
        return out
    }

    public static func encodeScroll(dx: Int16, dy: Int16) -> Data {
        var out = Data([15])
        out.appendBE16(UInt16(bitPattern: dx))
        out.appendBE16(UInt16(bitPattern: dy))
        return out
    }

    public static let requestControlMessage = Data([16])

    public static func encodeControlGranted(_ granted: Bool) -> Data {
        Data([17, granted ? 1 : 0])
    }

    public static func encodeSystemGesture(_ kind: SystemGesture) -> Data {
        Data([18, kind.rawValue])
    }

    /// nil for text that will not fit or is empty, so a caller cannot put a
    /// frame on the wire that the far end is obliged to refuse.
    public static func encodeTypeText(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard (1 ... maxTextBytes).contains(bytes.count) else { return nil }
        return Data([23, UInt8(bytes.count)] + bytes)
    }

    public static func encodeKey(_ which: Key) -> Data {
        Data([24, which.rawValue])
    }

    public static let identifyMessage = Data([9])

    public static func encode(payload: Data, sps: Data?, pps: Data?, keyframe: Bool, recovery: Bool = false,
                       droppable: Bool = false, sentMs: UInt32, sequence: UInt16,
                       baseSequence: UInt16, ltrToken: UInt64? = nil) -> Data {
        var out = Data([keyframe ? 1 : 0])
        out.appendBE(sentMs)
        var marker: UInt8 = recovery ? 2 : 0
        if ltrToken != nil { marker |= 1 }
        if droppable { marker |= 4 }
        out.append(marker)
        if let ltrToken { out.appendBE64(ltrToken) }
        out.appendBE16(sequence)
        out.appendBE16(baseSequence)
        out.appendBE(UInt32(sps?.count ?? 0))
        if let sps { out += sps }
        out.appendBE(UInt32(pps?.count ?? 0))
        if let pps { out += pps }
        out += payload
        return out
    }

    static func be64(_ b: [UInt8], _ o: Int) -> UInt64 {
        UInt64(be32(b, o)) << 32 | UInt64(be32(b, o + 4))
    }

    static func be16(_ b: [UInt8], _ o: Int) -> UInt16 {
        UInt16(b[o]) << 8 | UInt16(b[o + 1])
    }

    static func be32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
    }

    /// Network input — every length is bounds-checked before it is used.
    public static func decode(_ data: Data) -> Decoded? {
        let b = [UInt8](data)
        var o = 1
        guard b.count > 18 else { return nil }
        let sentMs = be32(b, o)
        o += 4
        let marker = b[o]
        o += 1
        guard marker <= 7 else { return nil }   // network input: unknown bits are refused
        var ltrToken: UInt64?
        if marker & 1 == 1 {
            guard o + 8 <= b.count else { return nil }
            ltrToken = be64(b, o)
            o += 8
        }
        guard o + 4 <= b.count else { return nil }
        let sequence = be16(b, o)
        o += 2
        let baseSequence = be16(b, o)
        o += 2

        func length() -> Int? {
            guard o + 4 <= b.count else { return nil }
            defer { o += 4 }
            let v = UInt32(b[o]) << 24 | UInt32(b[o + 1]) << 16 | UInt32(b[o + 2]) << 8 | UInt32(b[o + 3])
            return v <= UInt32(b.count) ? Int(v) : nil
        }

        guard let spsLen = length(), o + spsLen <= b.count else { return nil }
        let sps = spsLen > 0 ? Data(b[o ..< o + spsLen]) : nil
        o += spsLen

        guard let ppsLen = length(), o + ppsLen <= b.count else { return nil }
        let pps = ppsLen > 0 ? Data(b[o ..< o + ppsLen]) : nil
        o += ppsLen

        guard o < b.count else { return nil }
        return Decoded(keyframe: b[0] & 1 == 1, sentMs: sentMs, recovery: marker & 2 == 2,
                       sequence: sequence, baseSequence: baseSequence,
                       droppable: marker & 4 == 4, ltrToken: ltrToken,
                       sps: sps, pps: pps, payload: Data(b[o...]))
    }
}

extension Data {
    mutating func appendPoint(_ x: Double, _ y: Double) {
        // Swift.-qualified: inside an extension on Data, bare min/max resolve to
        // Sequence's own no-argument versions.
        appendBE(Float(Swift.min(Swift.max(x, 0), 1)).bitPattern)
        appendBE(Float(Swift.min(Swift.max(y, 0), 1)).bitPattern)
    }

    mutating func appendBE64(_ v: UInt64) {
        appendBE(UInt32(truncatingIfNeeded: v >> 32))
        appendBE(UInt32(truncatingIfNeeded: v))
    }

    mutating func appendBE16(_ v: UInt16) {
        append(contentsOf: [UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)])
    }

    mutating func appendBE(_ v: UInt32) {
        append(contentsOf: [UInt8(truncatingIfNeeded: v >> 24),
                            UInt8(truncatingIfNeeded: v >> 16),
                            UInt8(truncatingIfNeeded: v >> 8),
                            UInt8(truncatingIfNeeded: v)])
    }
}
