import CryptoKit
import Foundation

/// The six characters both screens show while a new viewer waits to be
/// approved. Each end computes it from the two certificate fingerprints and
/// the viewer's token, so a presenter reading the same code off both screens
/// has seen that the TLS connection in front of them is the one the phone in
/// their hand made — not one somebody on the same network completed with each
/// of them separately.
///
/// SHA-256(hostFp ‖ viewerFp ‖ token) in RFC 4648 base32 (A–Z, 2–7), the first
/// six characters: thirty bits, no glyph that reads two ways, and nothing worth
/// guessing at — there is no secret behind it to lock anyone out of.
public enum Pairing {
    public static func code(hostFingerprint: Data, viewerFingerprint: Data, token: UUID) -> String {
        var input = hostFingerprint + viewerFingerprint
        input.append(contentsOf: withUnsafeBytes(of: token.uuid) { [UInt8]($0) })
        return String(base32([UInt8](SHA256.hash(data: input))).prefix(6))
    }

    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    /// RFC 4648 without padding: five bits at a time, high bits first.
    static func base32(_ bytes: [UInt8]) -> String {
        var out = "", acc = 0, bits = 0
        for b in bytes {
            acc = acc << 8 | Int(b)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(acc >> bits) & 31])
            }
            acc &= (1 << bits) - 1
        }
        if bits > 0 { out.append(alphabet[(acc << (5 - bits)) & 31]) }
        return out
    }
}

/// The control lane's frames: `[length u32][bytes]`, length 1…8 MiB. TCP is a
/// byte stream; this is what makes it messages again. The cap is what stops a
/// peer claiming a 4 GB frame and being handed the buffer for it.
public enum Framing {
    public static let maxLength = 8_388_608

    /// An empty message has no frame — the far end would read a zero length as
    /// a broken stream and close — so sending one is a programming error.
    public static func encode(_ message: Data) -> Data {
        precondition(!message.isEmpty && message.count <= maxLength, "a frame is 1…8 MiB")
        var out = Data(capacity: 4 + message.count)
        out.appendBE(UInt32(message.count))
        out += message
        return out
    }

    /// Feed it whatever arrived; get back every complete frame, in order. nil
    /// means the stream is not speaking this protocol — a zero or oversized
    /// length — and the only right answer is to close it.
    public struct Decoder {
        private var buffer: [UInt8] = []

        public init() {}

        public mutating func feed(_ bytes: Data) -> [Data]? {
            buffer.append(contentsOf: bytes)
            var out: [Data] = []
            while buffer.count >= 4 {
                let length = Int(Packet.be32(buffer, 0))
                guard length > 0, length <= Framing.maxLength else { return nil }
                guard buffer.count >= 4 + length else { break }
                out.append(Data(buffer[4 ..< 4 + length]))
                // ponytail: O(n) shift per frame; a ring buffer if the control
                // lane ever carries more than a few frames a second.
                buffer.removeFirst(4 + length)
            }
            return out
        }
    }
}
