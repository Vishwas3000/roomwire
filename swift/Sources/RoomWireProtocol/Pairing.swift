import CryptoKit
import Foundation

/// The six characters both screens show while a new viewer waits to be
/// approved. Each end computes it from the two certificate fingerprints and the
/// two nonces, so a presenter reading the same code off both screens has seen
/// that the TLS connection in front of them is the one the phone in their hand
/// made — not one somebody on the same network completed with each of them
/// separately.
///
/// SHA-256(hostFp ‖ viewerFp ‖ token ‖ hostNonce) in RFC 4648 base32 (A–Z,
/// 2–7), the first six characters. Thirty bits, and no glyph that reads two
/// ways.
///
/// **Guessing it is not the attack, and it is worth spelling out what is.** A
/// machine in the middle holds two TLS connections: one to the Mac, where it
/// plays the viewer, and one to the phone, where it plays the host. It does not
/// have to guess either code — it has to make the two codes *equal*, and if it
/// can choose its own contribution to each after seeing everything else, it can
/// grind for a collision. Both halves are then pure SHA-256 with no
/// certificates needed: on the Mac leg it varies the nonce it sends, and on the
/// phone leg it re-mints its own self-signed certificate, which trust-on-
/// first-use obliges the phone to accept. Two independently steerable 30-bit
/// values meet in the middle at about 2^15 tries each — which measured at 0.05
/// seconds on one core, offline, with both screens then showing the same six
/// characters.
///
/// So neither side is allowed to choose last. The viewer commits first, in
/// `hello`, to SHA-256 of a token it has not sent; the host then sends its
/// nonce; only then does the viewer reveal the token, and the host closes the
/// connection if it does not hash to what was committed. Neither contribution
/// can be chosen in response to the other, which leaves an attacker one
/// 2^-30 shot per attempt instead of a search — and six characters is then
/// genuinely enough.
///
/// A longer code was the obvious alternative and it does not work: resisting a
/// two-sided birthday search needs double the bits, so twelve characters buys
/// 2^30 per side, which is GPU-seconds, and nobody compares twelve characters
/// off two screens. Committing is what short authenticated strings do instead,
/// and it costs two small messages.
public enum Pairing {
    public static func code(hostFingerprint: Data, viewerFingerprint: Data,
                            token: UUID, hostNonce: Data) -> String {
        var input = hostFingerprint + viewerFingerprint
        input.append(contentsOf: withUnsafeBytes(of: token.uuid) { [UInt8]($0) })
        input += hostNonce
        return String(base32([UInt8](SHA256.hash(data: input))).prefix(6))
    }

    /// What `hello` carries in place of the token: SHA-256 of it, 32 bytes.
    public static func commitment(for token: UUID) -> Data {
        Data(SHA256.hash(data: Data(withUnsafeBytes(of: token.uuid) { [UInt8]($0) })))
    }

    /// Whether a revealed token is the one that was committed to. The host
    /// closes the connection when this is false: a viewer that cannot produce
    /// the preimage of its own commitment is either broken or steering.
    public static func opens(commitment: Data, token: UUID) -> Bool {
        commitment.count == 32 && commitment == self.commitment(for: token)
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
