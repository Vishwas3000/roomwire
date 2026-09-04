import CryptoKit
import Foundation

/// The bulk lane's envelope: one AEAD frame per write on an ordered stream.
///
/// The media lane's envelope is next door and this is not it, for reasons worth
/// stating because both of the obvious reuses are wrong.
///
/// **Not `ChunkHeader`.** Its `frameId`, `index` and `count` describe a datagram
/// carved out of a video frame and mean nothing on a stream that cannot lose or
/// reorder anything; its decoder even refuses `count != 1` for non-video. Only
/// the nonce's shape is shared, and that is deliberate: `MediaSeal.nonce` is
/// called directly rather than restated.
///
/// **Not `Framing`.** That decoder does `removeFirst(4 + length)` per frame,
/// an O(n) shift its own comment flags, which at these sizes is the throughput.
/// And its 8 MiB ceiling is the wrong shape here in a way that is easy to miss:
/// an AEAD frame authenticates only once it is *whole*, so the ceiling is how
/// much unverified, attacker-chosen data this process will hold. 256 KiB.
///
/// **Lanes 2 and 3, not 0 and 1.** The media lane owns those. If a media key
/// ever reaches this code by mistake, distinct lane numbers mean the two nonce
/// spaces still cannot collide — the one mistake that turns two ciphertexts
/// into plaintext.
///
/// **The counter is not on the wire.** TCP delivers in order or not at all, so
/// the receiver knows what the counter must be and checks equality. That is
/// stronger than the media lane's replay window — it catches reordering,
/// duplication, dropped frames and splicing, not just replay — and it is one
/// comparison. A counter nobody transmits is a counter nobody can choose.
///
/// **The length is the associated data.** Tampering with it is then caught on
/// the frame it happened to, rather than a frame later when the next read lands
/// mid-ciphertext.
///
/// What none of this defends is **truncation**: an attacker who resets the
/// connection cuts the stream at a frame boundary, and no frame can say it was
/// the last one. TLS has `close_notify` for this; a raw AEAD stream has
/// nothing. That belongs to the layer above, which must not call a transfer
/// complete without the hash that says so. See `Transfer`.
public enum Bulk {
    /// The most file data one frame carries. Large on purpose: JCE allocates a
    /// `Cipher` per call, so small frames spend their time in provider lookups
    /// rather than encryption.
    public static let chunk = 262_144
    /// Room for the message's own fields on top of a full chunk.
    public static let maxPlaintext = chunk + 64
    public static let tag = 16
    /// The 4-byte length prefix is not counted: this is what the length says.
    public static let maxBody = maxPlaintext + tag
    /// One byte of plaintext — a `bye` — plus the tag.
    public static let minBody = 1 + tag

    /// Which direction this end seals on. Never a parameter a caller passes:
    /// two ends sealing the same lane under one key is the whole disaster.
    public enum Lane: UInt32, Sendable {
        case hostToViewer = 2
        case viewerToHost = 3

        public var opposite: Lane { self == .hostToViewer ? .viewerToHost : .hostToViewer }
    }

    /// The outbound half. Owns the counter; hands back a finished frame,
    /// length prefix included.
    public final class Sealer: @unchecked Sendable {
        private let key: SymmetricKey
        private let lane: Lane
        private let lock = NSLock()
        private var counter: UInt64 = 0

        public init(key: SymmetricKey, lane: Lane) {
            self.key = key
            self.lane = lane
        }

        public func seal(_ plaintext: Data) -> Data {
            precondition(!plaintext.isEmpty && plaintext.count <= Bulk.maxPlaintext,
                         "a bulk frame is 1…\(Bulk.maxPlaintext) bytes of plaintext")
            lock.lock()
            counter += 1
            let next = counter
            lock.unlock()
            // A u64 of 256 KiB frames is more data than has ever been written.
            precondition(next != 0, "the bulk lane's counter wrapped")

            var frame = Data(capacity: 4 + plaintext.count + Bulk.tag)
            frame.appendBE(UInt32(plaintext.count + Bulk.tag))
            let box = try! ChaChaPoly.seal(
                plaintext, using: key,
                nonce: try! ChaChaPoly.Nonce(data: MediaSeal.nonce(lane: lane.rawValue, counter: next)),
                authenticating: frame)
            frame += box.ciphertext
            frame += box.tag
            return frame
        }
    }

    /// The inbound half. `nil` is always fatal to the connection — there is no
    /// frame this can refuse and still be speaking to the same peer.
    public final class Opener {
        private let key: SymmetricKey
        private let lane: Lane
        private var expected: UInt64 = 0

        public init(key: SymmetricKey, lane: Lane) {
            self.key = key
            self.lane = lane
        }

        /// `frame` is a whole frame from `Decoder`, length prefix included.
        public func open(_ frame: Data) -> Data? {
            guard frame.count >= 4 + Bulk.minBody, frame.count <= 4 + Bulk.maxBody else { return nil }
            let bytes = [UInt8](frame)
            // The length must describe exactly what arrived. A decoder that
            // agrees is not enough: this is the value being authenticated, so
            // it is checked where it is used.
            guard Int(Packet.be32(bytes, 0)) == frame.count - 4 else { return nil }

            expected += 1
            let head = frame.prefix(4)
            let ciphertext = frame.dropFirst(4).dropLast(Bulk.tag)
            let tag = frame.suffix(Bulk.tag)
            guard let nonce = try? ChaChaPoly.Nonce(
                    data: MediaSeal.nonce(lane: lane.rawValue, counter: expected)),
                  let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
                  let plaintext = try? ChaChaPoly.open(box, using: key, authenticating: head)
            else { return nil }
            return plaintext
        }
    }

    /// Whole frames out of whatever arrived, without copying the tail back to
    /// the front on every one.
    ///
    /// `Framing.Decoder` keeps its buffer packed by shifting; here the read
    /// cursor moves instead and the buffer is compacted only once it has been
    /// consumed. At a few thousand frames a second that is the difference
    /// between a memmove per frame and none.
    public struct Decoder {
        private var buffer = Data()
        private var read = 0

        public init() {}

        /// `nil` means the stream is not speaking this protocol — a length that
        /// could not be one of ours — and the only answer is to close it.
        public mutating func feed(_ bytes: Data) -> [Data]? {
            buffer += bytes
            var out: [Data] = []
            while buffer.count - read >= 4 {
                let start = buffer.startIndex + read
                let length = Int(Packet.be32([UInt8](buffer[start ..< start + 4]), 0))
                guard length >= Bulk.minBody, length <= Bulk.maxBody else { return nil }
                guard buffer.count - read >= 4 + length else { break }
                out.append(Data(buffer[start ..< start + 4 + length]))
                read += 4 + length
            }
            if read == buffer.count {
                buffer.removeAll(keepingCapacity: true)
                read = 0
            } else if read > 0, read >= 1 << 20 {
                // Only once the wasted front is worth a copy.
                buffer = Data(buffer.dropFirst(read))
                read = 0
            }
            return out
        }
    }
}
