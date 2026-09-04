import Foundation

/// What moves over the bulk lane, as bytes. No sockets and no files here —
/// this is the format and the rules, so both ends can be held to the same
/// vectors and neither has to be running to test it.
///
/// A message space of its own, one byte wide, entirely separate from `Packet`.
/// That is the load-bearing decision: an unknown `Packet` id drops the whole
/// session on both ends, so every message that lives here is a message that can
/// never cost a version handshake. The feature costs two `Packet` ids in total,
/// and every transfer feature after it costs none.
public enum Transfer {
    /// How much of a file the offer's hash covers. Whole-file hashing before
    /// the first byte moves would stall a large send for seconds; this is
    /// instant, and the whole-file hash in `done` is computed while streaming.
    public static let headWindow = 65_536
    public static let maxName = 1024
    public static let maxMime = 255

    public enum Reject: UInt8, Sendable, CaseIterable {
        case declined = 0, noSpace = 1, tooBig = 2, busy = 3, gone = 4
    }

    public struct Offer: Equatable, Sendable {
        public let id: UInt16
        public let size: UInt64
        /// The source's modification time. Part of what identifies a partial
        /// file on resume, so a changed original is not silently stitched onto
        /// the bytes of the old one.
        public let mtimeMs: UInt64
        /// SHA-256 of the first `headWindow` bytes, or of the whole file if it
        /// is smaller.
        public let headHash: Data
        /// Paste it rather than saving it.
        public let isClipboard: Bool
        public let name: String
        public let mime: String

        public init(id: UInt16, size: UInt64, mtimeMs: UInt64, headHash: Data,
                    isClipboard: Bool = false, name: String, mime: String) {
            self.id = id
            self.size = size
            self.mtimeMs = mtimeMs
            self.headHash = headHash
            self.isClipboard = isClipboard
            self.name = name
            self.mime = mime
        }
    }

    public enum Frame: Equatable, Sendable {
        case offer(Offer)
        /// The receiver chooses where to resume. The offset appears exactly
        /// once, here, and never on `data` — so no sender can seek a file
        /// handle it does not own.
        case accept(id: UInt16, offset: UInt64)
        case reject(id: UInt16, reason: Reject)
        /// Position is implicit: sequential from what `accept` asked for.
        case data(id: UInt16, bytes: Data)
        /// The whole-file hash. A transfer is complete when this arrives and
        /// the hash matches, and at no other time — it is the only thing
        /// separating "the sender finished" from "somebody cut the connection".
        case done(id: UInt16, sha256: Data)
        case cancel(id: UInt16, reason: Reject)
        /// An orderly close, so its absence means "resume", never "done".
        case bye
    }

    // MARK: - Encoding

    public static func encode(_ frame: Frame) -> Data {
        switch frame {
        case .offer(let o):
            let name = Array(o.name.utf8), mime = Array(o.mime.utf8)
            precondition((1 ... maxName).contains(name.count), "a name is 1…\(maxName) bytes")
            precondition(mime.count <= maxMime, "a mime type is at most \(maxMime) bytes")
            precondition(o.headHash.count == 32, "a head hash is 32 bytes")
            var out = Data([1])
            out.appendBE16(o.id)
            out.appendBE64(o.size)
            out.appendBE64(o.mtimeMs)
            out += o.headHash
            out.append(o.isClipboard ? 1 : 0)
            out.appendBE16(UInt16(name.count))
            out += name
            out.appendBE16(UInt16(mime.count))
            out += mime
            return out
        case .accept(let id, let offset):
            var out = Data([2]); out.appendBE16(id); out.appendBE64(offset); return out
        case .reject(let id, let reason):
            var out = Data([3]); out.appendBE16(id); out.append(reason.rawValue); return out
        case .data(let id, let bytes):
            precondition(!bytes.isEmpty && bytes.count <= Bulk.chunk,
                         "a data frame is 1…\(Bulk.chunk) bytes")
            var out = Data([4]); out.appendBE16(id); out += bytes; return out
        case .done(let id, let sha256):
            precondition(sha256.count == 32, "a file hash is 32 bytes")
            var out = Data([5]); out.appendBE16(id); out += sha256; return out
        case .cancel(let id, let reason):
            var out = Data([6]); out.appendBE16(id); out.append(reason.rawValue); return out
        case .bye:
            return Data([7])
        }
    }

    // MARK: - Decoding

    /// Strict, like everything else on this wire: exact lengths, real UTF-8,
    /// known enum cases. `nil` closes the connection.
    public static func decode(_ plaintext: Data) -> Frame? {
        let b = [UInt8](plaintext)
        guard let kind = b.first else { return nil }
        switch kind {
        case 1:
            guard b.count >= 54 else { return nil }
            let id = be16(b, 1)
            let size = be64(b, 3)
            let mtime = be64(b, 11)
            let head = Data(b[19 ..< 51])
            guard b[51] <= 1 else { return nil }
            let nameLen = Int(be16(b, 52))
            guard (1 ... maxName).contains(nameLen), b.count >= 54 + nameLen + 2 else { return nil }
            guard let name = String(validating: b[54 ..< 54 + nameLen], as: UTF8.self) else { return nil }
            let mimeAt = 54 + nameLen
            let mimeLen = Int(be16(b, mimeAt))
            guard mimeLen <= maxMime, b.count == mimeAt + 2 + mimeLen else { return nil }
            guard let mime = String(validating: b[(mimeAt + 2)...], as: UTF8.self) else { return nil }
            return .offer(Offer(id: id, size: size, mtimeMs: mtime, headHash: head,
                                isClipboard: b[51] == 1, name: name, mime: mime))
        case 2:
            guard b.count == 11 else { return nil }
            return .accept(id: be16(b, 1), offset: be64(b, 3))
        case 3:
            guard b.count == 4, let reason = Reject(rawValue: b[3]) else { return nil }
            return .reject(id: be16(b, 1), reason: reason)
        case 4:
            guard b.count > 3, b.count <= 3 + Bulk.chunk else { return nil }
            return .data(id: be16(b, 1), bytes: Data(b[3...]))
        case 5:
            guard b.count == 35 else { return nil }
            return .done(id: be16(b, 1), sha256: Data(b[3 ..< 35]))
        case 6:
            guard b.count == 4, let reason = Reject(rawValue: b[3]) else { return nil }
            return .cancel(id: be16(b, 1), reason: reason)
        case 7:
            return b.count == 1 ? .bye : nil
        default:
            return nil
        }
    }

    // MARK: - Names

    /// A name safe to join onto a directory.
    ///
    /// `Offer.name` is chosen by the far end, so it is the one field in this
    /// format an attacker fully controls, and the only thing standing between
    /// it and somebody else's filesystem. Everything before the last separator
    /// goes, both separators count, control characters go, and the result is
    /// never empty, `.` or `..` — the three values that make a join mean
    /// something other than "a file in this directory".
    public static func safeName(_ raw: String) -> String {
        let cut = raw.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
        let clean = cut.unicodeScalars
            .filter { !CharacterSet.controlCharacters.contains($0) && $0 != ":" }
            .reduce(into: "") { $0.unicodeScalars.append($1) }
            .trimmingCharacters(in: .whitespaces)
        if clean.isEmpty || clean == "." || clean == ".." { return "received" }
        // Long names are a filesystem problem rather than a security one, but
        // a 1024-byte name is nobody's idea of a filename either.
        return String(clean.prefix(200))
    }

    // MARK: - Readers

    private static func be16(_ b: [UInt8], _ o: Int) -> UInt16 {
        UInt16(b[o]) << 8 | UInt16(b[o + 1])
    }

    private static func be64(_ b: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0 ..< 8 { v = v << 8 | UInt64(b[o + i]) }
        return v
    }
}
