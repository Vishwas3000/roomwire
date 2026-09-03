import CryptoKit
import Foundation

/// The media lane's envelope: ChaCha20-Poly1305 over the body, with the
/// 17-byte header as associated data so a header cannot be re-pointed at
/// another frame without the tag failing.
///
/// Nonce = lane ‖ counter, twelve bytes. Lane 0 is host to viewer, 1 viewer to
/// host, so the two directions never share a nonce under one key; the counter
/// never repeats within a direction; and the key is minted fresh for each
/// viewer in its `welcome`, so two viewers' counters cannot collide either.
public enum MediaSeal {
    public static func nonce(lane: UInt32, counter: UInt64) -> Data {
        var out = Data(capacity: 12)
        out.appendBE(lane)
        out.appendBE64(counter)
        return out
    }

    /// The key is 32 bytes by construction (`welcome` carries exactly that);
    /// anything else is a programming error, not network input, and traps.
    public static func seal(_ h: ChunkHeader.Fields, body: Data, key: SymmetricKey, lane: UInt32) -> Data {
        let header = ChunkHeader.encode(h)
        let nonce = try! ChaChaPoly.Nonce(data: nonce(lane: lane, counter: h.counter))
        let box = try! ChaChaPoly.seal(body, using: key, nonce: nonce, authenticating: header)
        return header + box.ciphertext + box.tag
    }

    /// nil for anything that does not open: too short, too long, a header we
    /// refuse, or a tag that does not match — header, body, key, lane and
    /// counter all have to agree. Nothing says which; a datagram is not owed a
    /// reason.
    public static func open(_ datagram: Data, key: SymmetricKey, lane: UInt32) -> (ChunkHeader.Fields, Data)? {
        guard datagram.count >= ChunkHeader.size + ChunkHeader.tag,
              datagram.count <= ChunkHeader.datagramMax,
              let h = ChunkHeader.decode(datagram) else { return nil }
        let header = datagram.prefix(ChunkHeader.size)
        let ciphertext = datagram.dropFirst(ChunkHeader.size).dropLast(ChunkHeader.tag)
        let tag = datagram.suffix(ChunkHeader.tag)
        guard let nonce = try? ChaChaPoly.Nonce(data: nonce(lane: lane, counter: h.counter)),
              let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
              let body = try? ChaChaPoly.open(box, using: key, authenticating: header) else { return nil }
        return (h, body)
    }
}
