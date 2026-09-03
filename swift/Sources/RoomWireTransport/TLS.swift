import CryptoKit
import Foundation
import Network
import RoomWireProtocol
import Security

/// Both ends of the control lane: TLS 1.3 over TCP, mutual, self-signed at both
/// ends.
///
/// There is no certificate authority and no name to validate against, so the
/// verify block accepts every certificate. That is not a weakened check, it is a
/// different one: nothing about a self-signed certificate can be verified at
/// handshake time, so the decision moves to where the evidence is. The host asks
/// its trust store, or asks the presenter with a pairing code on screen; the
/// viewer compares against what it saw last time. Accepting here and deciding
/// above is trust-on-first-use, and the pairing code is what covers the first
/// time.
///
/// The fingerprint is read afterwards, off the connection's own TLS metadata,
/// and deliberately not out of the verify block. A listener hands the same
/// `NWParameters` to every connection it accepts, so anything the block wrote
/// to would be shared between viewers connecting at once. Metadata belongs to
/// one connection and cannot be confused between two.
enum TLS {
    static func parameters(identity: Identity, requirePeer: Bool, queue: DispatchQueue) -> NWParameters {
        let options = NWProtocolTLS.Options()
        let sec = options.securityProtocolOptions
        sec_protocol_options_set_local_identity(sec, identity.secIdentity)
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv13)
        // The host wants a certificate from the viewer; without one there is
        // nothing to key trust on, and the connection is dropped above.
        if requirePeer {
            sec_protocol_options_set_peer_authentication_required(sec, true)
        }
        sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, queue)

        let tcp = NWProtocolTCP.Options()
        // A control message is small and wants to leave now, not when a segment
        // happens to fill.
        tcp.noDelay = true
        let parameters = NWParameters(tls: options, tcp: tcp)
        // AWDL is how two devices in a room reach each other with no
        // infrastructure at all, and it is off unless this is set — on the
        // listener, on the browser, and on every dial.
        parameters.includePeerToPeer = true
        return parameters
    }

    /// SHA-256 of the peer's leaf certificate, once the handshake is done.
    /// nil when the peer presented none, which for a host is a refusal.
    static func peerFingerprint(of connection: NWConnection) -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
            as? NWProtocolTLS.Metadata else { return nil }
        var leaf: Data?
        sec_protocol_metadata_access_peer_certificate_chain(metadata.securityProtocolMetadata) { certificate in
            guard leaf == nil else { return }   // the leaf comes first; the rest is noise here
            let ref = sec_certificate_copy_ref(certificate).takeRetainedValue()
            leaf = Data(SHA256.hash(data: SecCertificateCopyData(ref) as Data))
        }
        return leaf
    }

    /// UDP, peer-to-peer, no DTLS: the media lane carries its own envelope, so a
    /// second handshake here would buy nothing and cost a round trip.
    static func udp() -> NWParameters {
        let parameters = NWParameters(dtls: nil, udp: NWProtocolUDP.Options())
        parameters.includePeerToPeer = true
        return parameters
    }
}
