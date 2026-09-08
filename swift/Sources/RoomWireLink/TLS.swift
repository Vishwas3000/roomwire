import CryptoKit
import Foundation
import Network
import RoomWireProtocol
import Security

/// Both ends of the control lane: TLS 1.3 over TCP, self-signed. The host
/// always presents a certificate. A viewer presents one when it has one; a
/// viewer that has none — the iPhone, which links no certificate library —
/// identifies itself with a bare key one message later instead, on a second
/// listener that does not ask. Two listeners rather than one that asks
/// politely, because the API for "request a client certificate but accept not
/// getting one" (`sec_protocol_options_set_peer_authentication_optional`) does
/// not exist on macOS, and the host is a Mac.
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
public enum TLS {
    public static func parameters(identity: sec_identity_t?, requirePeer: Bool, reach: Reach,
                                  queue: DispatchQueue) -> NWParameters {
        let options = NWProtocolTLS.Options()
        let sec = options.securityProtocolOptions
        if let identity { sec_protocol_options_set_local_identity(sec, identity) }
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv13)
        // The certificate listener wants a certificate from the viewer and
        // TLS refuses the connection without one. The key listener never asks,
        // and its viewers prove a key in `revealSigned` instead.
        if requirePeer {
            sec_protocol_options_set_peer_authentication_required(sec, true)
        }
        sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, queue)

        let tcp = NWProtocolTCP.Options()
        // A control message is small and wants to leave now, not when a segment
        // happens to fill.
        tcp.noDelay = true
        let parameters = NWParameters(tls: options, tcp: tcp)
        // See `Reach`: off unless asked for, on the listener, the browser and
        // every dial alike, because one end asking is enough to wake AWDL.
        parameters.includePeerToPeer = reach == .peerToPeer
        return parameters
    }

    /// SHA-256 of the peer's leaf certificate, once the handshake is done.
    /// nil when the peer presented none: for a viewer that is a host to refuse;
    /// for a host it is a viewer on the key listener, which proves a key next.
    public static func peerFingerprint(of connection: NWConnection) -> Data? {
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
}
