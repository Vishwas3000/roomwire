import Crypto
import Foundation
import Network
import Security
import SwiftASN1
import X509

/// This device's TLS identity: a P-256 key and a self-signed certificate,
/// minted once and kept in the keychain.
///
/// There is no certificate authority anywhere in RoomWire and there is not
/// meant to be. Two devices in one room have no third party to appeal to, so
/// each end signs its own certificate and the *fingerprint* is the identity —
/// pinned on first use, checked on every connection after. That is the same
/// trade a phone makes when it pairs over Bluetooth, and it fails in the same
/// place: the very first connection, which is what the six-character pairing
/// code is for.
///
/// Minting is the one thing neither CryptoKit nor Security will do for us.
/// `SecKeyCreateRandomKey` makes a key and `SecItemAdd` stores it, but nothing
/// public puts a DER certificate around one — hence swift-certificates, and
/// hence its confinement to this product.
public struct Identity: @unchecked Sendable {
    /// SHA-256 of the certificate's DER. What the far end pins.
    public let fingerprint: Data
    /// What `NWProtocolTLS` wants. Not `Sendable`, which is why this struct is
    /// `@unchecked`: it is created once and only read after that.
    let secIdentity: sec_identity_t
    /// The DER, for the rare caller that wants to show a fingerprint's source.
    public let certificateDER: Data

    public enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus, String)
        case malformedCertificate

        public var description: String {
            switch self {
            case .keychain(let status, let what):
                return "keychain \(what) failed (OSStatus \(status))"
            case .malformedCertificate:
                return "the stored certificate is not one we can read"
            }
        }
    }

    /// The identity labelled `label`, minted and stored the first time it is
    /// asked for and loaded from the keychain every time after. `label` is what
    /// separates a host's identity from a viewer's on one machine.
    public static func load(label: String) throws -> Identity {
        try load(label: label, keychain: nil)
    }

    /// `keychain` is nil for the default one. The selftest passes a temporary
    /// keychain it deletes afterwards, which is also what keeps it from
    /// prompting: a rebuilt ad-hoc binary is a different binary to the login
    /// keychain's ACL, and it asks about that once per rebuild.
    public static func load(label: String, keychain: SecKeychain?) throws -> Identity {
        if let existing = try find(label: label, keychain: keychain) {
            return existing
        }
        try mint(label: label, keychain: keychain)
        guard let minted = try find(label: label, keychain: keychain) else {
            throw Failure.keychain(errSecItemNotFound, "reading back the certificate just stored")
        }
        return minted
    }

    // MARK: - Minting

    /// Minting, and the route is not the obvious one. Four ways of getting a
    /// key into a keychain were tried and three of them do not work at all:
    ///
    ///  - `SecItemAdd` with `kSecValueRef` on a key from `SecKeyCreateWithData`
    ///    is `errSecInvalidItemRef` (-25304). That key is a transient object and
    ///    a file keychain will not take a reference to one.
    ///  - `SecItemAdd` with `kSecValueData` is `errSecNoSuchAttr` (-25303).
    ///  - `SecItemImport` refuses a bare EC private key in *every* external
    ///    format — PEM and DER, unknown, openSSL, pemSequence, bsafe — with
    ///    `errSecUnknownFormat` (-25257).
    ///  - The data-protection keychain answers `errSecMissingEntitlement`
    ///    (-34018) to an unsigned or ad-hoc command-line binary, which is why
    ///    `kSecUseDataProtectionKeychain` is false throughout.
    ///
    /// What works is letting the Security framework generate the key itself, in
    /// the keychain, and then borrowing its bytes for as long as it takes to
    /// sign one certificate. A key created without an access control is
    /// extractable, so `SecKeyCopyExternalRepresentation` hands back the x9.63
    /// form, and swift-crypto reads that directly.
    private static func mint(label: String, keychain: SecKeychain?) throws {
        var error: Unmanaged<CFError>?
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecUseDataProtectionKeychain: false,
        ]
        var keyAttributes: [CFString: Any] = [kSecAttrIsPermanent: true, kSecAttrLabel: label]
        #if os(macOS)
        if let keychain {
            attributes[kSecUseKeychain] = keychain
            keyAttributes[kSecUseKeychain] = keychain
        }
        #endif
        attributes[kSecPrivateKeyAttrs] = keyAttributes as CFDictionary
        guard let stored = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Failure.keychain(errSecParam, "generating the key in the keychain \(detail(error))")
        }
        guard let raw = SecKeyCopyExternalRepresentation(stored, &error) as Data? else {
            throw Failure.keychain(errSecParam, "reading the key back out \(detail(error))")
        }
        let key = try P256.Signing.PrivateKey(x963Representation: raw)

        let signing = Certificate.PrivateKey(key)
        // The common name *is* the label, and it has to be: adding a
        // certificate to a file keychain overwrites `kSecAttrLabel` with the
        // certificate's own subject summary, so a label of our choosing is not
        // there to search by afterwards. Verified by reading the attributes
        // back — `labl` came out as the subject, not as what was asked for.
        // Nothing rests on the name either way; the fingerprint is the identity.
        let name = try DistinguishedName { CommonName(label) }
        let now = Date()
        // Ten years, and backdated an hour: the two clocks in the room are not
        // synchronised, and a certificate that is not valid yet is refused by
        // TLS as firmly as one that has expired. Nothing renews these — the
        // fingerprint is the identity, so an expiry only ever costs a re-pair.
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: signing.publicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(10 * 365 * 24 * 3600),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                try Critical(BasicConstraints.notCertificateAuthority)
                // Both ends present a certificate and both verify one, so every
                // identity here is a server and a client at once.
                try ExtendedKeyUsage([.serverAuth, .clientAuth])
                try Critical(KeyUsage(digitalSignature: true))
            },
            issuerPrivateKey: signing
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        let der = Data(serializer.serializedBytes)
        guard let secCert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw Failure.malformedCertificate
        }
        // A certificate reference, unlike a key reference, is something
        // SecItemAdd will take.
        try add(item: [kSecClass: kSecClassCertificate, kSecValueRef: secCert, kSecAttrLabel: label],
                keychain: keychain, what: "storing the certificate")
    }

    private static func detail(_ error: Unmanaged<CFError>?) -> String {
        error.map { "(\(String(describing: $0.takeRetainedValue())))" } ?? "(no detail)"
    }

    private static func add(item: [CFString: Any], keychain: SecKeychain?, what: String) throws {
        var query = item
        // No entitlements, so no data-protection keychain: this has to work in
        // an unsigned command-line binary as well as in a signed app.
        query[kSecUseDataProtectionKeychain] = false
        #if os(macOS)
        if let keychain { query[kSecUseKeychain] = keychain }
        #endif
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw Failure.keychain(status, what)
        }
    }

    // MARK: - Loading

    private static func find(label: String, keychain: SecKeychain?) throws -> Identity? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: label,
            kSecReturnRef: true,
            kSecUseDataProtectionKeychain: false,
        ]
        #if os(macOS)
        if let keychain { query[kSecMatchSearchList] = [keychain] as CFArray }
        #endif
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let certificate = item as! SecCertificate? else {
            throw Failure.keychain(status, "looking for the certificate")
        }

        let der = SecCertificateCopyData(certificate) as Data
        let fingerprint = Data(SHA256.hash(data: der))

        #if os(macOS)
        // The pair is assembled from the certificate: the key is found by the
        // public key it matches, not by our label, so this works whichever
        // keychain the two ended up in.
        var secIdentity: SecIdentity?
        let paired = SecIdentityCreateWithCertificate(keychain, certificate, &secIdentity)
        guard paired == errSecSuccess, let secIdentity else {
            throw Failure.keychain(paired, "pairing the certificate with its key")
        }
        #else
        // iOS has no SecIdentityCreateWithCertificate; the keychain hands over
        // whole identities instead.
        let identityQuery: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecAttrLabel: label,
            kSecReturnRef: true,
            kSecUseDataProtectionKeychain: false,
        ]
        var found: CFTypeRef?
        let got = SecItemCopyMatching(identityQuery as CFDictionary, &found)
        guard got == errSecSuccess, let secIdentity = found as! SecIdentity? else {
            throw Failure.keychain(got, "looking for the identity")
        }
        #endif

        guard let wrapped = sec_identity_create(secIdentity) else {
            throw Failure.keychain(errSecParam, "wrapping the identity for Network.framework")
        }
        return Identity(fingerprint: fingerprint, secIdentity: wrapped, certificateDER: der)
    }

    /// Every certificate and key under `label`, gone. The lab tool's way of
    /// starting over; nothing in an app should need it.
    public static func forget(label: String) {
        for klass in [kSecClassCertificate, kSecClassKey, kSecClassIdentity] {
            SecItemDelete([kSecClass: klass, kSecAttrLabel: label,
                           kSecUseDataProtectionKeychain: false] as CFDictionary)
        }
    }
}

/// Hex, lowercase — how a fingerprint is shown to a person and stored in
/// `UserDefaults`.
public extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
