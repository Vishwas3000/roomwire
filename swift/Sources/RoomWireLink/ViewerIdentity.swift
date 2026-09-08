import CryptoKit
import Foundation
import Network
import RoomWireProtocol
import Security

/// Who a viewer is, in the one form the host pins: a 32-byte fingerprint.
///
/// A certificate is what every viewer that can mint one has — macOS through
/// swift-certificates, Android through its Keystore — and TLS proves the key
/// behind it during the handshake. A platform that links no certificate
/// library has a key and nothing to wrap it in; it identifies itself by the key
/// alone, fingerprint = SHA-256 of the X9.63 public key, and proves possession
/// in `revealSigned` instead of in the handshake. Once admitted the host cannot
/// tell the two apart and does not need to: what it stores is the fingerprint.
public enum ViewerIdentity: @unchecked Sendable {
    case certificate(sec_identity_t, fingerprint: Data)
    case key(SigningKey)

    public var fingerprint: Data {
        switch self {
        case .certificate(_, let fingerprint): return fingerprint
        case .key(let key): return key.fingerprint
        }
    }

    var secIdentity: sec_identity_t? {
        if case .certificate(let identity, _) = self { return identity }
        return nil
    }
}

/// A P-256 signing key, in the Secure Enclave when the device has one and in
/// software when it does not — a simulator, a Mac running a test. Either way
/// the private half never crosses this type's boundary: it signs, and it says
/// what its public key is.
public enum SigningKey: @unchecked Sendable {
    case software(P256.Signing.PrivateKey)
    case enclave(SecureEnclave.P256.Signing.PrivateKey)

    public var publicKey: P256.Signing.PublicKey {
        switch self {
        case .software(let key): return key.publicKey
        case .enclave(let key): return key.publicKey
        }
    }

    /// SHA-256 of the X9.63 public key, 65 bytes in. Stands exactly where
    /// SHA-256 of a certificate's DER stands for every other viewer.
    public var fingerprint: Data { Data(SHA256.hash(data: publicKey.x963Representation)) }

    /// Raw r ‖ s, 64 bytes — what `revealSigned` carries.
    public func signature(for data: Data) throws -> Data {
        switch self {
        case .software(let key): return try key.signature(for: data).rawRepresentation
        case .enclave(let key): return try key.signature(for: data).rawRepresentation
        }
    }

    /// A key that lives only as long as this process. For the selftest and
    /// the lab, where remembering would only leave things behind.
    public static func ephemeral() -> SigningKey { .software(P256.Signing.PrivateKey()) }

    /// The key under `label`, minted the first time and loaded every time
    /// after. In the Secure Enclave where there is one — the private key then
    /// cannot leave the chip, the same property Android's Keystore gives the
    /// certificate path — and in software otherwise. What the keychain holds
    /// for an enclave key is its opaque handle, useless on any other device.
    public static func load(label: String) throws -> SigningKey {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.roomwire.viewer-key",
            kSecAttrAccount: label,
            kSecUseDataProtectionKeychain: true,
        ]
        var found: CFTypeRef?
        query[kSecReturnData] = true
        let status = SecItemCopyMatching(query as CFDictionary, &found)
        if status == errSecSuccess, let stored = found as? Data {
            if SecureEnclave.isAvailable,
               let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored) {
                return .enclave(key)
            }
            return .software(try P256.Signing.PrivateKey(rawRepresentation: stored))
        }
        guard status == errSecItemNotFound else { throw Failure.keychain(status, "looking for the viewer key") }

        let key: SigningKey
        let stored: Data
        if SecureEnclave.isAvailable {
            let made = try SecureEnclave.P256.Signing.PrivateKey()
            key = .enclave(made); stored = made.dataRepresentation
        } else {
            let made = P256.Signing.PrivateKey()
            key = .software(made); stored = made.rawRepresentation
        }
        query[kSecReturnData] = nil
        query[kSecValueData] = stored
        query[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(query as CFDictionary, nil)
        guard added == errSecSuccess else { throw Failure.keychain(added, "storing the viewer key") }
        return key
    }

    public enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus, String)
        public var description: String {
            switch self {
            case .keychain(let status, let what): return "keychain \(what) failed (OSStatus \(status))"
            }
        }
    }
}
