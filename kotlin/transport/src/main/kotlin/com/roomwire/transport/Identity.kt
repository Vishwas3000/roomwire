package com.roomwire.transport

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.security.auth.x500.X500Principal

/**
 * This device's TLS identity: a P-256 key in the Android Keystore and the
 * self-signed certificate the Keystore mints to go with it.
 *
 * Easier here than on the Mac, and for a good reason: `KeyGenParameterSpec`
 * makes the certificate itself, so there is no certificate library on this side
 * at all. The key is not extractable — it never leaves the Keystore, and TLS
 * signs by handle — which is a stronger position than the Mac's, where the key
 * has to come out for long enough to sign one certificate.
 *
 * The fingerprint is SHA-256 of the certificate's DER, exactly as on the other
 * end, and it is the only thing that identifies this device. The pairing token
 * is not an identity and nothing is keyed on it.
 */
class Identity private constructor(
    val fingerprint: ByteArray,
    private val alias: String,
    private val chain: Array<X509Certificate>,
    private val key: java.security.PrivateKey,
) {
    val fingerprintHex: String get() = fingerprint.joinToString("") { "%02x".format(it) }

    /**
     * A factory that presents this identity and accepts whatever the host
     * presents, recording it. The trust manager it returns is how the caller
     * learns the host's fingerprint, so it is handed back rather than hidden.
     */
    fun sslContext(seen: RecordingTrustManager): SSLSocketFactory {
        val context = SSLContext.getInstance("TLSv1.3")
        context.init(arrayOf(AliasKeyManager(alias, chain, key)), arrayOf(seen), null)
        return context.socketFactory
    }

    companion object {
        private const val STORE = "AndroidKeyStore"

        /**
         * The identity under [alias], minted the first time it is asked for and
         * loaded from the Keystore every time after.
         */
        fun load(alias: String = "roomwire"): Identity {
            val store = KeyStore.getInstance(STORE).apply { load(null) }
            if (!store.containsAlias(alias)) mint(alias)
            val certificate = store.getCertificate(alias) as X509Certificate
            val key = store.getKey(alias, null) as java.security.PrivateKey
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
            return Identity(fingerprint, alias, arrayOf(certificate), key)
        }

        /** Forget it entirely. The next load mints a new one, with a new fingerprint. */
        fun forget(alias: String = "roomwire") {
            KeyStore.getInstance(STORE).apply { load(null) }.deleteEntry(alias)
        }

        private fun mint(alias: String) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, STORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    // DIGEST_NONE as well as SHA-256, and the NONE is the one
                    // that matters: TLS hashes the handshake transcript itself
                    // and hands the key a finished digest to sign raw, so
                    // Conscrypt asks for NONEwithECDSA. A key minted for
                    // SHA-256 alone refuses that with INCOMPATIBLE_DIGEST, and
                    // the handshake dies at startHandshake() with nothing on
                    // the wire to explain why.
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(X500Principal("CN=RoomWire"))
                    // No user authentication requirement: a viewer that could
                    // only connect while the screen was unlocked and a finger
                    // was on the sensor would be a worse product and no safer —
                    // what this key proves is continuity of device, not consent.
                    .build(),
            )
            generator.generateKeyPair()
        }
    }
}
