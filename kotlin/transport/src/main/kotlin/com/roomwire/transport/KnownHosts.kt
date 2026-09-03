package com.roomwire.transport

import android.content.Context

/**
 * Which certificate each host name had last time.
 *
 * A warning aid and not a secret: anyone who can read this file learns a
 * fingerprint, and a fingerprint grants nothing. What it buys is the ability to
 * say "this is not the Mac you paired with" when a name comes back behind a
 * different certificate — which is what an impersonator looks like, and equally
 * what a reinstalled Mac looks like, so it is shown to the person rather than
 * refused on their behalf.
 */
class KnownHosts(context: Context) {
    private val prefs = context.getSharedPreferences("roomwire", Context.MODE_PRIVATE)

    fun fingerprintOf(hostName: String): String? = prefs.getString(key(hostName), null)

    fun remember(hostName: String, fingerprintHex: String) {
        prefs.edit().putString(key(hostName), fingerprintHex).apply()
    }

    fun forget(hostName: String) {
        prefs.edit().remove(key(hostName)).apply()
    }

    private fun key(hostName: String) = "host:$hostName"
}
