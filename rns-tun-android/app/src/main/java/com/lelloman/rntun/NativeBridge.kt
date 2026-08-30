package com.lelloman.rntun

import android.net.VpnService

object NativeBridge {
    init { System.loadLibrary("rns_tun_android") }

    external fun nativeCreate(configJson: String): Long
    external fun nativeStart(handle: Long, service: VpnService)
    external fun nativePollEvent(handle: Long): String?
    external fun nativeStatus(handle: Long): String
    external fun nativeAttachTun(handle: Long, fd: Int, appliedJson: String)
    external fun nativeStop(handle: Long): Boolean
    external fun nativeEnsureIdentity(path: String): String
    external fun nativeExportIdentity(path: String): ByteArray
    external fun nativeImportIdentity(path: String, bytes: ByteArray): String
    external fun nativeEncryptBundle(type: String, plaintext: ByteArray, password: String): ByteArray
    external fun nativeDecryptBundle(type: String, encoded: ByteArray, password: String): ByteArray
    external fun nativeValidateNodeConfig(config: String, fullTunnel: Boolean): String?
}
