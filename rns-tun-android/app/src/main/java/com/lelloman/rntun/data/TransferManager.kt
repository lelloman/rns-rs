package com.lelloman.rntun.data

import android.util.Base64
import com.lelloman.rntun.NativeBridge
import java.util.UUID

object TransferManager {
    private const val QR_PREFIX = "rntun://profile/v1/"

    fun exportProfile(profile: TunnelProfile, password: String): ByteArray =
        NativeBridge.nativeEncryptBundle(
            "profile",
            AppJson.encodeToString(TunnelProfile.serializer(), profile).encodeToByteArray(),
            password,
        )

    fun importProfile(encoded: ByteArray, password: String): TunnelProfile =
        AppJson.decodeFromString(
            TunnelProfile.serializer(),
            NativeBridge.nativeDecryptBundle("profile", encoded, password).decodeToString(),
        ).copy(id = UUID.randomUUID().toString())

    fun profileQr(profile: TunnelProfile, password: String): String =
        QR_PREFIX + Base64.encodeToString(
            exportProfile(profile, password),
            Base64.URL_SAFE or Base64.NO_WRAP,
        )

    fun importProfileQr(value: String, password: String): TunnelProfile {
        require(value.startsWith(QR_PREFIX)) { "Not an rntun profile QR code" }
        return importProfile(
            Base64.decode(value.removePrefix(QR_PREFIX), Base64.URL_SAFE or Base64.NO_WRAP),
            password,
        )
    }

    fun exportIdentity(path: String, password: String): ByteArray =
        NativeBridge.nativeEncryptBundle("identity", NativeBridge.nativeExportIdentity(path), password)

    fun importIdentity(path: String, encoded: ByteArray, password: String): String =
        NativeBridge.nativeImportIdentity(
            path,
            NativeBridge.nativeDecryptBundle("identity", encoded, password),
        )
}
