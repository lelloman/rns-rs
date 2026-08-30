package com.lelloman.rntun.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.lelloman.rntun.MainActivity
import com.lelloman.rntun.NativeBridge
import com.lelloman.rntun.R
import com.lelloman.rntun.data.AppliedTunConfig
import com.lelloman.rntun.data.AppJson
import com.lelloman.rntun.data.ProfileRepository
import com.lelloman.rntun.data.TunnelMode
import com.lelloman.rntun.data.TunnelProfile
import com.lelloman.rntun.data.nativeConfig
import com.lelloman.rntun.data.toJson
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

class RntunVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var sessionJob: Job? = null
    private var nativeHandle = 0L
    private var tun: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSession()
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification("Connecting…"))
        if (sessionJob?.isActive != true) {
            sessionJob = scope.launch { runSession(intent?.getStringExtra(EXTRA_PROFILE_ID)) }
        }
        return START_STICKY
    }

    private suspend fun runSession(requestedProfileId: String?) {
        val repository = ProfileRepository.get(this)
        val store = repository.state.first()
        val profile = requestedProfileId?.let { id -> store.profiles.find { it.id == id } }
            ?: store.profiles.find { it.id == store.defaultProfileId }
        if (profile == null) {
            fail("No default profile is configured")
            return
        }
        val errors = profile.validate()
        if (errors.isNotEmpty()) {
            fail(errors.joinToString("; "))
            return
        }
        TunnelState.update(
            TunnelSnapshot(TunnelPhase.CONNECTING, profile.id, profile.name, "Negotiating with gateway"),
        )
        updateNotification("Connecting ${profile.name}…")
        var preserveFailClosedTun = false
        try {
            val identity = File(filesDir, "rntun/identity")
            NativeBridge.nativeEnsureIdentity(identity.absolutePath)
            val config = profile.nativeConfig(filesDir, identity)
            NativeBridge.nativeValidateNodeConfig(profile.nodeConfig(), profile.tunnelMode == TunnelMode.FULL)
                ?.let { throw IllegalArgumentException(it) }

            if (profile.tunnelMode == TunnelMode.FULL) {
                tun = establishBlackhole(profile)
                    ?: throw IllegalStateException("Android refused the fail-closed VPN interface")
            }
            nativeHandle = NativeBridge.nativeCreate(config.toJson())
            check(nativeHandle != 0L) { "Native tunnel setup failed" }
            NativeBridge.nativeStart(nativeHandle, this)

            while (scope.isActive) {
                val event = NativeBridge.nativePollEvent(nativeHandle)
                if (event == null) {
                    runCatching { NativeBridge.nativeStatus(nativeHandle) }
                        .onSuccess { status -> TunnelState.update { it.copy(statusJson = status) } }
                    delay(50)
                    continue
                }
                handleEvent(profile, event)
            }
        } catch (_: CancellationException) {
            // Normal shutdown.
        } catch (error: Throwable) {
            Diagnostics.record(this, "ERROR", error.message ?: error.javaClass.simpleName)
            preserveFailClosedTun = profile.tunnelMode == TunnelMode.FULL && tun != null
            fail(error.message ?: "Tunnel failed", stopService = !preserveFailClosedTun)
            if (preserveFailClosedTun) updateNotification("Traffic blocked · connection failed")
        } finally {
            closeResources(preserveTun = preserveFailClosedTun)
        }
    }

    private fun handleEvent(profile: TunnelProfile, encoded: String) {
        val objectValue = AppJson.parseToJsonElement(encoded).jsonObject
        when (objectValue.getValue("event").jsonPrimitive.content) {
            "accepted" -> {
                TunnelState.update { it.copy(phase = TunnelPhase.CONFIGURING, message = "Applying VPN settings") }
                val accepted = AppJson.decodeFromJsonElement(
                    AcceptedPayload.serializer(),
                    objectValue.getValue("data"),
                )
                val finalTun = establishAccepted(profile, accepted)
                    ?: throw IllegalStateException("Android refused the negotiated VPN interface")
                val oldTun = tun
                val applied = AppliedTunConfig(
                    accepted.address,
                    accepted.prefixLength,
                    accepted.routes,
                    accepted.dnsServers,
                    accepted.mtu,
                )
                try {
                    NativeBridge.nativeAttachTun(nativeHandle, finalTun.fd, applied.toJson())
                    tun = finalTun
                    oldTun?.close()
                } catch (error: Throwable) {
                    finalTun.close()
                    throw error
                }
            }
            "ready" -> {
                TunnelState.update { it.copy(phase = TunnelPhase.CONNECTED, message = "Connected") }
                updateNotification("Connected to ${profile.name}")
            }
            "disconnected" -> {
                TunnelState.update { it.copy(phase = TunnelPhase.RECONNECTING, message = "Reconnecting") }
                updateNotification("Reconnecting ${profile.name}…")
            }
            "warning" -> Diagnostics.record(this, "WARN", encoded)
            "error" -> throw IllegalStateException(objectValue["data"]?.jsonPrimitive?.content ?: "Native error")
            "stopped" -> stopSelf()
        }
    }

    private fun establishBlackhole(profile: TunnelProfile): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("${profile.name} (connecting)")
            .setMtu(profile.mtu)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(false)
        profile.allowedDns.forEach(builder::addDnsServer)
        return builder.establish()
    }

    private fun establishAccepted(
        profile: TunnelProfile,
        accepted: AcceptedPayload,
    ): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(profile.name)
            .setMtu(accepted.mtu)
            .addAddress(accepted.address, accepted.prefixLength)
            .setBlocking(false)
        accepted.routes.forEach { cidr ->
            val parts = cidr.split('/')
            builder.addRoute(parts[0], parts[1].toInt())
        }
        if (accepted.fullTunnel) {
            check(accepted.dnsServers.isNotEmpty()) { "Gateway supplied no DNS for a full tunnel" }
            accepted.dnsServers.forEach(builder::addDnsServer)
            // No allowFamily(AF_INET6): Android blocks uncovered IPv6 for covered apps.
        } else {
            check(accepted.dnsServers.isEmpty()) { "Split-tunnel gateway supplied unsupported tunnel DNS" }
            builder.allowFamily(android.system.OsConstants.AF_INET6)
        }
        return builder.establish()
    }

    override fun onRevoke() {
        Diagnostics.record(this, "INFO", "VPN permission revoked")
        stopSession()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopSession()
        scope.cancel()
        super.onDestroy()
    }

    private fun stopSession() {
        TunnelState.update { it.copy(phase = TunnelPhase.STOPPING, message = "Stopping") }
        sessionJob?.cancel()
        sessionJob = null
        closeResources()
        TunnelState.update(TunnelSnapshot())
    }

    @Synchronized
    private fun closeResources(preserveTun: Boolean = false) {
        if (nativeHandle != 0L) {
            NativeBridge.nativeStop(nativeHandle)
            nativeHandle = 0L
        }
        if (!preserveTun) {
            tun?.close()
            tun = null
        }
    }

    private fun fail(message: String, stopService: Boolean = true) {
        TunnelState.update { it.copy(phase = TunnelPhase.ERROR, message = message) }
        updateNotification("Connection failed")
        Diagnostics.record(this, "ERROR", message)
        if (stopService) stopSelf()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN connection", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    private fun notification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, RntunVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentTitle("rntun")
            .setContentText(text)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .addAction(0, "Disconnect", stopIntent)
            .build()
    }

    @Serializable
    private data class AcceptedPayload(
        val address: String,
        @SerialName("prefix_len") val prefixLength: Int,
        val gateway: String,
        val routes: List<String>,
        @SerialName("dns_servers") val dnsServers: List<String>,
        val mtu: Int,
        @SerialName("full_tunnel") val fullTunnel: Boolean,
    )

    companion object {
        const val EXTRA_PROFILE_ID = "profile_id"
        const val ACTION_STOP = "com.lelloman.rntun.STOP"
        private const val CHANNEL_ID = "rntun_vpn"
        private const val NOTIFICATION_ID = 2401
    }
}
