package com.lelloman.rntun.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

val AppJson = Json {
    encodeDefaults = true
    ignoreUnknownKeys = true
    prettyPrint = false
}

@Serializable
enum class ProfileRole { CLIENT, GATEWAY }

@Serializable
enum class TunnelMode { SPLIT, FULL }

@Serializable
enum class InterfaceKind { TCP_CLIENT, ADVANCED }

@Serializable
data class TunnelProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "New tunnel",
    val role: ProfileRole = ProfileRole.CLIENT,
    val destinationHash: String = "",
    val tunnelMode: TunnelMode = TunnelMode.SPLIT,
    val requestedRoutes: List<String> = emptyList(),
    val allowedRoutes: List<String> = emptyList(),
    val allowedDns: List<String> = emptyList(),
    val mtu: Int = 1280,
    val interfaceKind: InterfaceKind = InterfaceKind.TCP_CLIENT,
    val tcpHost: String = "",
    val tcpPort: Int = 4242,
    val advancedNodeConfig: String = "",
) {
    fun effectiveRequestedRoutes(): List<String> =
        if (tunnelMode == TunnelMode.FULL) listOf("0.0.0.0/0") else requestedRoutes

    fun effectiveAllowedRoutes(): List<String> =
        if (tunnelMode == TunnelMode.FULL) listOf("0.0.0.0/0") else allowedRoutes

    fun nodeConfig(): String = when (interfaceKind) {
        InterfaceKind.ADVANCED -> advancedNodeConfig.trim() + "\n"
        InterfaceKind.TCP_CLIENT -> """
            [reticulum]
              share_instance = No
              discover_interfaces = No

            [interfaces]
              [[rntun TCP uplink]]
                type = TCPClientInterface
                enabled = Yes
                target_host = $tcpHost
                target_port = $tcpPort
        """.trimIndent() + "\n"
    }

    fun validate(): List<String> = buildList {
        if (role != ProfileRole.CLIENT) add("Gateway mode is reserved for version 2")
        if (name.isBlank()) add("Name is required")
        if (!destinationHash.matches(Regex("[0-9a-fA-F]{32}"))) {
            add("Gateway destination must be exactly 32 hexadecimal characters")
        }
        if (mtu !in 576..1500) add("MTU must be between 576 and 1500")
        if (interfaceKind == InterfaceKind.TCP_CLIENT) {
            if (tcpHost.isBlank() || tcpHost.any(Char::isWhitespace)) add("TCP host is required")
            if (tcpPort !in 1..65535) add("TCP port must be between 1 and 65535")
        } else if (advancedNodeConfig.isBlank()) {
            add("Reticulum configuration is required")
        }
        if (tunnelMode == TunnelMode.FULL && allowedDns.isEmpty()) {
            add("Full tunnel requires at least one approved IPv4 DNS server")
        }
        (effectiveRequestedRoutes() + effectiveAllowedRoutes()).forEach {
            if (!it.isIpv4Cidr()) add("Invalid IPv4 route: $it")
        }
        allowedDns.forEach { if (!it.isIpv4Address()) add("Invalid IPv4 DNS server: $it") }
    }
}

@Serializable
data class AppStore(
    val schemaVersion: Int = 1,
    val profiles: List<TunnelProfile> = emptyList(),
    val defaultProfileId: String? = null,
)

@Serializable
data class NativeConfig(
    @SerialName("schema_version") val schemaVersion: Int = 1,
    val role: String = "client",
    @SerialName("node_config_dir") val nodeConfigDir: String,
    @SerialName("state_dir") val stateDir: String,
    @SerialName("identity_file") val identityFile: String,
    @SerialName("destination_hash") val destinationHash: String,
    @SerialName("requested_routes") val requestedRoutes: List<String>,
    @SerialName("allowed_routes") val allowedRoutes: List<String>,
    @SerialName("allowed_dns") val allowedDns: List<String>,
    @SerialName("allow_default_route") val allowDefaultRoute: Boolean,
    val mtu: Int,
)

@Serializable
data class AppliedTunConfig(
    val address: String,
    @SerialName("prefix_len") val prefixLength: Int,
    val routes: List<String>,
    @SerialName("dns_servers") val dnsServers: List<String>,
    val mtu: Int,
)

fun TunnelProfile.nativeConfig(filesDir: File, identityFile: File): NativeConfig {
    val root = File(filesDir, "rntun/profiles/$id")
    val configDir = File(root, "config").apply { mkdirs() }
    File(configDir, "config").writeText(nodeConfig())
    val stateDir = File(root, "state").apply { mkdirs() }
    return NativeConfig(
        nodeConfigDir = configDir.absolutePath,
        stateDir = stateDir.absolutePath,
        identityFile = identityFile.absolutePath,
        destinationHash = destinationHash.lowercase(),
        requestedRoutes = effectiveRequestedRoutes(),
        allowedRoutes = effectiveAllowedRoutes(),
        allowedDns = allowedDns,
        allowDefaultRoute = tunnelMode == TunnelMode.FULL,
        mtu = mtu,
    )
}

fun NativeConfig.toJson(): String = AppJson.encodeToString(this)
fun AppliedTunConfig.toJson(): String = AppJson.encodeToString(this)

private fun String.isIpv4Address(): Boolean {
    val parts = split('.')
    return parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
}

private fun String.isIpv4Cidr(): Boolean {
    val parts = split('/')
    return parts.size == 2 && parts[0].isIpv4Address() && parts[1].toIntOrNull() in 0..32
}
