package com.lelloman.rntun.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileTest {
    private val valid = TunnelProfile(
        name = "home",
        destinationHash = "00112233445566778899aabbccddeeff",
        tcpHost = "example.net",
        requestedRoutes = listOf("10.20.0.0/16"),
        allowedRoutes = listOf("10.20.0.0/16"),
    )

    @Test
    fun guidedTcpProfileProducesPrivateNodeConfig() {
        assertTrue(valid.validate().isEmpty())
        val config = valid.nodeConfig()
        assertTrue(config.contains("type = TCPClientInterface"))
        assertTrue(config.contains("target_host = example.net"))
        assertTrue(config.contains("share_instance = No"))
    }

    @Test
    fun fullTunnelIsExplicitAndRequiresDns() {
        val invalid = valid.copy(tunnelMode = TunnelMode.FULL)
        assertTrue(invalid.validate().any { it.contains("DNS") })
        val full = invalid.copy(allowedDns = listOf("9.9.9.9"))
        assertTrue(full.validate().isEmpty())
        assertEquals(listOf("0.0.0.0/0"), full.effectiveRequestedRoutes())
        assertEquals(listOf("0.0.0.0/0"), full.effectiveAllowedRoutes())
    }

    @Test
    fun gatewayRoleIsReservedButRejectedInVersionOne() {
        val gateway = valid.copy(role = ProfileRole.GATEWAY)
        assertTrue(gateway.validate().any { it.contains("version 2") })
    }
}
