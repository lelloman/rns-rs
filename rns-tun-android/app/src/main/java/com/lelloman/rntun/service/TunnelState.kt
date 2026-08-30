package com.lelloman.rntun.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class TunnelPhase { IDLE, CONNECTING, CONFIGURING, CONNECTED, RECONNECTING, STOPPING, ERROR }

data class TunnelSnapshot(
    val phase: TunnelPhase = TunnelPhase.IDLE,
    val profileId: String? = null,
    val profileName: String? = null,
    val message: String? = null,
    val statusJson: String? = null,
)

object TunnelState {
    private val mutable = MutableStateFlow(TunnelSnapshot())
    val current: StateFlow<TunnelSnapshot> = mutable.asStateFlow()

    fun update(value: TunnelSnapshot) { mutable.value = value }
    fun update(transform: (TunnelSnapshot) -> TunnelSnapshot) { mutable.value = transform(mutable.value) }
}
