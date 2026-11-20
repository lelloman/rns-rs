//! The hook host of builds without hooks: no state, no hooks attached, and
//! every hook management request answered with
//! [`HookOpError::NotEnabled`].

use super::*;
use crate::config::ParsedHook;
use crate::event::{HookInfo, HookOpError, ProviderBridgeStats};

/// The hook points the driver runs hooks at; the same points as in builds
/// with hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookPoint {
    PreIngress,
    PreDispatch,
    AnnounceReceived,
    PathUpdated,
    AnnounceRetransmit,
    LinkRequestReceived,
    LinkEstablished,
    LinkClosed,
    InterfaceUp,
    InterfaceDown,
    InterfaceConfigChanged,
    BackbonePeerConnected,
    BackbonePeerDisconnected,
    BackbonePeerIdleTimeout,
    BackbonePeerWriteStall,
    BackbonePeerPenalty,
    SendOnInterface,
    BroadcastOnAllInterfaces,
    DeliverLocal,
    TunnelSynthesize,
    Tick,
}

/// No hook state.
pub(crate) struct HookHost;

/// What a hook chain produced; no chain runs, so there is none.
pub(crate) enum HookRun {}

impl HookRun {
    #[inline]
    pub(crate) fn dropped(&self) -> bool {
        match *self {}
    }

    #[inline]
    pub(crate) fn take_injected(&mut self) -> Vec<TransportAction> {
        match *self {}
    }
}

impl HookHost {
    #[inline]
    pub(crate) fn new() -> Self {
        HookHost
    }

    #[inline]
    pub(crate) fn attached(&self, _point: HookPoint) -> bool {
        false
    }

    #[inline]
    pub(crate) fn run(
        &mut self,
        _point: HookPoint,
        _event: &HookEvent<'_>,
        _env: &HookEnv<'_>,
    ) -> Option<HookRun> {
        None
    }

    #[inline]
    pub(crate) fn emit_provider_events(&self, _point: HookPoint, run: &HookRun) {
        match *run {}
    }

    #[inline]
    pub(crate) fn packet_outcome(
        &mut self,
        _point: HookPoint,
        run: &HookRun,
        _max_len: usize,
    ) -> PacketHookOutcome {
        match *run {}
    }

    #[inline]
    pub(crate) fn load_wasm(
        &mut self,
        _name: String,
        _wasm_bytes: &[u8],
        _attach_point: &str,
        _priority: i32,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn load_file(
        &mut self,
        _name: String,
        _path: &str,
        _hook_type: &str,
        _attach_point: &str,
        _priority: i32,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn load_builtin(
        &mut self,
        _name: String,
        _builtin_id: &str,
        _attach_point: &str,
        _priority: i32,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn unload(&mut self, _name: &str, _attach_point: &str) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn reload_wasm(
        &mut self,
        _name: &str,
        _attach_point: &str,
        _wasm_bytes: &[u8],
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn reload_file(
        &mut self,
        _name: &str,
        _attach_point: &str,
        _path: &str,
        _hook_type: &str,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn reload_builtin(
        &mut self,
        _name: &str,
        _attach_point: &str,
        _builtin_id: &str,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn set_enabled(
        &mut self,
        _name: &str,
        _attach_point: &str,
        _enabled: bool,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn set_priority(
        &mut self,
        _name: &str,
        _attach_point: &str,
        _priority: i32,
    ) -> Result<(), HookOpError> {
        Err(HookOpError::NotEnabled)
    }

    #[inline]
    pub(crate) fn list(&self) -> Vec<HookInfo> {
        Vec::new()
    }

    #[inline]
    pub(crate) fn load_configured(&mut self, _hooks: &[ParsedHook]) {}

    #[inline]
    pub(crate) fn serve_provider_bridge(&self, _ready: &crate::poll::Events) {}

    #[inline]
    pub(crate) fn stop_provider_bridge(&self) {}

    #[inline]
    pub(crate) fn provider_bridge_stats(&self) -> Option<ProviderBridgeStats> {
        None
    }

    #[inline]
    pub(crate) fn provider_queued_events(&self) -> (usize, usize) {
        (0, 0)
    }
}
