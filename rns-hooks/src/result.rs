pub use rns_hooks_abi::result::{HookResult, Verdict};

/// A provider event a hook emitted, for the host to forward to its
/// subscribers.
#[derive(Debug, Clone)]
pub struct EmittedProviderEvent {
    /// Name of the program that emitted it.
    pub hook_name: String,
    /// Payload type string chosen by the hook, e.g. `"stats.packet.v1"`.
    pub payload_type: String,
    /// The payload bytes, opaque to the host.
    pub payload: Vec<u8>,
}

/// Result of executing a single program or a chain, with owned data extracted
/// from WASM memory before the store is dropped.
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    /// The deciding result: for a chain, that of the program that dropped or
    /// halted it, else of the last program that returned `Modify`, else
    /// `None` (everything continued).
    pub hook_result: Option<HookResult>,
    /// Actions injected by the programs that ran, in order.
    pub injected_actions: Vec<crate::wire::ActionWire>,
    /// Provider events emitted by the programs that ran, in order.
    pub provider_events: Vec<EmittedProviderEvent>,
    /// Replacement packet bytes from a `Modify` verdict, unvalidated.
    pub modified_data: Option<Vec<u8>>,
}
