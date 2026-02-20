pub use rns_hooks_abi::result::{HookResult, Verdict};

/// Result of executing a single program or a chain, with owned data extracted
/// from WASM memory before the store is dropped.
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    pub hook_result: Option<HookResult>,
    pub injected_actions: Vec<crate::wire::ActionWire>,
    pub modified_data: Option<Vec<u8>>,
}
