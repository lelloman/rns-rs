#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod action;
pub mod context;
pub mod host;
pub mod result;

// Re-export everything from the shared ABI crate so existing hooks don't
// need to change imports.
pub use rns_hooks_abi;
pub use rns_hooks_abi::ABI_VERSION;

pub use context::{
    AnnounceContext, InterfaceContext, LinkContext, PacketContext, TickContext, ARENA_BASE,
    CTX_TYPE_ANNOUNCE, CTX_TYPE_INTERFACE, CTX_TYPE_LINK, CTX_TYPE_PACKET, CTX_TYPE_TICK,
};
pub use result::{HookResult, VERDICT_CONTINUE, VERDICT_DROP, VERDICT_HALT, VERDICT_MODIFY};

/// Exported function that the host loader calls to verify ABI compatibility.
/// Returns the ABI version this SDK was compiled against.
#[no_mangle]
pub extern "C" fn __rns_abi_version() -> i32 {
    rns_hooks_abi::ABI_VERSION
}
