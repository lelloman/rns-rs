//! Guest-side SDK for writing rns-hooks programs.
//!
//! A WASM hook built with this crate exports `__rns_abi_version` (defined
//! here) and its hook entry points. The host writes the call's context at
//! [`ARENA_BASE`] in the hook's linear memory and passes its address; the
//! hook reads it with the types in [`context`], may call the host functions
//! in [`host`] and inject actions encoded with [`action`], and returns a
//! [`HookResult`]. Native hooks use the same context and result layouts
//! through the types in [`native`].
//!
//! The [`host`] functions are imports of the `env` module that only an
//! rns-hooks WASM host provides.

#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Encoders for the actions a hook injects with
/// [`host::inject_action_raw`].
///
/// Each encoder writes the tag byte and fields at the start of `buf` and
/// returns the number of bytes written; it panics if `buf` is shorter than
/// that. `data_ptr`/`app_data_ptr` are addresses in the hook's linear memory
/// of bytes that must stay in place until the host function returns.
pub mod action;
/// Context layouts the host writes, and access to a packet's bytes.
pub mod context;
/// Calls into the host. Only usable from a WASM hook run by an rns-hooks
/// host.
pub mod host;
/// Types of the native (shared library) hook interface.
pub mod native;
/// The verdict and result a hook returns.
pub mod result;

// Re-export everything from the shared ABI crate so existing hooks don't
// need to change imports.
pub use rns_hooks_abi;
pub use rns_hooks_abi::ABI_VERSION;

pub use context::{
    AnnounceContext, BackbonePeerContext, InterfaceContext, LinkContext, PacketContext,
    TickContext, ARENA_BASE, CTX_TYPE_ANNOUNCE, CTX_TYPE_BACKBONE_PEER, CTX_TYPE_INTERFACE,
    CTX_TYPE_LINK, CTX_TYPE_PACKET, CTX_TYPE_TICK,
};
pub use result::{HookResult, VERDICT_CONTINUE, VERDICT_DROP, VERDICT_HALT, VERDICT_MODIFY};

/// Exported function that the host loader calls to verify ABI compatibility.
/// Returns the ABI version this SDK was compiled against.
#[no_mangle]
pub extern "C" fn __rns_abi_version() -> i32 {
    rns_hooks_abi::ABI_VERSION
}
