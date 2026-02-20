#![no_std]

pub mod context;
pub mod result;
pub mod wire;

/// ABI version number. Bump this when the ABI surface changes (context struct
/// layouts, host function signatures, action wire encoding, verdict constants).
///
/// Compiled WASM modules export `__rns_abi_version() -> i32` returning this
/// value. The host loader rejects modules whose version does not match.
pub const ABI_VERSION: i32 = 1;
