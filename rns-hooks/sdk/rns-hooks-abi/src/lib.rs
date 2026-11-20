//! Definitions shared by the rns-hooks host and the hook programs it runs.
//!
//! Everything here is part of the binary contract between the two sides:
//! the context layouts the host writes, the result a hook returns, the
//! action wire tags, the native hook entry points, and the payload formats
//! of the bundled stats and sentinel hooks. All multi-byte integers are
//! little-endian. A change to a context, result or wire layout means bumping
//! [`ABI_VERSION`]; the stats and sentinel payloads are versioned by their
//! payload type strings instead.

#![no_std]
#![warn(missing_docs)]

pub mod context;
pub mod native;
pub mod result;
pub mod sentinel;
pub mod stats;
pub mod wire;

/// ABI version number. Bump this when the ABI surface changes (context struct
/// layouts, the result layout, host function signatures, action wire encoding,
/// verdict constants).
///
/// Compiled WASM modules export `__rns_abi_version() -> i32` returning this
/// value. The host loader rejects modules whose version does not match.
pub const ABI_VERSION: i32 = 2;
