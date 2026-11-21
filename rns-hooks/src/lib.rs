//! Host side of the hook system: programs that observe and steer a node's
//! transport pipeline.
//!
//! A hook program is attached to one [`HookPoint`] and runs, in priority
//! order with the other programs there, each time the node reaches that
//! point. It sees a [`HookContext`], can query the node through
//! [`EngineAccess`], may inject [`ActionWire`] actions and emit provider
//! events, and returns a [`HookResult`] whose [`Verdict`] can let the event
//! through, drop it, replace the packet bytes, or stop the chain.
//!
//! Programs come from three backends, see [`HookBackend`]: WebAssembly
//! modules run sandboxed in Wasmtime (feature `wasm`), shared libraries
//! loaded into the process (feature `native`), and Rust functions
//! registered at startup with [`register_builtin_hook`] (always available).
//! Neither optional backend is enabled by default. A program that fails
//! repeatedly is disabled; failures never block the event (fail-open).
//!
//! This crate has no dependency on the node itself: interface ids are
//! plain `u64`s and hashes plain byte arrays. The binary layouts shared with
//! hook programs live in the `rns-hooks-abi` crate.

#[cfg(any(feature = "wasm", feature = "native"))]
mod arena;
/// Built-in hooks: Rust functions linked into the host and registered by id.
pub mod builtin;
/// The packet context the host fills in for packet hook points.
pub mod context;
/// The node queries a hook can make.
pub mod engine_access;
/// Errors of loading and running hooks.
pub mod error;
/// Hook points, the context passed to them, and the per-point program slots.
pub mod hooks;
#[cfg(feature = "wasm")]
mod host_fns;
/// Loading programs and running them, alone or as a chain.
pub mod manager;
/// Native hooks: shared libraries implementing the C hook interface.
#[cfg(feature = "native")]
pub mod native;
/// A loaded hook program and its bookkeeping.
pub mod program;
/// What running a program or a chain produced.
pub mod result;
mod runtime;
/// Actions a hook can ask the host to carry out.
pub mod wire;

pub use builtin::{register_builtin_hook, BuiltinHook, BuiltinHookCall, BuiltinHookHost};
pub use context::PacketContext;
pub use engine_access::{EngineAccess, NullEngine};
pub use error::HookError;
pub use hooks::{create_hook_slots, hook_noop, HookContext, HookFn, HookPoint, HookSlot};
pub use manager::{HookBackend, HookManager, UnknownHookBackend};
pub use program::LoadedProgram;
pub use result::{EmittedProviderEvent, ExecuteResult, HookResult, Verdict};
pub use wire::ActionWire;
