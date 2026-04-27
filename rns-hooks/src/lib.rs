pub mod arena;
pub mod context;
pub mod engine_access;
pub mod error;
pub mod hooks;
#[cfg(feature = "wasm")]
pub mod host_fns;
pub mod manager;
#[cfg(feature = "native")]
pub mod native;
pub mod program;
pub mod result;
pub mod runtime;
pub mod wire;

pub use context::PacketContext;
pub use engine_access::{EngineAccess, NullEngine};
pub use error::HookError;
pub use hooks::{create_hook_slots, hook_noop, HookContext, HookFn, HookPoint, HookSlot};
pub use manager::{HookBackend, HookManager};
pub use program::LoadedProgram;
pub use result::{EmittedProviderEvent, ExecuteResult, HookResult, Verdict};
pub use wire::ActionWire;
