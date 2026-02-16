#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod action;
pub mod context;
pub mod host;
pub mod result;

pub use context::{
    AnnounceContext, InterfaceContext, LinkContext, PacketContext, TickContext, ARENA_BASE,
    CTX_TYPE_ANNOUNCE, CTX_TYPE_INTERFACE, CTX_TYPE_LINK, CTX_TYPE_PACKET, CTX_TYPE_TICK,
};
pub use result::{HookResult, VERDICT_CONTINUE, VERDICT_DROP, VERDICT_HALT, VERDICT_MODIFY};
