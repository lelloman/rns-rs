#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

pub mod channel_parts;
pub mod engine;
/// Direct Link signalling constants, states, actions and errors.
pub mod types;

pub use engine::{
    decode_fallback, decode_hello, derive_keepalive_key, encode_fallback, encode_hello,
    validate_signal, Hello, HolePunchEngine,
};
pub use types::{
    decode_signal, encode_signal, Endpoint, HolePunchAction, HolePunchError, HolePunchState,
    ProbeProtocol, CHANNEL_PART, CHANNEL_PART_ACK, CONTEXT_DIRECT_LINK, DIRECT_LINK_VERSION,
    DIRECT_MAX_PACKET, FALLBACK, HELLO, REJECT_BUSY, REJECT_NO_ENDPOINT, REJECT_POLICY,
    REJECT_UNSUPPORTED, UPGRADE_ACCEPT, UPGRADE_READY, UPGRADE_REJECT, UPGRADE_REQUEST,
};
