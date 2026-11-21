//! Wire protocol, transport routing, and link and resource engines for the
//! Reticulum network stack.
//!
//! The crate performs no I/O: engines take packets and the current time and
//! return actions for the caller to carry out. Without the default `std`
//! feature it builds as `no_std` with `alloc`.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// Announce building, parsing, validation and stamps.
pub mod announce;
/// Stream data messages carried over a channel.
pub mod buffer;
/// Reliable, windowed message channel over a link.
pub mod channel;
/// Protocol constants, mostly as upstream defines them.
pub mod constants;
/// Destination names and hashes.
pub mod destination;
pub mod discovery;
/// Base256 renderings of byte strings.
pub mod display;
/// Hex and base64 encoding and decoding.
pub mod encoding;
/// SHA-256 based hashes: full, truncated, random and name hashes.
pub mod hash;
/// Direct Link signalling and the NAT hole-punch state machine.
pub mod holepunch;
/// Link handshake, encryption and lifecycle.
pub mod link;
pub mod logging;
pub mod msgpack;
/// Packet flags, packing and unpacking.
pub mod packet;
/// Packet proof validation.
pub mod receipt;
/// Resource transfers: advertisement, parts, proofs and assembly.
pub mod resource;
pub mod stamp;
/// Path table, announce handling and packet routing.
pub mod transport;
pub mod types;
