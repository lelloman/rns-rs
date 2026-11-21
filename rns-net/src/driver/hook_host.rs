//! Hosting hook programs.
//!
//! [`HookHost`] is the real host in builds with the `hooks` feature and a
//! zero-sized stand-in without it. Both have the same methods, so the driver
//! calls them without cfgs; the stand-in's methods do nothing, its
//! [`HookRun`] cannot exist, and the hook points compile away.

use super::*;

#[cfg(not(feature = "hooks"))]
mod disabled;
#[cfg(feature = "hooks")]
mod enabled;

#[cfg(not(feature = "hooks"))]
pub(crate) use disabled::{HookHost, HookPoint, HookRun};
#[cfg(feature = "hooks")]
pub(crate) use enabled::{HookHost, HookPoint, HookRun};

/// The driver state hooks may read while they run.
#[cfg_attr(
    not(feature = "hooks"),
    allow(dead_code, reason = "builds without hooks run no hook to read it")
)]
pub(crate) struct HookEnv<'a> {
    pub(crate) engine: &'a TransportEngine,
    pub(crate) interfaces: &'a crate::interface::InterfaceMap<InterfaceEntry>,
    pub(crate) link_manager: &'a LinkManager,
}

/// What a hook point hands its hooks.
#[cfg_attr(
    not(feature = "hooks"),
    allow(dead_code, reason = "builds without hooks never read the event")
)]
pub(crate) enum HookEvent<'a> {
    /// A packet, or for tunnel synthesis its payload, with its header fields.
    Packet {
        flags: u8,
        hops: u8,
        destination_hash: [u8; 16],
        packet_hash: [u8; 32],
        interface_id: u64,
        raw: &'a [u8],
    },
    /// An interface event.
    Interface { interface_id: u64 },
    /// The periodic tick.
    Tick,
    /// An announce or path event.
    Announce {
        destination_hash: [u8; 16],
        hops: u8,
        interface_id: u64,
    },
    /// A link event.
    Link {
        link_id: [u8; 16],
        interface_id: u64,
    },
    /// A Backbone peer event.
    BackbonePeer(&'a BackbonePeerHookEvent),
}

impl<'a> HookEvent<'a> {
    /// A packet on the wire, its header fields read from its first bytes and
    /// without a hash.
    pub(crate) fn wire_packet(raw: &'a [u8], interface_id: u64) -> Self {
        HookEvent::Packet {
            flags: raw.first().copied().unwrap_or(0),
            hops: raw.get(1).copied().unwrap_or(0),
            destination_hash: extract_dest_hash(raw),
            packet_hash: [0; 32],
            interface_id,
            raw,
        }
    }
}

/// What a packet hook point does after its hook chain ran.
///
/// Only hook points that hold the raw packet bytes before acting on them apply
/// a `Modify` verdict (`PreIngress`, `SendOnInterface`,
/// `BroadcastOnAllInterfaces`, `DeliverLocal`). Every other hook point treats
/// `Modify` as `Continue` and ignores the replacement bytes.
#[cfg_attr(
    not(feature = "hooks"),
    allow(dead_code, reason = "builds without hooks only keep packets")
)]
pub(crate) enum PacketHookOutcome {
    /// Carry on with the bytes the hook point already holds.
    Keep,
    /// Stop processing this packet.
    Drop,
    /// Carry on with the replacement bytes, decoded with the same decoder the
    /// normal path uses. Hashes and header fields come from the replacement.
    Replace(RawPacket),
}

/// Where the actions hooks inject go.
pub(crate) enum InjectedActions<'a> {
    /// Dispatch them right away.
    Dispatch,
    /// Add them to the caller's list, which it dispatches one nesting level
    /// down once it is done with its own actions.
    Collect(&'a mut Vec<TransportAction>),
}
