//! The driver's handling of its events: frames from interfaces, the
//! application's sends, timers and interface changes, run by its event loop.

mod cleanup;
mod event_loop;
mod folded;
mod inbound;
mod interfaces;
mod management;
mod memory;
mod outbound;
mod paths;
mod tick;
mod tunnels;

use super::*;
use rns_core::transport::types::PacketBytes;
use rns_core::transport::{DecodedInboundFrame, DecodedPacket, RxMetadata};

/// A busy driver checks its folded tick deadline once in this many turns; an
/// idle one checks it before it waits. A tick runs late by at most this many
/// turns' work, which is far below its one-second period.
const FOLDED_TIMER_CHECK_TURNS: u32 = 32;

/// A driver that never goes idle still runs one unit of folded work (a
/// queued job, or one announce check) once in this many events, so that work
/// waits a bounded time under load instead of until the load stops.
const FOLDED_WORK_BUSY_EVENTS: u32 = 64;

/// Events the driver handles before flushing driver-run writers and polling
/// its sockets even though its queue has not emptied yet.
const WRITER_FLUSH_EVENTS: usize = 1024;

/// How long a shared instance client waits after registering a destination
/// before announcing it to the instance as a path response (upstream's
/// `Transport.register_destination`).
const REGISTRATION_ANNOUNCE_DELAY: Duration = Duration::from_millis(250);
