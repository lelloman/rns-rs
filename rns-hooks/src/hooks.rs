use crate::program::LoadedProgram;
use crate::result::HookResult;

/// All hook points in the transport pipeline.
///
/// The discriminant is the index of the point's [`HookSlot`]. Each point
/// says which [`HookContext`] it passes and which verdicts take effect there;
/// at the other points only injected actions and provider events do.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPoint {
    // Packet lifecycle
    /// An inbound packet, after admission checks and before the transport
    /// engine sees it. Packet context; `Drop` discards the packet and
    /// `Modify` replaces it.
    PreIngress = 0,
    /// An inbound packet, after the transport engine handled it and before
    /// the resulting actions are dispatched. Packet context; observation
    /// only, as the engine has already acted on the packet.
    PreDispatch = 1,

    // Announce processing
    /// A validated announce. Announce context; `Drop` makes the node
    /// ignore the announce.
    AnnounceReceived = 2,
    /// A path table entry was added or changed. Announce context with the
    /// new path's hop count and interface.
    PathUpdated = 3,
    /// An announce is being retransmitted. Announce context.
    AnnounceRetransmit = 4,

    // Link lifecycle
    /// A link request arrived for a local destination. Link context.
    LinkRequestReceived = 5,
    /// A link became active. Link context.
    LinkEstablished = 6,
    /// A link closed. Link context, without an interface.
    LinkClosed = 7,

    // Interface lifecycle
    /// An interface came up. Interface context.
    InterfaceUp = 8,
    /// An interface went down. Interface context.
    InterfaceDown = 9,
    /// An interface's settings were changed at runtime. Interface context.
    InterfaceConfigChanged = 10,

    // Backbone peer lifecycle
    /// A peer connected to a backbone server interface. Backbone peer
    /// context.
    BackbonePeerConnected = 11,
    /// A backbone peer disconnected. Backbone peer context.
    BackbonePeerDisconnected = 12,
    /// A backbone peer was dropped for being idle. Backbone peer context.
    BackbonePeerIdleTimeout = 13,
    /// A backbone peer was dropped because writes to it stalled. Backbone
    /// peer context.
    BackbonePeerWriteStall = 14,
    /// A backbone peer's IP was penalized and blacklisted. Backbone peer
    /// context.
    BackbonePeerPenalty = 15,

    // Per-action hooks
    /// A packet about to be sent on one interface. Packet context; `Drop`
    /// suppresses the send and `Modify` replaces the bytes.
    SendOnInterface = 16,
    /// A packet about to be broadcast on all interfaces. Packet context;
    /// `Drop` and `Modify` as for [`SendOnInterface`](Self::SendOnInterface).
    BroadcastOnAllInterfaces = 17,
    /// A packet about to be delivered to a local destination. Packet
    /// context with the packet hash; `Drop` and `Modify` take effect.
    DeliverLocal = 18,
    /// Tunnel synthesis data about to be sent. Packet context whose bytes
    /// are the synthesis payload; `Drop` suppresses it.
    TunnelSynthesize = 19,

    // Periodic
    /// Once per driver tick (every second by default). Tick context.
    Tick = 20,
}

impl HookPoint {
    /// Total number of hook points.
    pub const COUNT: usize = 21;
}

/// Context passed to hook functions (host-side only, NOT `repr(C)`).
///
/// This enum carries the relevant data for each hook invocation.
/// The WASM runtime serializes this into the guest's linear memory.
pub enum HookContext<'a> {
    /// A packet (or, for tunnel synthesis, a payload) and its header fields.
    Packet {
        /// Header fields of the packet.
        ctx: &'a crate::context::PacketContext,
        /// The packet's raw bytes.
        raw: &'a [u8],
    },
    /// An interface event.
    Interface {
        /// The interface the event is about.
        interface_id: u64,
    },
    /// The periodic tick; it carries no data.
    Tick,
    /// An announce or path event.
    Announce {
        /// The announced destination.
        destination_hash: [u8; 16],
        /// Hop count of the announce or path.
        hops: u8,
        /// Interface the announce arrived on or the path uses; 0 if unknown.
        interface_id: u64,
    },
    /// A link event.
    Link {
        /// The link's id.
        link_id: [u8; 16],
        /// Interface the link runs over; 0 if unknown.
        interface_id: u64,
    },
    /// A backbone peer event.
    BackbonePeer {
        /// The backbone server interface the peer connected to.
        server_interface_id: u64,
        /// The interface spawned for the peer; `None` for a penalty.
        peer_interface_id: Option<u64>,
        /// The peer's IP address.
        peer_ip: std::net::IpAddr,
        /// The peer's TCP port; 0 for a penalty.
        peer_port: u16,
        /// How long the connection lasted; zero when the event has none.
        connected_for: std::time::Duration,
        /// The peer sent data before it disconnected; false for other events.
        had_received_data: bool,
        /// Penalty level of a penalty; 0 for other events.
        penalty_level: u8,
        /// How long the IP is blacklisted, for a penalty; zero otherwise.
        blacklist_for: std::time::Duration,
    },
}

/// Function pointer type for hook slot runners.
pub type HookFn = fn(&HookSlot, &HookContext) -> Option<HookResult>;

/// No-op hook runner — returns `None` immediately.
///
/// This is the default for all hook points when no programs are attached.
pub fn hook_noop(_slot: &HookSlot, _ctx: &HookContext) -> Option<HookResult> {
    None
}

/// Placeholder runner for slots that have programs attached.
///
/// This function is swapped in when programs are present, serving as a
/// "something to do" signal. Actual execution goes through `HookManager`.
fn hook_has_programs(_slot: &HookSlot, _ctx: &HookContext) -> Option<HookResult> {
    // Execution is handled externally by HookManager.run_chain().
    // This runner just signals that the slot is active.
    None
}

/// A slot for a single hook point, holding its attached programs and runner.
pub struct HookSlot {
    /// Attached programs, highest priority first. After changing the list
    /// directly, call [`update_runner`](Self::update_runner).
    pub programs: Vec<LoadedProgram>,
    /// [`hook_noop`] when no programs are attached, otherwise a runner that
    /// also returns `None`: it only marks the slot active, and the programs
    /// run through [`HookManager::run_chain`](crate::HookManager::run_chain).
    pub runner: HookFn,
}

impl HookSlot {
    /// Update the runner pointer based on whether programs are present.
    pub fn update_runner(&mut self) {
        if self.programs.is_empty() {
            self.runner = hook_noop;
        } else {
            self.runner = hook_has_programs;
        }
    }

    /// Attach a program to this slot. Maintains descending priority order.
    pub fn attach(&mut self, program: LoadedProgram) {
        self.programs.push(program);
        self.programs
            .sort_by_key(|program| std::cmp::Reverse(program.priority));
        self.update_runner();
    }

    /// Detach a program by name. Returns the removed program, if found.
    pub fn detach(&mut self, name: &str) -> Option<LoadedProgram> {
        let pos = self.programs.iter().position(|p| p.name == name)?;
        let prog = self.programs.remove(pos);
        self.update_runner();
        Some(prog)
    }

    /// Returns true if this slot has programs attached (fast check).
    pub fn has_programs(&self) -> bool {
        !std::ptr::eq(self.runner as *const (), hook_noop as *const ())
    }
}

/// Create an array of [`HookSlot`]s, one per [`HookPoint`], all initialized
/// with empty program lists and the [`hook_noop`] runner.
pub fn create_hook_slots() -> [HookSlot; HookPoint::COUNT] {
    std::array::from_fn(|_| HookSlot {
        programs: Vec::new(),
        runner: hook_noop,
    })
}

/// Dispatch a hook call through the slot's function pointer.
///
/// When the `rns-hooks` feature is enabled in `rns-net`, this macro is used
/// at each integration point. When no programs are attached, the noop runner
/// returns `None` immediately.
///
/// When `rns-hooks` is **not** enabled, the call site wraps this in
/// `#[cfg(feature = "rns-hooks")]` so it compiles to nothing.
#[macro_export]
macro_rules! run_hook {
    ($driver:expr, $point:expr, $ctx:expr) => {{
        ($driver.hook_slots[$point as usize].runner)(&$driver.hook_slots[$point as usize], &$ctx)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::Verdict;

    #[test]
    fn test_hook_point_count() {
        assert_eq!(HookPoint::COUNT, 21);
        // Verify the last variant matches COUNT - 1
        assert_eq!(HookPoint::Tick as usize, 20);
    }

    #[test]
    fn test_hook_noop_returns_none() {
        let slot = HookSlot {
            programs: Vec::new(),
            runner: hook_noop,
        };
        let ctx = HookContext::Tick;
        assert!(hook_noop(&slot, &ctx).is_none());
    }

    #[test]
    fn test_create_hook_slots() {
        let slots = create_hook_slots();
        assert_eq!(slots.len(), HookPoint::COUNT);
        for slot in &slots {
            assert!(slot.programs.is_empty());
            // Verify runner is hook_noop by calling it
            let ctx = HookContext::Tick;
            assert!((slot.runner)(slot, &ctx).is_none());
        }
    }

    #[test]
    fn test_run_hook_macro() {
        struct FakeDriver {
            hook_slots: [HookSlot; HookPoint::COUNT],
        }
        let driver = FakeDriver {
            hook_slots: create_hook_slots(),
        };
        let ctx = HookContext::Tick;
        let result = run_hook!(driver, HookPoint::Tick, ctx);
        assert!(result.is_none());

        let ctx2 = HookContext::Interface { interface_id: 42 };
        let result2 = run_hook!(driver, HookPoint::InterfaceUp, ctx2);
        assert!(result2.is_none());
    }

    #[test]
    fn test_verdict_values() {
        assert_eq!(Verdict::Continue as u32, 0);
        assert_eq!(Verdict::Drop as u32, 1);
        assert_eq!(Verdict::Modify as u32, 2);
        assert_eq!(Verdict::Halt as u32, 3);
    }

    #[test]
    fn test_hook_result_helpers() {
        let drop_r = HookResult::drop_result();
        assert!(drop_r.is_drop());
        assert_eq!(drop_r.verdict, Verdict::Drop as u32);

        let cont_r = HookResult::continue_result();
        assert!(!cont_r.is_drop());
        assert_eq!(cont_r.verdict, Verdict::Continue as u32);
        assert_eq!(cont_r.modified_data_len, 0);
        assert_eq!(cont_r.inject_actions_count, 0);
        assert_eq!(cont_r.log_len, 0);
    }
}
