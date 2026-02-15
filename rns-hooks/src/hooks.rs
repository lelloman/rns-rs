use crate::program::LoadedProgram;
use crate::result::HookResult;

/// All hook points in the transport pipeline.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPoint {
    // Packet lifecycle
    PreIngress = 0,
    PreDispatch = 1,

    // Announce processing
    AnnounceReceived = 2,
    PathUpdated = 3,
    AnnounceRetransmit = 4,

    // Link lifecycle
    LinkRequestReceived = 5,
    LinkEstablished = 6,
    LinkClosed = 7,

    // Interface lifecycle
    InterfaceUp = 8,
    InterfaceDown = 9,
    InterfaceConfigChanged = 10,

    // Per-action hooks
    SendOnInterface = 11,
    BroadcastOnAllInterfaces = 12,
    DeliverLocal = 13,
    TunnelSynthesize = 14,

    // Periodic
    Tick = 15,
}

impl HookPoint {
    /// Total number of hook points.
    pub const COUNT: usize = 16;
}

/// Context passed to hook functions (host-side only, NOT `repr(C)`).
///
/// This enum carries the relevant data for each hook invocation.
/// The WASM runtime serializes this into the guest's linear memory.
pub enum HookContext<'a> {
    Packet(&'a crate::context::PacketContext),
    Interface { interface_id: u64 },
    Tick,
    Announce {
        destination_hash: [u8; 16],
        hops: u8,
        interface_id: u64,
    },
    Link {
        link_id: [u8; 16],
        interface_id: u64,
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
    pub programs: Vec<LoadedProgram>,
    /// Function pointer — points to [`hook_noop`] when empty,
    /// [`hook_has_programs`] when programs are attached.
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
        self.programs.sort_by(|a, b| b.priority.cmp(&a.priority));
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
        self.runner as *const () as usize != hook_noop as *const () as usize
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
        ($driver.hook_slots[$point as usize].runner)(
            &$driver.hook_slots[$point as usize],
            &$ctx,
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::Verdict;

    #[test]
    fn test_hook_point_count() {
        assert_eq!(HookPoint::COUNT, 16);
        // Verify the last variant matches COUNT - 1
        assert_eq!(HookPoint::Tick as usize, 15);
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
