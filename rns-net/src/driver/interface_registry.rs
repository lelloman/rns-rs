//! What the driver knows about its interfaces beyond their entries.

use super::*;

/// Bookkeeping about the interfaces beyond their entries: how upstream
/// names them, their listeners, interface management, and the samples and
/// ordering interface statistics report.
pub(crate) struct InterfaceRegistry {
    /// Parent listener for dynamically spawned interfaces.
    pub(crate) dynamic_parents: HashMap<InterfaceId, InterfaceId>,
    /// Parent listeners of removed managed interfaces; interfaces they
    /// still spawn are not registered.
    pub(crate) retired_parents: HashSet<InterfaceId>,
    /// Shared allocator for listener-created and discovery-created dynamic interfaces.
    pub(crate) next_dynamic_id: Arc<AtomicU64>,
    /// Upstream's display names (`str(interface)`) of interfaces whose
    /// name shows more than `{type}[{name}]`: addresses, parents.
    pub(crate) display_names: HashMap<InterfaceId, String>,
    /// Upstream's `interface.name` of spawned interfaces whose upstream
    /// name differs from their own (`Client on {listener}`), reported as
    /// their `short_name`.
    pub(crate) short_names: HashMap<InterfaceId, String>,
    /// Listeners with no interface entry of their own, reported in
    /// interface statistics as upstream lists them.
    pub(crate) listener_stats: Vec<ListenerStat>,
    /// Controls of the listeners, which stop accepting when draining and
    /// at shutdown.
    pub(crate) listener_controls: Vec<crate::interface::ListenerControl>,
    /// Interface management configuration, when enabled.
    pub(crate) management: Option<crate::node::InterfaceManagementConfig>,
    /// Interfaces under interface management, by name.
    pub(crate) managed: HashMap<String, ManagedInterface>,
    /// Static interfaces started without interface management, with their
    /// stop controls, so transport can still detach one as upstream's
    /// `_detach_interface(.., internal_forced=True)` does.
    pub(crate) unmanaged_static: HashMap<InterfaceId, Option<crate::interface::ListenerControl>>,
    /// Announce rate and cap options from configured interface sections,
    /// by interface name, applied when the interface registers.
    pub(crate) announce_limits: HashMap<String, crate::node::InterfaceAnnounceLimits>,
    /// Upstream's `Transport.interfaces` order: by bitrate, recomputed
    /// every `INTERFACE_JOBS_INTERVAL`; interfaces added since are listed
    /// after it.
    pub(crate) priority: Vec<u64>,
    /// When `priority` was last recomputed.
    pub(crate) priority_at: f64,
    /// Previous cumulative counters used to calculate current one-second rates.
    pub(crate) traffic_samples: HashMap<InterfaceId, TrafficSample>,
    /// The link table's traffic speeds, measured as upstream's traffic
    /// loop measures them.
    pub(crate) link_traffic: LinkTrafficSampler,
}

impl InterfaceRegistry {
    pub(crate) fn new() -> Self {
        Self {
            dynamic_parents: HashMap::new(),
            retired_parents: HashSet::new(),
            next_dynamic_id: Arc::new(AtomicU64::new(10000)),
            display_names: HashMap::new(),
            short_names: HashMap::new(),
            listener_stats: Vec::new(),
            listener_controls: Vec::new(),
            management: None,
            managed: HashMap::new(),
            unmanaged_static: HashMap::new(),
            announce_limits: HashMap::new(),
            priority: Vec::new(),
            priority_at: 0.0,
            traffic_samples: HashMap::new(),
            link_traffic: LinkTrafficSampler::default(),
        }
    }
}

/// Upstream ef3e8086's `link_speed_rx`/`link_speed_tx`, which its traffic
/// loop computes on each pass from the growth of `link_rxb`/`link_txb`
/// over the time since its previous pass, as `time.monotonic()` reads it.
/// The first pass measures from `Transport.start_time`, a `time.time()`
/// reading, so its interval is a monotonic reading less a wall clock one:
/// negative, and its speeds a negative zero, or a tiny negative number for
/// any link traffic in that first second.
#[derive(Debug, Default)]
pub(crate) struct LinkTrafficSampler {
    /// The previous pass's monotonic reading (upstream's `cts`).
    sampled_at: Option<f64>,
    /// `link_rxb` and `link_txb` at the previous pass.
    rxb: u64,
    txb: u64,
    /// The speeds, `None` before the first pass.
    pub(crate) speeds: Option<(f64, f64)>,
}

impl LinkTrafficSampler {
    /// When the previous pass was, `None` before the first.
    pub(crate) fn sampled_at(&self) -> Option<f64> {
        self.sampled_at
    }

    /// One pass at monotonic time `monotonic` over the link table's
    /// totals; `start_time` is upstream's `Transport.start_time`.
    pub(crate) fn sample(&mut self, monotonic: f64, start_time: f64, (rxb, txb): (u64, u64)) {
        let td = monotonic - self.sampled_at.unwrap_or(start_time);
        let speed = |now: u64, then: u64| (now.saturating_sub(then) * 8) as f64 / td;
        self.speeds = Some((speed(rxb, self.rxb), speed(txb, self.txb)));
        self.sampled_at = Some(monotonic);
        self.rxb = rxb;
        self.txb = txb;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream ef3e8086's traffic loop: no speeds before its first pass;
    /// the first measures from the `time.time()` start against a
    /// `time.monotonic()` reading, a negative interval; later passes from
    /// the previous one.
    #[test]
    fn link_speeds_are_measured_as_upstreams_traffic_loop() {
        let start_time = 1_763_200_000.0;
        let mut sampler = LinkTrafficSampler::default();
        assert_eq!(sampler.speeds, None);
        assert_eq!(sampler.sampled_at(), None);

        sampler.sample(5000.0, start_time, (0, 0));
        let (rx, tx) = sampler.speeds.unwrap();
        // Python's `0*8 / (5000.0 - 1763200000.0)`: -0.0.
        assert!(rx == 0.0 && rx.is_sign_negative());
        assert!(tx == 0.0 && tx.is_sign_negative());
        assert_eq!(sampler.sampled_at(), Some(5000.0));

        let mut first_second = LinkTrafficSampler::default();
        first_second.sample(5000.0, start_time, (100, 0));
        assert_eq!(
            first_second.speeds.unwrap().0,
            800.0 / (5000.0 - start_time)
        );

        sampler.sample(5002.0, start_time, (1000, 250));
        assert_eq!(sampler.speeds, Some((4000.0, 1000.0)));
        sampler.sample(5003.0, start_time, (1000, 250));
        let (rx, tx) = sampler.speeds.unwrap();
        assert!(rx == 0.0 && !rx.is_sign_negative());
        assert!(tx == 0.0 && !tx.is_sign_negative());
    }
}
