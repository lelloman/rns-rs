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
        }
    }
}
