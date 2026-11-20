//! The driver's settings, applied as the node configures it.

use super::*;

impl Driver {
    /// Replace the announce verification queue with an empty one using these
    /// limits: entry count, bytes, staleness in seconds and overflow policy.
    pub fn set_announce_verify_queue_config(
        &mut self,
        max_entries: usize,
        max_bytes: usize,
        max_stale_secs: f64,
        overflow_policy: OverflowPolicy,
    ) {
        self.announce_verify_queue = Arc::new(Mutex::new(AnnounceVerifyQueue::with_limits(
            max_entries,
            max_bytes,
            max_stale_secs,
            overflow_policy,
        )));
    }

    /// Set the announce rate options given to interfaces that configure no
    /// announce rate target of their own, when transport is enabled.
    pub fn set_announce_rate_defaults(&mut self, defaults: AnnounceRateDefaults) {
        self.announce_rate_defaults = defaults;
    }

    /// Set the ingress control values used in place of the built-in defaults
    /// on interfaces registered while transport is enabled.
    pub fn set_ingress_control_defaults(
        &mut self,
        defaults: rns_core::transport::types::IngressControlConfig,
    ) {
        self.ingress_control_defaults = defaults;
    }

    /// Remember a configured interface's announce rate and cap options.
    pub(crate) fn set_interface_announce_limits(
        &mut self,
        name: &str,
        limits: crate::node::InterfaceAnnounceLimits,
    ) {
        if limits == crate::node::InterfaceAnnounceLimits::default() {
            self.interface_announce_limits.remove(name);
        } else {
            self.interface_announce_limits
                .insert(name.to_string(), limits);
        }
    }

    /// Apply the interface's own configured announce options, before the
    /// instance-wide defaults fill whatever it left unset. Interfaces a
    /// listener spawns copy their parent's values instead.
    pub(crate) fn apply_interface_announce_limits(
        &self,
        info: &mut rns_core::transport::types::InterfaceInfo,
    ) {
        if let Some(limits) = self.interface_announce_limits.get(&info.name) {
            limits.apply(info);
        }
    }

    pub(crate) fn apply_announce_rate_defaults(
        &self,
        info: &mut rns_core::transport::types::InterfaceInfo,
    ) {
        if !self.engine.transport_enabled() || info.announce_rate_target.is_some() {
            return;
        }

        let Some(target) = self.announce_rate_defaults.target else {
            return;
        };

        info.announce_rate_target = Some(target);
        if info.announce_rate_grace == 0 {
            info.announce_rate_grace = self.announce_rate_defaults.grace;
        }
        if info.announce_rate_penalty == 0.0 {
            info.announce_rate_penalty = self.announce_rate_defaults.penalty;
        }
    }

    pub(crate) fn apply_ingress_control_defaults(
        &self,
        info: &mut rns_core::transport::types::InterfaceInfo,
    ) {
        if !self.engine.transport_enabled() {
            return;
        }

        let baseline = if info.ingress_control.enabled {
            rns_core::transport::types::IngressControlConfig::enabled()
        } else {
            rns_core::transport::types::IngressControlConfig::disabled()
        };
        let defaults = self.ingress_control_defaults;
        let ic = &mut info.ingress_control;

        if ic.max_held_announces == baseline.max_held_announces {
            ic.max_held_announces = defaults.max_held_announces;
        }
        if ic.burst_hold == baseline.burst_hold {
            ic.burst_hold = defaults.burst_hold;
        }
        if ic.burst_freq_new == baseline.burst_freq_new {
            ic.burst_freq_new = defaults.burst_freq_new;
        }
        if ic.burst_freq == baseline.burst_freq {
            ic.burst_freq = defaults.burst_freq;
        }
        if ic.pr_burst_freq_new == baseline.pr_burst_freq_new {
            ic.pr_burst_freq_new = defaults.pr_burst_freq_new;
        }
        if ic.pr_burst_freq == baseline.pr_burst_freq {
            ic.pr_burst_freq = defaults.pr_burst_freq;
        }
        if ic.new_time == baseline.new_time {
            ic.new_time = defaults.new_time;
        }
        if ic.burst_penalty == baseline.burst_penalty {
            ic.burst_penalty = defaults.burst_penalty;
        }
        if ic.held_release_interval == baseline.held_release_interval {
            ic.held_release_interval = defaults.held_release_interval;
        }
        if ic.egress_enabled == baseline.egress_enabled {
            ic.egress_enabled = defaults.egress_enabled;
        }
        if ic.egress_pr_freq == baseline.egress_pr_freq {
            ic.egress_pr_freq = defaults.egress_pr_freq;
        }
    }

    pub(super) fn wrap_interface_writer(
        &self,
        interface_id: InterfaceId,
        interface_name: &str,
        writer: Box<dyn crate::interface::Writer>,
    ) -> (
        Box<dyn crate::interface::Writer>,
        crate::interface::AsyncWriterMetrics,
    ) {
        crate::interface::wrap_async_writer(
            writer,
            interface_id,
            interface_name,
            self.event_tx.clone(),
            self.interface_writer_queue_capacity,
        )
    }

    pub(crate) fn set_tick_interval_handle(&mut self, tick_interval_ms: Arc<AtomicU64>) {
        self.tick_interval_ms = tick_interval_ms;
    }

    /// Share the node's stamper, so announces and path requests wait in the
    /// same priority queues as upstream's single stamper thread.
    pub(crate) fn set_stamper(&mut self, stamper: Arc<crate::stamper::Stamper>) {
        self.stamper = stamper;
    }

    /// Apply the `[stamps]` config section and `[filter] hop_limiter`,
    /// as `Reticulum.__apply_config` sets the `Transport` attributes before
    /// transport starts (Reticulum.py, d7749b0b). The configured flags also
    /// become the defaults the `global.stamp_*` runtime keys reset to.
    ///
    /// Call after [`Self::set_stamper`] and
    /// [`Self::set_stamp_destinations_flag`], which this updates in place.
    pub(crate) fn apply_stamp_config(
        &mut self,
        stamps: &crate::config::StampsSection,
        hop_limiter: u8,
    ) {
        self.engine.set_stamp_requirements(stamps.requirements());
        self.engine.set_stamp_prs(stamps.stamp_prs);
        self.stamp_destinations
            .store(stamps.stamp_destinations, Ordering::Relaxed);
        self.stamper
            .set_targets(crate::stamper::StampTargets::from(stamps));
        self.stamper
            .set_path_request_timeout(stamps.path_request_stamp_timeout());
        self.runtime_config.defaults.stamp_destinations = stamps.stamp_destinations;
        self.runtime_config.defaults.stamp_path_requests = stamps.stamp_prs;
        self.runtime_config.defaults.stamp_link_requests = stamps.stamp_lrs;
        self.runtime_config.defaults.always_stamp_link_requests = stamps.always_stamp_lrs;
        self.runtime_config.defaults.stamps_enforced = stamps.stamps_enforced;
        self.runtime_config.defaults.lr_stamps_enforced = stamps.lr_stamps_enforced;
        // The per-destination cost table shared with the node API and the
        // announce builder: `lr_cost` is `Transport.LR_COST`, the cost of
        // destinations that call no `set_link_cost`.
        let link_request_costs = self.link_manager.link_request_costs();
        link_request_costs.set_default_cost(stamps.lr_cost);
        link_request_costs.set_enforced(stamps.lr_stamps_enforced);
        self.stamp_settings = stamps.clone();
        self.hop_limiter = hop_limiter;
        self.engine.set_hop_limiter(hop_limiter);
        // Transport.start (Transport.py:521).
        if hop_limiter != rns_core::constants::PATHFINDER_M {
            log::debug!("Transport hop limit set to {hop_limiter}");
        }
    }

    /// Switch announce and path request stamp enforcement
    /// (`Transport.STAMPS_ENFORCED`), keeping the required costs.
    pub(crate) fn set_stamps_enforced(&mut self, enforced: bool) {
        let mut requirements = self.engine.stamp_requirements();
        requirements.enforced = enforced;
        self.engine.set_stamp_requirements(requirements);
    }

    /// Share the node handle's `STAMP_DESTINATIONS` flag so runtime config
    /// changes made here are seen by the announce API.
    pub(crate) fn set_stamp_destinations_flag(&mut self, flag: Arc<AtomicBool>) {
        self.stamp_destinations = flag;
    }

    /// The flag the node handle reads to refuse new work once draining starts.
    pub(crate) fn accepting_work_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lifecycle.accepting_work)
    }

    #[allow(dead_code)]
    pub(crate) fn set_packet_hashlist_max_entries(&mut self, max_entries: usize) {
        self.engine.set_packet_hashlist_max_entries(max_entries);
    }

    /// Set the probe addresses, protocol, and optional device for hole punching.
    pub fn set_probe_config(
        &mut self,
        addrs: Vec<std::net::SocketAddr>,
        protocol: rns_core::holepunch::ProbeProtocol,
        device: Option<String>,
    ) {
        self.holepunch_manager
            .set_probe_config(addrs, protocol, device);
        self.holepunch_manager
            .set_event_sender(self.event_tx.clone());
        self.holepunch_manager.set_underlay_mark(self.underlay_mark);
    }
}
