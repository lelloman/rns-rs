//! Peers found by discovery: admitting them, keeping them and timing
//! them out.

use super::*;
use std::os::fd::AsFd;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PeerKey {
    pub(super) link_local_addr: String,
    pub(super) if_index: u32,
}

/// A discovered peer.
pub(super) struct AutoPeer {
    pub(super) interface_id: InterfaceId,
    pub(super) ifname: String,
    pub(super) if_index: u32,
    pub(super) last_heard: f64,
}

/// Outcome of asking a discovery worker to admit a new peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerAdmissionDecision {
    Admit,
    /// The worker already has `max_peers` active peers.
    AtCapacity,
    /// The worker admitted [`MAX_NEW_PEERS_PER_WINDOW`] peers in the current window.
    RateLimited,
}

/// Per-worker bookkeeping for admitting new peers.
#[derive(Debug, Default)]
pub(super) struct PeerAdmission {
    pub(super) window_start: Option<Instant>,
    pub(super) admitted_in_window: usize,
    pub(super) last_refusal_log: Option<Instant>,
    pub(super) refusals_since_log: usize,
}

impl PeerAdmission {
    /// Decide whether a new peer may be created, given the worker's current
    /// number of active peers. An admitted peer counts against the window.
    pub(super) fn decide(
        &mut self,
        active_peers: usize,
        max_peers: usize,
        now: Instant,
    ) -> PeerAdmissionDecision {
        if active_peers >= max_peers {
            return PeerAdmissionDecision::AtCapacity;
        }
        let window_elapsed = self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= PEER_ADMISSION_WINDOW);
        if window_elapsed {
            self.window_start = Some(now);
            self.admitted_in_window = 0;
        }
        if self.admitted_in_window >= MAX_NEW_PEERS_PER_WINDOW {
            return PeerAdmissionDecision::RateLimited;
        }
        self.admitted_in_window += 1;
        PeerAdmissionDecision::Admit
    }

    /// Record a refusal. Returns the number of refusals to report when a
    /// warning is due, or `None` while warnings are being spaced out.
    pub(super) fn note_refusal(&mut self, now: Instant) -> Option<usize> {
        self.refusals_since_log = self.refusals_since_log.saturating_add(1);
        let due = self
            .last_refusal_log
            .is_none_or(|last| now.saturating_duration_since(last) >= PEER_REFUSAL_LOG_INTERVAL);
        if !due {
            return None;
        }
        self.last_refusal_log = Some(now);
        Some(std::mem::take(&mut self.refusals_since_log))
    }
}

/// Shared state for the AutoInterface across all threads.
pub(super) struct SharedState {
    /// Known peers, scoped by link-local address and interface index.
    pub(super) peers: HashMap<PeerKey, AutoPeer>,
    /// Our own scoped link-local addresses (for echo detection).
    pub(super) link_local_addresses: HashSet<PeerKey>,
    /// Deduplication deque: (hash, timestamp)
    pub(super) dedup_deque: VecDeque<([u8; 32], f64)>,
    /// Flag set when final_init is done
    pub(super) online: bool,
    /// Next dynamic interface ID
    pub(super) next_id: Arc<AtomicU64>,
    /// Maximum active peers per adopted network interface.
    pub(super) max_peers: usize,
    /// New-peer admission state, keyed by adopted network interface name.
    pub(super) peer_admission: HashMap<String, PeerAdmission>,
}

impl SharedState {
    pub(super) fn new(next_id: Arc<AtomicU64>) -> Self {
        SharedState {
            peers: HashMap::new(),
            link_local_addresses: HashSet::new(),
            dedup_deque: VecDeque::new(),
            online: false,
            next_id,
            max_peers: DEFAULT_MAX_PEERS,
            peer_admission: HashMap::new(),
        }
    }

    /// Number of active peers discovered on the adopted interface `ifname`.
    pub(super) fn active_peers_on(&self, ifname: &str) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.ifname == ifname)
            .count()
    }

    /// Decide whether the worker on `ifname` may create one more peer.
    pub(super) fn admit_new_peer(&mut self, ifname: &str, now: Instant) -> PeerAdmissionDecision {
        let active_peers = self.active_peers_on(ifname);
        let max_peers = self.max_peers;
        self.peer_admission
            .entry(ifname.to_string())
            .or_default()
            .decide(active_peers, max_peers, now)
    }

    /// Record an ignored discovery source for `ifname`; see [`PeerAdmission::note_refusal`].
    pub(super) fn note_peer_refusal(&mut self, ifname: &str, now: Instant) -> Option<usize> {
        self.peer_admission
            .entry(ifname.to_string())
            .or_default()
            .note_refusal(now)
    }

    /// Remove peers not heard from within `peer_timeout_secs`, returning them.
    pub(super) fn remove_timed_out_peers(
        &mut self,
        now: f64,
        peer_timeout_secs: f64,
    ) -> Vec<(PeerKey, InterfaceId)> {
        let timed_out = self
            .peers
            .iter()
            .filter(|(_, peer)| now > peer.last_heard + peer_timeout_secs)
            .map(|(peer_key, peer)| (peer_key.clone(), peer.interface_id))
            .collect::<Vec<_>>();
        for (peer_key, _) in &timed_out {
            self.peers.remove(peer_key);
        }
        timed_out
    }

    /// Check dedup deque for a data hash.
    pub(super) fn is_duplicate(&self, hash: &[u8; 32], now: f64) -> bool {
        for (h, ts) in &self.dedup_deque {
            if h == hash && now < *ts + MULTI_IF_DEQUE_TTL {
                return true;
            }
        }
        false
    }

    /// Add to dedup deque, trimming to max length.
    pub(super) fn add_dedup(&mut self, hash: [u8; 32], now: f64) {
        self.dedup_deque.push_back((hash, now));
        while self.dedup_deque.len() > MULTI_IF_DEQUE_LEN {
            self.dedup_deque.pop_front();
        }
    }

    /// Refresh a peer's last_heard timestamp.
    pub(super) fn refresh_peer(&mut self, key: &PeerKey, now: f64) {
        if let Some(peer) = self.peers.get_mut(key) {
            peer.last_heard = now;
        }
    }
}

pub(super) fn peer_key_from_src(src_addr: &SocketAddrV6, fallback_if_index: u32) -> PeerKey {
    let if_index = match src_addr.scope_id() {
        0 => fallback_if_index,
        scope_id => scope_id,
    };

    PeerKey {
        link_local_addr: src_addr.ip().to_string(),
        if_index,
    }
}

pub(super) fn peer_target_addr(peer_key: &PeerKey, data_port: u16) -> io::Result<SocketAddrV6> {
    let peer_ip = peer_key.link_local_addr.parse::<Ipv6Addr>().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad peer IPv6: {}", e))
    })?;

    Ok(SocketAddrV6::new(peer_ip, data_port, 0, peer_key.if_index))
}

pub(super) fn remove_peers_for_worker(
    shared: &Arc<Mutex<SharedState>>,
    tx: &EventSender,
    key: &AutoWorkerKey,
) {
    for iface_id in take_peers_for_worker(shared, key) {
        let _ = tx.send(Event::InterfaceDown(iface_id));
    }
}

/// Forget the peers found through the worker for `key`, returning their
/// interfaces, which the caller reports down.
pub(super) fn take_peers_for_worker(
    shared: &Arc<Mutex<SharedState>>,
    key: &AutoWorkerKey,
) -> Vec<InterfaceId> {
    let removed = {
        let mut state = lock_or_recover(shared, "auto shared state");
        let removed = state
            .peers
            .iter()
            .filter_map(|(peer_key, peer)| {
                if peer.if_index == key.if_index && peer.ifname == key.ifname {
                    Some((peer_key.clone(), peer.interface_id))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (peer_key, _) in &removed {
            state.peers.remove(peer_key);
        }
        state.peer_admission.remove(&key.ifname);

        removed
    };

    removed.into_iter().map(|(_, iface_id)| iface_id).collect()
}

/// Add a new peer, creating a writer and emitting InterfaceUp.
pub(super) struct AddPeerContext<'a> {
    pub(super) shared: &'a Arc<Mutex<SharedState>>,
    pub(super) peer_key: &'a PeerKey,
    pub(super) data_port: u16,
    pub(super) name: &'a str,
    pub(super) ifname: &'a str,
    pub(super) configured_bitrate: u64,
    pub(super) runtime: &'a Arc<Mutex<AutoRuntime>>,
    pub(super) dynamic_template: Option<&'a crate::interface::DynamicInterfaceTemplate>,
    pub(super) underlay_mark: Option<u32>,
    pub(super) inline: bool,
}

/// Admit a new peer, returning the event that brings up its interface.
pub(super) fn add_peer(context: AddPeerContext<'_>) -> Option<Event> {
    let AddPeerContext {
        shared,
        peer_key,
        data_port,
        name,
        ifname,
        configured_bitrate,
        runtime: _runtime,
        dynamic_template,
        underlay_mark,
        inline,
    } = context;

    {
        let mut state = lock_or_recover(shared, "auto shared state");
        if state.peers.contains_key(peer_key) {
            state.refresh_peer(peer_key, crate::time::now());
            return None;
        }
        let now = Instant::now();
        let decision = state.admit_new_peer(ifname, now);
        if decision != PeerAdmissionDecision::Admit {
            let report = state.note_peer_refusal(ifname, now);
            let max_peers = state.max_peers;
            drop(state);
            log_peer_refusal(name, ifname, peer_key, decision, max_peers, report);
            return None;
        }
    }

    // Create UDP writer to send data to this peer
    let send_socket = match UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "[{}] failed to create writer for peer {}: {}",
                name,
                peer_key.link_local_addr,
                e
            );
            return None;
        }
    };
    if let Err(error) = crate::interface::apply_underlay_mark(send_socket.as_fd(), underlay_mark) {
        log::error!("[{}] failed to mark peer socket: {}", name, error);
        return None;
    }
    if inline {
        if let Err(error) = send_socket.set_nonblocking(true) {
            log::warn!("[{}] failed to set up peer socket: {}", name, error);
            return None;
        }
    }

    let target = match peer_target_addr(peer_key, data_port) {
        Ok(target) => target,
        Err(e) => {
            log::warn!(
                "[{}] failed to create target for peer {}%{}: {}",
                name,
                peer_key.link_local_addr,
                peer_key.if_index,
                e
            );
            return None;
        }
    };

    let mut state = lock_or_recover(shared, "auto shared state");

    // Double-check not already added (race)
    if state.peers.contains_key(peer_key) {
        state.refresh_peer(peer_key, crate::time::now());
        return None;
    }
    // Both discovery receivers of a worker may admit concurrently; recheck the cap.
    if state.active_peers_on(ifname) >= state.max_peers {
        let report = state.note_peer_refusal(ifname, Instant::now());
        let max_peers = state.max_peers;
        drop(state);
        log_peer_refusal(
            name,
            ifname,
            peer_key,
            PeerAdmissionDecision::AtCapacity,
            max_peers,
            report,
        );
        return None;
    }

    let peer_id = InterfaceId(state.next_id.fetch_add(1, Ordering::Relaxed));

    // Create a boxed writer for the driver
    let driver_writer: Box<dyn Writer> = Box::new(UdpWriter {
        socket: send_socket,
        target,
        inline,
    });

    let peer_info = rns_core::transport::types::InterfaceInfo {
        stamp_costs: Default::default(),
        id: peer_id,
        name: format!(
            "{}:{}%{}",
            name, peer_key.link_local_addr, peer_key.if_index
        ),
        mode: rns_core::constants::MODE_FULL,
        gravity: 0,
        recursive_prs: false,
        announces_from_internal: true,
        announces_to_internal: None,
        out_capable: true,
        in_capable: true,
        bitrate: Some(configured_bitrate),
        airtime_profile: None,
        announce_rate_target: None,
        announce_rate_grace: 0,
        announce_rate_penalty: 0.0,
        announce_cap: rns_core::constants::ANNOUNCE_CAP,
        is_local_client: false,
        wants_tunnel: false,
        hop_limiter: None,
        tunnel_id: None,
        mtu: HW_MTU as u32,
        mtu_upgradable: true,
        ia_freq: 0.0,
        ia_samples: 0,
        ip_freq: 0.0,
        op_freq: 0.0,
        op_samples: 0,
        started: 0.0,
        // The driver gives a spawned peer its parent's ingress control;
        // this is the AutoInterface default.
        ingress_control: rns_core::transport::types::IngressControlConfig::enabled(),
    };

    let now = crate::time::now();
    state.peers.insert(
        peer_key.clone(),
        AutoPeer {
            interface_id: peer_id,
            ifname: ifname.to_string(),
            if_index: peer_key.if_index,
            last_heard: now,
        },
    );

    log::info!(
        "[{}] Peer discovered: {} (id={})",
        name,
        peer_key.link_local_addr,
        peer_id.0
    );

    // Notify driver of new dynamic interface
    let event = if let Some(template) = dynamic_template {
        let mut registration = template.registration(peer_info);
        registration.display_name = Some(crate::interface::display::auto_peer(
            ifname,
            &peer_key.link_local_addr,
        ));
        // Upstream's `AutoInterfacePeer` never sets a name.
        registration.short_name = Some(crate::interface::display::UNNAMED.into());
        Event::DynamicInterfaceUp {
            id: peer_id,
            writer: driver_writer,
            registration: Box::new(registration),
        }
    } else {
        Event::InterfaceUp(peer_id, Some(driver_writer), Some(Box::new(peer_info)))
    };
    Some(event)
}

/// Warn about an ignored discovery source when `report` says a warning is due.
pub(super) fn log_peer_refusal(
    name: &str,
    ifname: &str,
    peer_key: &PeerKey,
    decision: PeerAdmissionDecision,
    max_peers: usize,
    report: Option<usize>,
) {
    let Some(ignored) = report else {
        return;
    };
    let reason = match decision {
        PeerAdmissionDecision::AtCapacity => format!("{} active peers is the limit", max_peers),
        PeerAdmissionDecision::RateLimited => format!(
            "at most {} new peers per {}s",
            MAX_NEW_PEERS_PER_WINDOW,
            PEER_ADMISSION_WINDOW.as_secs()
        ),
        PeerAdmissionDecision::Admit => return,
    };
    log::warn!(
        "[{}] ignoring new peer {}%{} on {} ({}); {} new peer(s) ignored since the last warning",
        name,
        peer_key.link_local_addr,
        peer_key.if_index,
        ifname,
        reason,
        ignored
    );
}

/// Peer jobs: periodically cull timed-out peers.
pub(super) fn peer_jobs_loop(
    shared: Arc<Mutex<SharedState>>,
    tx: EventSender,
    runtime: Arc<Mutex<AutoRuntime>>,
    running: &AtomicBool,
    name: &str,
) {
    while running.load(Ordering::Relaxed) {
        let interval = Duration::from_secs_f64(
            lock_or_recover(&runtime, "auto runtime")
                .peer_job_interval_secs
                .max(0.1),
        );
        thread::sleep(interval);

        let now = crate::time::now();
        let peer_timeout_secs = lock_or_recover(&runtime, "auto runtime").peer_timeout_secs;

        let timed_out = lock_or_recover(&shared, "auto shared state")
            .remove_timed_out_peers(now, peer_timeout_secs);

        for (peer_key, iface_id) in &timed_out {
            log::info!(
                "[{}] Peer timed out: {}%{}",
                name,
                peer_key.link_local_addr,
                peer_key.if_index
            );
            let _ = tx.send(Event::InterfaceDown(*iface_id));
        }
    }
}
