//! Defending a server against abusive peers: fast flapping, blocked
//! addresses and peer penalties.

use super::*;

/// Configurable behavior-based abuse detection for inbound peers.
#[derive(Debug, Clone, Default)]
pub struct BackboneAbuseConfig {
    pub max_penalty_duration: Option<Duration>,
}

/// Upstream-compatible automatic blocking for repeatedly short-lived inbound
/// Backbone connections.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BackboneFastFlapConfig {
    pub enabled: bool,
    pub connection_threshold: Duration,
    pub grace: u64,
    pub block_duration: Duration,
}

impl Default for BackboneFastFlapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_threshold: Duration::from_secs(20),
            grace: 5,
            block_duration: Duration::from_secs(12 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct FastFlapPeerState {
    first_flap_at: Instant,
    last_flap_at: Instant,
    flap_count: u64,
}

/// Result of recording one short-lived connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FastFlapRecord {
    pub flap_count: u64,
    pub blocked: bool,
    pub newly_blocked: bool,
    pub blocked_until: Option<Instant>,
    pub elapsed_since_first: Duration,
}

/// The flap count upstream gives an address from the `blocked_ips` file
/// (rgit `5f2dbc16`): it blocks wherever the listener's grace is below it.
pub const STATIC_BLOCK_FLAP_COUNT: u64 = 0xFFFF;

/// Process-wide fast-flap history. Policy remains per listener, while the IP
/// history is shared like upstream's class-level `fast_flapping` table.
#[derive(Debug, Default)]
pub struct BackboneFastFlapMonitor {
    peers: HashMap<IpAddr, FastFlapPeerState>,
    /// Addresses from the `blocked_ips` file. Upstream stores them in the
    /// fast-flap table with a flap time 1000 years ahead; here they are
    /// permanent entries that never expire.
    static_blocked: HashSet<IpAddr>,
}

impl BackboneFastFlapMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_disconnect(
        &mut self,
        peer_ip: IpAddr,
        connected_for: Duration,
        config: &BackboneFastFlapConfig,
        now: Instant,
    ) -> Option<FastFlapRecord> {
        if !config.enabled || connected_for >= config.connection_threshold {
            return None;
        }

        self.expire_peer(peer_ip, config, now);
        let state = self.peers.entry(peer_ip).or_insert(FastFlapPeerState {
            first_flap_at: now,
            last_flap_at: now,
            flap_count: 0,
        });
        let was_blocked = state.flap_count > config.grace;
        state.last_flap_at = now;
        state.flap_count = state.flap_count.saturating_add(1);
        let blocked = state.flap_count > config.grace;

        Some(FastFlapRecord {
            flap_count: state.flap_count,
            blocked,
            newly_blocked: blocked && !was_blocked,
            blocked_until: blocked
                .then(|| now.checked_add(config.block_duration))
                .flatten(),
            elapsed_since_first: now.saturating_duration_since(state.first_flap_at),
        })
    }

    pub fn is_blocked(
        &mut self,
        peer_ip: IpAddr,
        config: &BackboneFastFlapConfig,
        now: Instant,
    ) -> bool {
        self.is_statically_blocked(peer_ip, config)
            || self.blocked_until(peer_ip, config, now).is_some()
    }

    /// Add addresses from the `blocked_ips` file.
    pub fn load_static_blocked(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        self.static_blocked
            .extend(ips.into_iter().map(|ip| ip.to_canonical()));
    }

    /// Whether the `blocked_ips` file blocks `peer_ip` on a listener with
    /// this policy: only with fast-flap blocking on and a grace below the
    /// flap count upstream gives those addresses.
    pub fn is_statically_blocked(&self, peer_ip: IpAddr, config: &BackboneFastFlapConfig) -> bool {
        self.static_block_applies(config) && self.static_blocked.contains(&peer_ip.to_canonical())
    }

    pub(super) fn static_block_applies(&self, config: &BackboneFastFlapConfig) -> bool {
        config.enabled && STATIC_BLOCK_FLAP_COUNT > config.grace
    }

    pub fn blocked_until(
        &mut self,
        peer_ip: IpAddr,
        config: &BackboneFastFlapConfig,
        now: Instant,
    ) -> Option<Instant> {
        if !config.enabled {
            return None;
        }
        self.expire_peer(peer_ip, config, now);
        self.peers
            .get(&peer_ip)
            .filter(|state| state.flap_count > config.grace)
            .and_then(|state| state.last_flap_at.checked_add(config.block_duration))
    }

    pub fn blocked_ip_count(&mut self, config: &BackboneFastFlapConfig, now: Instant) -> usize {
        if !config.enabled {
            return 0;
        }
        self.blocked_ip_list(config, now).len()
    }

    pub fn blocked_ip_list(
        &mut self,
        config: &BackboneFastFlapConfig,
        now: Instant,
    ) -> Vec<IpAddr> {
        if !config.enabled {
            return Vec::new();
        }
        self.expire_all(config, now);
        let mut blocked: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, state)| state.flap_count > config.grace)
            .map(|(peer_ip, _)| *peer_ip)
            .collect();
        if self.static_block_applies(config) {
            blocked.extend(self.static_blocked.iter().copied());
        }
        blocked.sort_unstable();
        blocked.dedup();
        blocked
    }

    pub fn flap_count(&self, peer_ip: IpAddr) -> u64 {
        self.peers
            .get(&peer_ip)
            .map(|state| state.flap_count)
            .unwrap_or(0)
    }

    /// Forget an address, including a `blocked_ips` file entry; the file
    /// blocks it again at the next start.
    pub fn clear(&mut self, peer_ip: IpAddr) -> bool {
        let dynamic = self.peers.remove(&peer_ip).is_some();
        let file = self.static_blocked.remove(&peer_ip.to_canonical());
        dynamic || file
    }

    pub(super) fn expire_peer(
        &mut self,
        peer_ip: IpAddr,
        config: &BackboneFastFlapConfig,
        now: Instant,
    ) {
        let expired = self.peers.get(&peer_ip).is_some_and(|state| {
            now.saturating_duration_since(state.last_flap_at) > config.block_duration
        });
        if expired {
            self.peers.remove(&peer_ip);
        }
    }

    pub(super) fn expire_all(&mut self, config: &BackboneFastFlapConfig, now: Instant) {
        self.peers.retain(|_, state| {
            now.saturating_duration_since(state.last_flap_at) <= config.block_duration
        });
    }
}

/// The addresses in `<config dir>/blocked_ips`, as upstream reads the file
/// (rgit `5f2dbc16`): one IPv4 or IPv6 address per line, lines starting
/// with `#` skipped, anything else ignored. A missing file blocks nothing;
/// an unreadable one is logged and blocks nothing.
pub fn read_blocked_ips_file(config_dir: &std::path::Path) -> Vec<IpAddr> {
    let path = config_dir.join("blocked_ips");
    if !path.is_file() {
        return Vec::new();
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            log::error!("Error while loading blocked IP list: {}", error);
            return Vec::new();
        }
    };
    text.trim()
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

/// Block the addresses in `<config dir>/blocked_ips` on every Backbone
/// listener of this process, as upstream does at startup.
pub fn load_blocked_ips_file(config_dir: &std::path::Path) {
    if !config_dir.join("blocked_ips").is_file() {
        return;
    }
    let ips = read_blocked_ips_file(config_dir);
    log::debug!("Loaded {} blocked IPs", ips.len());
    if !ips.is_empty() {
        lock_or_recover(&shared_fast_flap_monitor(), "backbone fast-flap state")
            .load_static_blocked(ips);
    }
}

pub(super) fn shared_fast_flap_monitor() -> Arc<Mutex<BackboneFastFlapMonitor>> {
    static MONITOR: OnceLock<Arc<Mutex<BackboneFastFlapMonitor>>> = OnceLock::new();
    Arc::clone(MONITOR.get_or_init(|| Arc::new(Mutex::new(BackboneFastFlapMonitor::new()))))
}

#[derive(Debug, Clone)]
pub(super) struct PeerBehaviorState {
    pub(super) blacklisted_until: Option<Instant>,
    pub(super) blacklist_reason: Option<String>,
    pub(super) reject_count: u64,
    pub(super) connected_count: usize,
}

impl PeerBehaviorState {
    pub(super) fn new() -> Self {
        Self {
            blacklisted_until: None,
            blacklist_reason: None,
            reject_count: 0,
            connected_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BackbonePeerMonitor {
    peers: HashMap<IpAddr, PeerBehaviorState>,
}

impl BackbonePeerMonitor {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub(super) fn upsert_snapshot(&mut self, peers: &HashMap<IpAddr, PeerBehaviorState>) {
        let mut merged = self.peers.clone();

        for (peer_ip, state) in peers {
            let entry = merged
                .entry(*peer_ip)
                .or_insert_with(PeerBehaviorState::new);
            entry.connected_count = state.connected_count;
            entry.reject_count = state.reject_count;
            entry.blacklisted_until = state.blacklisted_until;
            entry.blacklist_reason = state.blacklist_reason.clone();
        }

        merged.retain(|peer_ip, state| {
            peers.contains_key(peer_ip)
                || state.blacklisted_until.is_some()
                || state.reject_count > 0
        });
        self.peers = merged;
    }

    pub(super) fn sync_into(&self, peers: &mut HashMap<IpAddr, PeerBehaviorState>) {
        for (peer_ip, state) in &self.peers {
            let entry = peers.entry(*peer_ip).or_insert_with(PeerBehaviorState::new);
            entry.blacklisted_until = state.blacklisted_until;
            entry.blacklist_reason = state.blacklist_reason.clone();
            entry.reject_count = state.reject_count;
        }

        peers.retain(|peer_ip, state| {
            if state.connected_count > 0 {
                return true;
            }
            self.peers.contains_key(peer_ip)
        });
    }

    pub fn list(&self, interface_name: &str) -> Vec<BackbonePeerStateEntry> {
        let now = Instant::now();
        let mut entries: Vec<BackbonePeerStateEntry> = self
            .peers
            .iter()
            .map(|(peer_ip, state)| BackbonePeerStateEntry {
                interface_name: interface_name.to_string(),
                peer_ip: *peer_ip,
                connected_count: state.connected_count,
                blacklisted_remaining_secs: state
                    .blacklisted_until
                    .and_then(|until| (until > now).then(|| (until - now).as_secs_f64())),
                blacklist_reason: state.blacklist_reason.clone(),
                reject_count: state.reject_count,
            })
            .collect();
        entries.sort_by_key(|a| a.peer_ip);
        entries
    }

    pub fn clear(&mut self, peer_ip: IpAddr) -> bool {
        self.peers.remove(&peer_ip).is_some()
    }

    pub fn blacklist(&mut self, peer_ip: IpAddr, duration: Duration, reason: String) -> bool {
        let state = self
            .peers
            .entry(peer_ip)
            .or_insert_with(PeerBehaviorState::new);
        state.blacklisted_until = Some(Instant::now() + duration);
        state.blacklist_reason = Some(reason);
        true
    }

    #[cfg(test)]
    pub fn seed_entry(&mut self, entry: BackbonePeerStateEntry) {
        let mut state = PeerBehaviorState::new();
        state.connected_count = entry.connected_count;
        state.reject_count = entry.reject_count;
        state.blacklist_reason = entry.blacklist_reason;
        if let Some(remaining) = entry.blacklisted_remaining_secs {
            state.blacklisted_until = Some(Instant::now() + Duration::from_secs_f64(remaining));
        }
        self.peers.insert(entry.peer_ip, state);
    }
}

#[derive(Clone, Copy)]
pub(super) enum DisconnectReason {
    RemoteClosed,
    IdleTimeout,
    WriteStall,
}

pub(super) fn cleanup_peer_state(peers: &mut HashMap<IpAddr, PeerBehaviorState>) {
    let now = Instant::now();
    peers.retain(|_, state| {
        if matches!(state.blacklisted_until, Some(until) if now >= until) {
            state.blacklisted_until = None;
            state.blacklist_reason = None;
        }
        state.blacklisted_until.is_some() || state.connected_count > 0 || state.reject_count > 0
    });
}

pub(super) fn is_ip_blacklisted(
    peers: &mut HashMap<IpAddr, PeerBehaviorState>,
    peer_ip: IpAddr,
) -> bool {
    let now = Instant::now();
    if let Some(state) = peers.get_mut(&peer_ip) {
        if let Some(until) = state.blacklisted_until {
            if now < until {
                return true;
            }
            state.blacklisted_until = None;
        }
    }
    false
}
