//! Fetching blackhole lists from the sources in `blackhole_sources`, as
//! upstream's `RNS.Discovery.BlackholeUpdater` does.
//!
//! A shared or standalone instance with sources configured checks them every
//! minute, starting 20 seconds after startup. A source whose list is older
//! than `blackhole_update_interval` is asked for it: the driver links to the
//! source's `rnstransport.info.blackhole` destination and requests `/list`.
//! Entries not blackholed yet are added with the source recorded, and the
//! list is saved to `storage/blackhole/<source>` so it is loaded again at
//! the next start. The links are the driver's own; applications never see
//! them.

use rns_core::encoding::hex;
use std::collections::HashMap;
use std::sync::mpsc;

use rns_core::msgpack;

use super::*;

/// Seconds after startup before the first check (`INITIAL_WAIT`).
pub(crate) const INITIAL_WAIT: f64 = 20.0;
/// Seconds between checks (`JOB_INTERVAL`).
pub(crate) const JOB_INTERVAL: f64 = 60.0;
/// Default seconds between fetches from one source (`UPDATE_INTERVAL`).
pub(crate) const DEFAULT_UPDATE_INTERVAL: f64 = 60.0 * 60.0;

/// The destination type the updater needs announces of.
const BLACKHOLE_DESTINATION_TYPE: &str = "rnstransport.info.blackhole";

pub(crate) struct BlackholeUpdater {
    /// Seconds between fetches from one source.
    interval: f64,
    started_at: f64,
    last_job: Option<f64>,
    /// When each source was last asked for its list.
    last_updates: HashMap<[u8; 16], f64>,
    /// The updater's links, by link id, with the source each one is to.
    links: HashMap<[u8; 16], [u8; 16]>,
    /// Links still being created (a stamped link request is completed on
    /// a helper thread), with the source each one is to.
    creating: Vec<([u8; 16], mpsc::Receiver<[u8; 16]>)>,
}

impl Driver {
    /// Start fetching blackhole lists from `self.blackhole.sources`
    /// (`Transport.enable_blackhole_updater`). `interval` is the seconds
    /// between fetches from one source, or `None` for an hour.
    pub(crate) fn enable_blackhole_updater(&mut self, interval: Option<f64>) {
        if self.blackhole.updater.is_some() || self.blackhole.sources.is_empty() {
            return;
        }
        let requester = self.engine.identity_hash().copied().unwrap_or([0u8; 16]);
        self.wants_destination_type(BLACKHOLE_DESTINATION_TYPE, &requester);
        let count = self.blackhole.sources.len();
        let s = if count == 1 { "" } else { "s" };
        log::debug!("Starting blackhole updater with {count} source{s}");
        self.blackhole.updater = Some(BlackholeUpdater::new(
            interval.unwrap_or(DEFAULT_UPDATE_INTERVAL),
        ));
    }

    /// Run the updater's check when it is due.
    pub(crate) fn tick_blackhole_updater(&mut self, now: f64) {
        for source in self.blackhole.due_updates(now) {
            self.start_blackhole_update(source, now);
        }
    }

    /// Link to a source's blackhole destination to ask for its list, or
    /// ask for a path to it and try again at the next check.
    fn start_blackhole_update(&mut self, source: [u8; 16], now: f64) {
        let dest_hash = crate::management::blackhole_dest_hash(&source);
        let announced = if self.engine.has_path(&dest_hash) {
            self.known.announced(&dest_hash)
        } else {
            None
        };
        let Some(announced) = announced else {
            log::info!(
                "No path available for blackhole list update from {}, retrying later",
                hex(&source)
            );
            self.handle_request_path(dest_hash);
            return;
        };
        log::debug!("Attempting blackhole list update from {}...", hex(&source));
        let (_, sig_pub) = rns_crypto::identity::split_key(&announced.public_key);
        let (link_tx, link_rx) = mpsc::channel();
        self.handle_create_link(dest_hash, sig_pub, link_tx);
        if let Some(updater) = self.blackhole.updater.as_mut() {
            updater.creating.push((source, link_rx));
            updater.last_updates.insert(source, now);
            updater.collect_links();
        }
    }

    /// An updater link was established: ask for the list.
    ///
    /// The request goes through the event queue, as an application's
    /// would: the link's RTT packet is still waiting in the actions being
    /// dispatched, and the responder ignores a request that reaches it
    /// before the RTT packet has made its side of the link active.
    pub(crate) fn blackhole_update_link_established(&mut self, link_id: [u8; 16]) {
        log::debug!("Link established for blackhole list update");
        let request = Event::SendRequest {
            link_id,
            path: "/list".into(),
            data: Vec::new(),
            max_response_size: None,
            timeout: None,
        };
        if let Err(error) = self.get_event_sender().send(request) {
            log::warn!("Could not request a blackhole list: {error:?}");
            let actions = self.link_manager.teardown_link(&link_id);
            self.dispatch_link_actions(actions);
        }
    }

    /// A source answered with its list, or its request failed (`None`).
    pub(crate) fn blackhole_update_response(
        &mut self,
        link_id: [u8; 16],
        source: [u8; 16],
        data: Option<&[u8]>,
    ) {
        let actions = self.link_manager.teardown_link(&link_id);
        self.dispatch_link_actions(actions);
        let list = data.and_then(|data| msgpack::unpack_exact(data).ok());
        let Some((list, map)) = list
            .as_ref()
            .and_then(|list| list.as_map().map(|map| (list, map)))
        else {
            log::debug!(
                "Blackhole list update from {} returned no list",
                hex(&source)
            );
            return;
        };
        let now = time::now();
        let mut added = 0usize;
        for (identity_hash, entry) in crate::blackhole_store::list_entries(map, Some(source), now) {
            if self.engine.insert_blackhole_entry(identity_hash, entry) {
                added += 1;
            }
        }
        if added > 0 {
            let spec = if added == 1 { "identity" } else { "identities" };
            log::debug!("Added {added} blackholed {spec} from {}", hex(&source));
            if let Some(dir) = self.blackhole.dir.as_ref() {
                if let Err(error) = crate::blackhole_store::save_source(dir, &source, list) {
                    log::error!(
                        "Error while persisting blackhole list from {}: {error}",
                        hex(&source)
                    );
                }
            }
            self.remove_blackholed_paths();
        }
        log::debug!("Blackhole list update from {} completed", hex(&source));
    }
}

impl BlackholeUpdater {
    fn new(interval: f64) -> Self {
        Self {
            interval,
            started_at: time::now(),
            last_job: None,
            last_updates: HashMap::new(),
            links: HashMap::new(),
            creating: Vec::new(),
        }
    }

    /// Record the ids of the updater's links once they are created.
    fn collect_links(&mut self) {
        let mut links = Vec::new();
        self.creating
            .retain(|(source, link_rx)| match link_rx.try_recv() {
                Ok(link_id) => {
                    // The all-zero id means the link request was never sent.
                    if link_id != [0u8; 16] {
                        links.push((link_id, *source));
                    }
                    false
                }
                Err(mpsc::TryRecvError::Empty) => true,
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        self.links.extend(links);
    }

    /// The `sources` to ask for their lists now, when a check is due.
    fn due_sources(&mut self, sources: &[[u8; 16]], now: f64) -> Vec<[u8; 16]> {
        if now < self.started_at + INITIAL_WAIT
            || self
                .last_job
                .is_some_and(|last_job| now < last_job + JOB_INTERVAL)
        {
            return Vec::new();
        }
        self.last_job = Some(now);
        sources
            .iter()
            .copied()
            .filter(|source| {
                now > self.last_updates.get(source).copied().unwrap_or(0.0) + self.interval
            })
            .collect()
    }
}

impl blackhole::BlackholeState {
    /// The sources whose lists to ask for now: none unless the updater
    /// runs and its check is due.
    fn due_updates(&mut self, now: f64) -> Vec<[u8; 16]> {
        let Some(updater) = self.updater.as_mut() else {
            return Vec::new();
        };
        updater.collect_links();
        updater.due_sources(&self.sources, now)
    }

    /// The source an updater link is to, or `None` for any other link.
    pub(crate) fn update_source(&mut self, link_id: &[u8; 16]) -> Option<[u8; 16]> {
        let updater = self.updater.as_mut()?;
        updater.collect_links();
        updater.links.get(link_id).copied()
    }

    /// An updater link was closed.
    pub(crate) fn update_link_closed(&mut self, link_id: &[u8; 16]) {
        if let Some(updater) = self.updater.as_mut() {
            updater.links.remove(link_id);
        }
    }
}
