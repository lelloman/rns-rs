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
    /// Start fetching blackhole lists from `self.blackhole_sources`
    /// (`Transport.enable_blackhole_updater`). `interval` is the seconds
    /// between fetches from one source, or `None` for an hour.
    pub(crate) fn enable_blackhole_updater(&mut self, interval: Option<f64>) {
        if self.blackhole_updater.is_some() || self.blackhole_sources.is_empty() {
            return;
        }
        let requester = self.engine.identity_hash().copied().unwrap_or([0u8; 16]);
        self.wants_destination_type(BLACKHOLE_DESTINATION_TYPE, &requester);
        let count = self.blackhole_sources.len();
        let s = if count == 1 { "" } else { "s" };
        log::debug!("Starting blackhole updater with {count} source{s}");
        self.blackhole_updater = Some(BlackholeUpdater {
            interval: interval.unwrap_or(DEFAULT_UPDATE_INTERVAL),
            started_at: time::now(),
            last_job: None,
            last_updates: HashMap::new(),
            links: HashMap::new(),
            creating: Vec::new(),
        });
    }

    /// Run the updater's check when it is due.
    pub(crate) fn tick_blackhole_updater(&mut self, now: f64) {
        self.collect_blackhole_update_links();
        let Some(updater) = self.blackhole_updater.as_mut() else {
            return;
        };
        if now < updater.started_at + INITIAL_WAIT
            || updater
                .last_job
                .is_some_and(|last_job| now < last_job + JOB_INTERVAL)
        {
            return;
        }
        updater.last_job = Some(now);
        let interval = updater.interval;
        let due: Vec<[u8; 16]> = self
            .blackhole_sources
            .iter()
            .copied()
            .filter(|source| {
                now > updater.last_updates.get(source).copied().unwrap_or(0.0) + interval
            })
            .collect();
        for source in due {
            self.start_blackhole_update(source, now);
        }
    }

    /// Link to a source's blackhole destination to ask for its list, or
    /// ask for a path to it and try again at the next check.
    fn start_blackhole_update(&mut self, source: [u8; 16], now: f64) {
        let dest_hash = crate::management::blackhole_dest_hash(&source);
        let announced = if self.engine.has_path(&dest_hash) {
            self.known_destination_announced(&dest_hash)
        } else {
            None
        };
        let Some(announced) = announced else {
            log::info!(
                "No path available for blackhole list update from {}, retrying later",
                hex16(&source)
            );
            self.handle_request_path(dest_hash);
            return;
        };
        log::debug!(
            "Attempting blackhole list update from {}...",
            hex16(&source)
        );
        let sig_pub: [u8; 32] = announced.public_key[32..64]
            .try_into()
            .expect("an announced public key is 64 bytes");
        let (link_tx, link_rx) = mpsc::channel();
        self.handle_create_link(dest_hash, sig_pub, link_tx);
        if let Some(updater) = self.blackhole_updater.as_mut() {
            updater.creating.push((source, link_rx));
            updater.last_updates.insert(source, now);
        }
        self.collect_blackhole_update_links();
    }

    /// Record the ids of the updater's links once they are created.
    fn collect_blackhole_update_links(&mut self) {
        let Some(updater) = self.blackhole_updater.as_mut() else {
            return;
        };
        let mut links = Vec::new();
        updater
            .creating
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
        updater.links.extend(links);
    }

    /// The source an updater link is to, or `None` for any other link.
    pub(crate) fn blackhole_update_source(&mut self, link_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.collect_blackhole_update_links();
        self.blackhole_updater
            .as_ref()
            .and_then(|updater| updater.links.get(link_id).copied())
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
        };
        if let Err(error) = self.get_event_sender().send(request) {
            log::warn!("Could not request a blackhole list: {error:?}");
            let actions = self.link_manager.teardown_link(&link_id);
            self.dispatch_link_actions(actions);
        }
    }

    /// An updater link was closed.
    pub(crate) fn blackhole_update_link_closed(&mut self, link_id: &[u8; 16]) {
        if let Some(updater) = self.blackhole_updater.as_mut() {
            updater.links.remove(link_id);
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
        let Some(map) = list.as_ref().and_then(|list| list.as_map()) else {
            log::debug!(
                "Blackhole list update from {} returned no list",
                hex16(&source)
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
            log::debug!("Added {added} blackholed {spec} from {}", hex16(&source));
            if let Some(dir) = self.blackhole_dir.as_ref() {
                if let Err(error) =
                    crate::blackhole_store::save_source(dir, &source, list.as_ref().unwrap())
                {
                    log::error!(
                        "Error while persisting blackhole list from {}: {error}",
                        hex16(&source)
                    );
                }
            }
            self.remove_blackholed_paths();
        }
        log::debug!("Blackhole list update from {} completed", hex16(&source));
    }
}

fn hex16(hash: &[u8; 16]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}
