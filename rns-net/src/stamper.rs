//! Asynchronous stamp generation for own announces and path requests.
//!
//! Upstream `Transport` (1.6.0, rgit `5d38ce30`) grinds the stamps it
//! emits on a single lazily started daemon thread, `stamper_job`, fed by
//! `WorkerQueues`: two bounded FIFO queues scanned in priority order, path
//! requests (`STAMP_PR_PRIORITY`) before destination announces
//! (`STAMP_DST_PRIORITY`), each entry optionally keyed so a newer job for the
//! same key replaces the queued one. Generated path request stamps are kept
//! in `pr_stamp_cache`, keyed on the stamp material and bounded to
//! `pr_stamp_cache_max` entries, so one grind serves a request that is
//! relayed on several interfaces with the same tag.
//!
//! This module is that worker. Path request jobs come from the driver, which
//! either emits its own request (`Event::RequestPath`) or forwards an
//! unstamped request from a local client
//! (`TransportAction::StampPathRequest`); the ground stamp goes back to the
//! driver as [`Event::SendStampedPathRequest`]. Announce jobs come from the
//! node API when `STAMP_DESTINATIONS` is on and the destination has no
//! persisted stamp yet: the worker grinds and persists it, then builds and
//! submits the announce exactly as the synchronous API would have.
//!
//! Nothing here runs while both emission flags are off, which is the
//! upstream default; the queue is cheap to hold and the thread starts only
//! on the first job.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use rns_core::constants;
use rns_core::stamp::StampCost;
use rns_core::transport::types::InterfaceId;
use rns_crypto::identity::Identity;

use crate::destination::Destination;
use crate::event::{Event, EventSender};
use crate::link_send::Completion;
use crate::stamps::DestinationStampStore;

/// `Transport.STAMPER_PR_QUEUE_LENGTH`.
pub const PATH_REQUEST_QUEUE_LENGTH: usize = 32;
/// `Transport.STAMPER_AN_QUEUE_LENGTH`.
pub const ANNOUNCE_QUEUE_LENGTH: usize = 32;
/// `Transport.pr_stamp_cache_max`.
pub const PATH_REQUEST_STAMP_CACHE_MAX: usize = 256;

const PRIORITY_PATH_REQUEST: usize = 0;
const PRIORITY_ANNOUNCE: usize = 1;
const QUEUE_LENGTHS: [usize; 2] = [PATH_REQUEST_QUEUE_LENGTH, ANNOUNCE_QUEUE_LENGTH];

/// How long the worker waits for a job before re-checking the stop flag,
/// as `stamp_queues.get(block=True, timeout=1)`.
const WORKER_WAIT: Duration = Duration::from_secs(1);

/// Stamp target values used by the stamper and the announce builder. The
/// defaults are the protocol constants, overridden by the `[stamps]` config
/// section; tests lower them so a grind finishes quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StampTargets {
    /// Default target value for destination stamps
    /// (`Transport.DESTINATION_VALUE`). A destination may target more with
    /// [`Destination::set_value`], never less.
    pub destination_value: StampCost,
    /// Target value for a path request stamp (`Transport.PR_VALUE`).
    pub path_request_value: StampCost,
}

impl Default for StampTargets {
    fn default() -> Self {
        Self {
            destination_value: constants::DESTINATION_STAMP_VALUE,
            path_request_value: constants::PATH_REQUEST_STAMP_VALUE,
        }
    }
}

impl From<&crate::config::StampsSection> for StampTargets {
    fn from(stamps: &crate::config::StampsSection) -> Self {
        Self {
            destination_value: stamps.destination_value,
            path_request_value: stamps.pr_value,
        }
    }
}

impl StampTargets {
    /// The stamp value `dest` must hold, and is ground at, when announced
    /// (Destination.py `target_value`): a persisted stamp below it is
    /// regenerated.
    pub fn destination_target(&self, dest: &Destination) -> StampCost {
        dest.effective_target_value(self.destination_value)
    }
}

/// A path request waiting for its stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRequestStampJob {
    pub destination_hash: [u8; 16],
    /// 1..=16 bytes: the request's own random tag, or the tag of the local
    /// client request being forwarded.
    pub tag: Vec<u8>,
    /// `None` broadcasts the request as `Event::RequestPath` would have;
    /// `Some` sends it on that interface only, as a forwarded request.
    pub interface: Option<InterfaceId>,
}

/// An announce waiting for its destination stamp.
pub struct AnnounceStampJob {
    pub dest: Destination,
    /// Full private key of the identity owning `dest`; the announce is
    /// signed with it once the stamp exists.
    pub identity_prv_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    /// Present when the caller used a confirmed-transmission API and waits
    /// on the matching receipt.
    pub completion: Option<Completion>,
}

/// A path request stamp ground off the driver thread, ready to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedPathRequest {
    pub destination_hash: [u8; 16],
    pub tag: Vec<u8>,
    pub ext_payload: [u8; constants::PR_EXT_PAYLOAD_LENGTH],
    pub interface: Option<InterfaceId>,
}

/// The queue for `priority` is at capacity; upstream drops the job with a
/// debug log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stamp queue is full")
    }
}

impl std::error::Error for QueueFull {}

enum Job {
    PathRequest(PathRequestStampJob),
    Announce(Box<AnnounceStampJob>),
}

type Key = Vec<u8>;

struct Queues {
    queues: [VecDeque<(Option<Key>, Job)>; 2],
    worker_alive: bool,
    stopped: bool,
}

/// `pr_stamp_cache`: insertion-ordered, evicting the oldest past the cap.
struct PathRequestStampCache {
    stamps: HashMap<Vec<u8>, Vec<u8>>,
    order: VecDeque<Vec<u8>>,
    max: usize,
}

impl PathRequestStampCache {
    fn new(max: usize) -> Self {
        Self {
            stamps: HashMap::new(),
            order: VecDeque::new(),
            max,
        }
    }

    fn get(&self, material: &[u8]) -> Option<Vec<u8>> {
        self.stamps.get(material).cloned()
    }

    fn insert(&mut self, material: Vec<u8>, stamp: Vec<u8>) {
        if self.stamps.insert(material.clone(), stamp).is_none() {
            self.order.push_back(material);
        }
        while self.stamps.len() > self.max {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.stamps.remove(&oldest);
                }
                None => break,
            }
        }
    }

    fn len(&self) -> usize {
        self.stamps.len()
    }
}

struct Inner {
    queues: Mutex<Queues>,
    wake: Condvar,
    event_tx: EventSender,
    stamp_store: Mutex<Option<DestinationStampStore>>,
    targets: Mutex<StampTargets>,
    /// `Transport.PR_STAMP_TIMEOUT`.
    path_request_timeout: Mutex<Duration>,
    pr_stamp_cache: Mutex<PathRequestStampCache>,
}

impl Inner {
    fn lock_queues(&self) -> MutexGuard<'_, Queues> {
        self.queues
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn stamp_store(&self) -> Option<DestinationStampStore> {
        self.stamp_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn targets(&self) -> StampTargets {
        *self
            .targets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn path_request_timeout(&self) -> Duration {
        *self
            .path_request_timeout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn cached_path_request_stamp(&self, material: &[u8]) -> Option<Vec<u8>> {
        self.pr_stamp_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(material)
    }

    fn cache_path_request_stamp(&self, material: Vec<u8>, stamp: Vec<u8>) {
        self.pr_stamp_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(material, stamp);
    }
}

/// The shared stamper: queues, cache and the worker that drains them.
///
/// One instance is shared by the node handle (announce jobs) and the driver
/// (path request jobs). Dropping the last handle stops the worker after its
/// current job.
pub struct Stamper {
    inner: Arc<Inner>,
}

impl Stamper {
    /// A stamper posting its results to `event_tx`, with the protocol stamp
    /// targets. Announce jobs need a stamp store; see
    /// [`Self::set_stamp_store`].
    pub fn new(event_tx: EventSender, stamp_store: Option<DestinationStampStore>) -> Self {
        Self::with_targets(event_tx, stamp_store, StampTargets::default())
    }

    /// As [`Self::new`], with explicit stamp targets.
    pub fn with_targets(
        event_tx: EventSender,
        stamp_store: Option<DestinationStampStore>,
        targets: StampTargets,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                queues: Mutex::new(Queues {
                    queues: [VecDeque::new(), VecDeque::new()],
                    worker_alive: false,
                    stopped: false,
                }),
                wake: Condvar::new(),
                event_tx,
                stamp_store: Mutex::new(stamp_store),
                targets: Mutex::new(targets),
                path_request_timeout: Mutex::new(Duration::from_secs(
                    constants::PATH_REQUEST_STAMP_TIMEOUT,
                )),
                pr_stamp_cache: Mutex::new(PathRequestStampCache::new(
                    PATH_REQUEST_STAMP_CACHE_MAX,
                )),
            }),
        }
    }

    /// Where destination stamps are persisted and reloaded from.
    pub fn set_stamp_store(&self, stamp_store: Option<DestinationStampStore>) {
        *self
            .inner
            .stamp_store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = stamp_store;
    }

    pub fn targets(&self) -> StampTargets {
        self.inner.targets()
    }

    #[doc(hidden)]
    pub fn set_targets(&self, targets: StampTargets) {
        *self
            .inner
            .targets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = targets;
    }

    /// How long a path request stamp may take before the request is dropped
    /// (`Transport.PR_STAMP_TIMEOUT`, `[stamps] pr_stamp_timeout`).
    pub fn path_request_timeout(&self) -> Duration {
        self.inner.path_request_timeout()
    }

    /// Set the path request stamp timeout.
    pub fn set_path_request_timeout(&self, timeout: Duration) {
        *self
            .inner
            .path_request_timeout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = timeout;
    }

    /// `Transport.pr_stamp_material`.
    pub fn path_request_stamp_material(destination_hash: &[u8; 16], tag: &[u8]) -> Vec<u8> {
        let mut material = Vec::with_capacity(16 + tag.len());
        material.extend_from_slice(destination_hash);
        material.extend_from_slice(tag);
        material
    }

    /// A previously ground stamp for this destination and tag, if cached.
    pub fn cached_path_request_stamp(
        &self,
        destination_hash: &[u8; 16],
        tag: &[u8],
    ) -> Option<Vec<u8>> {
        self.inner
            .cached_path_request_stamp(&Self::path_request_stamp_material(destination_hash, tag))
    }

    /// Number of cached path request stamps.
    pub fn cached_path_request_stamps(&self) -> usize {
        self.inner
            .pr_stamp_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Queue a path request for stamping (`Transport.enqueue_stamped_pr`).
    ///
    /// Keyed on the destination hash plus the interface, so a newer request
    /// for the same destination on the same interface replaces a queued one.
    pub fn enqueue_path_request(&self, job: PathRequestStampJob) -> Result<(), QueueFull> {
        let mut key = job.destination_hash.to_vec();
        if let Some(interface) = job.interface {
            key.extend_from_slice(&interface.0.to_be_bytes());
        }
        self.put(PRIORITY_PATH_REQUEST, Some(key), Job::PathRequest(job))
    }

    /// Queue an announce whose destination stamp must be ground first
    /// (`Transport.enqueue_stamped_announce`).
    ///
    /// Keyed on the destination hash: a newer announce for the same
    /// destination replaces a queued one, whose completion, if any, then
    /// reports an interrupted transmission.
    pub fn enqueue_announce(&self, job: AnnounceStampJob) -> Result<(), QueueFull> {
        let key = job.dest.hash.0.to_vec();
        self.put(PRIORITY_ANNOUNCE, Some(key), Job::Announce(Box::new(job)))
    }

    /// Jobs waiting in both queues.
    pub fn queued(&self) -> usize {
        let queues = self.inner.lock_queues();
        queues.queues.iter().map(VecDeque::len).sum()
    }

    /// Whether the worker thread is currently running.
    pub fn worker_alive(&self) -> bool {
        self.inner.lock_queues().worker_alive
    }

    /// `WorkerQueues.put` followed by `Transport.ensure_stamper`.
    fn put(&self, priority: usize, key: Option<Key>, job: Job) -> Result<(), QueueFull> {
        let mut queues = self.inner.lock_queues();
        if queues.stopped {
            return Err(QueueFull);
        }
        let queue = &mut queues.queues[priority];
        if let Some(key) = key.as_ref() {
            queue.retain(|(existing, _)| existing.as_ref() != Some(key));
        }
        if queue.len() >= QUEUE_LENGTHS[priority] {
            return Err(QueueFull);
        }
        queue.push_back((key, job));
        self.ensure_worker(&mut queues);
        drop(queues);
        self.inner.wake.notify_one();
        Ok(())
    }

    fn ensure_worker(&self, queues: &mut Queues) {
        if queues.worker_alive {
            return;
        }
        let inner = Arc::clone(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("rns-stamper".into())
            .spawn(move || worker_main(inner));
        match spawned {
            Ok(_) => {
                log::debug!("Starting stamp worker");
                queues.worker_alive = true;
            }
            Err(error) => log::warn!("could not start stamper worker: {error}"),
        }
    }
}

impl Drop for Stamper {
    fn drop(&mut self) {
        let mut queues = self.inner.lock_queues();
        queues.stopped = true;
        for queue in &mut queues.queues {
            queue.clear();
        }
        drop(queues);
        self.inner.wake.notify_all();
    }
}

/// Clears `worker_alive` when the worker exits, including by panic, so the
/// next job starts a fresh thread as upstream's `is_alive()` check does.
struct WorkerGuard(Arc<Inner>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.lock_queues().worker_alive = false;
    }
}

/// `Transport.stamper_job`.
fn worker_main(inner: Arc<Inner>) {
    let _guard = WorkerGuard(Arc::clone(&inner));
    loop {
        let job = {
            let mut queues = inner.lock_queues();
            loop {
                if queues.stopped {
                    return;
                }
                if let Some(job) = queues
                    .queues
                    .iter_mut()
                    .find_map(|queue| queue.pop_front().map(|(_, job)| job))
                {
                    break job;
                }
                queues = inner
                    .wake
                    .wait_timeout(queues, WORKER_WAIT)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0;
            }
        };
        match job {
            Job::PathRequest(job) => stamp_path_request(&inner, job),
            Job::Announce(job) => stamp_announce(&inner, *job),
        }
    }
}

/// `Transport.stamp_path_request`, posting the result to the driver.
///
/// Grinding is bounded by `PR_STAMP_TIMEOUT`: upstream runs the job under a
/// watchdog that calls `cancel_work` past the deadline, and cancels the
/// emission when no stamp results (Transport.py:3977-3993, d7749b0b). A
/// cancelled grind is not cached.
fn stamp_path_request(inner: &Inner, job: PathRequestStampJob) {
    let material = Stamper::path_request_stamp_material(&job.destination_hash, &job.tag);
    let stamp = match inner.cached_path_request_stamp(&material) {
        Some(stamp) => stamp,
        None => {
            let target = inner.targets().path_request_value;
            let started = std::time::Instant::now();
            let deadline = started.checked_add(inner.path_request_timeout());
            match crate::stamps::generate_stamp_until(
                &material,
                target,
                constants::STAMP_LENGTH,
                0,
                deadline,
            ) {
                Some((stamp, value)) => {
                    log::debug!(
                        "Generated path request stamp with value {value} for {:02x?} in {:?}",
                        &job.destination_hash[..4],
                        started.elapsed()
                    );
                    inner.cache_path_request_stamp(material, stamp.clone());
                    stamp
                }
                None => {
                    log::warn!(
                        "Could not generate path request stamp for {:02x?}, path request emission cancelled",
                        &job.destination_hash[..4]
                    );
                    return;
                }
            }
        }
    };
    let payload = crate::stamps::path_request_ext_payload(&stamp, 0);
    let mut ext_payload = [0u8; constants::PR_EXT_PAYLOAD_LENGTH];
    ext_payload.copy_from_slice(&payload);
    let event = Event::SendStampedPathRequest(Box::new(StampedPathRequest {
        destination_hash: job.destination_hash,
        tag: job.tag,
        ext_payload,
        interface: job.interface,
    }));
    if inner.event_tx.send(event).is_err() {
        log::debug!("Driver is gone, dropping stamped path request");
    }
}

/// The announce half of `stamper_job`: `destination._announce(send=True)`
/// after the stamp exists.
fn stamp_announce(inner: &Inner, job: AnnounceStampJob) {
    let AnnounceStampJob {
        dest,
        identity_prv_key,
        app_data,
        completion,
    } = job;
    let identity = Identity::from_private_key(&identity_prv_key);
    let targets = inner.targets();
    let stamp_store = inner.stamp_store();
    let Some(store) = stamp_store.as_ref() else {
        log::warn!(
            "No stamp store for destination {:02x?}, announce emission cancelled",
            &dest.hash.0[..4]
        );
        return;
    };
    if let Err(error) = crate::node::ensure_destination_stamp(store, targets, &dest, &identity) {
        log::warn!(
            "Could not generate destination stamp for {:02x?}, announce emission cancelled: {error}",
            &dest.hash.0[..4]
        );
        return;
    }
    let built = crate::node::build_announce_packet(
        &inner.event_tx,
        stamp_store.as_ref(),
        true,
        targets,
        &dest,
        &identity,
        app_data.as_deref(),
    );
    let (packet, replay) = match built {
        Ok(built) => built,
        Err(_) => {
            log::error!(
                "Error while stamping and emitting announce for {:02x?}: announce could not be built",
                &dest.hash.0[..4]
            );
            return;
        }
    };
    let dest_type = dest.dest_type.to_wire_constant();
    let result = match completion {
        Some(completion) => inner.event_tx.send(Event::SendOutboundTracked {
            raw: packet.raw,
            dest_type,
            replay,
            completion,
        }),
        None => {
            let stored = match replay {
                Some(replay) => inner.event_tx.send(Event::StoreSharedAnnounce {
                    dest_hash: replay.dest_hash,
                    name_hash: replay.name_hash,
                    identity_prv_key: replay.identity_prv_key,
                    app_data: replay.app_data,
                }),
                None => Ok(()),
            };
            stored.and_then(|_| {
                inner.event_tx.send(Event::SendOutbound {
                    raw: packet.raw,
                    dest_type,
                    attached_interface: None,
                })
            })
        }
    };
    if result.is_err() {
        log::debug!("Driver is gone, dropping stamped announce");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use rns_core::packet::RawPacket;
    use rns_core::stamp::{stamp_valid, stamp_workblock};
    use std::time::Instant;

    const RECV_TIMEOUT: Duration = Duration::from_secs(30);

    fn fast_targets() -> StampTargets {
        StampTargets {
            destination_value: StampCost::from_whole(6),
            path_request_value: StampCost::from_whole(6),
        }
    }

    fn pr_job(dest: u8, tag: u8, interface: Option<u64>) -> PathRequestStampJob {
        PathRequestStampJob {
            destination_hash: [dest; 16],
            tag: vec![tag; 16],
            interface: interface.map(InterfaceId),
        }
    }

    fn announce_job(seed: u8) -> (AnnounceStampJob, Identity) {
        let identity = Identity::from_private_key(&[seed; 64]);
        let dest = Destination::single_in(
            "stamper",
            &["test"],
            rns_core::types::IdentityHash(*identity.hash()),
        );
        (
            AnnounceStampJob {
                dest,
                identity_prv_key: identity.get_private_key().unwrap(),
                app_data: Some(vec![seed]),
                completion: None,
            },
            identity,
        )
    }

    /// A stamper for queue inspection; callers mark the worker alive first so
    /// no thread starts and the queued jobs stay observable.
    fn frozen_stamper() -> (Stamper, event::EventReceiver) {
        let (tx, rx) = event::channel();
        let stamper = Stamper::with_targets(tx, None, fast_targets());
        (stamper, rx)
    }

    fn drain_queued(stamper: &Stamper) -> Vec<(Option<Key>, usize)> {
        let mut queues = stamper.inner.lock_queues();
        // Stop the worker from racing the inspection.
        queues.stopped = true;
        let mut out = Vec::new();
        for (priority, queue) in queues.queues.iter_mut().enumerate() {
            while let Some((key, _)) = queue.pop_front() {
                out.push((key, priority));
            }
        }
        out
    }

    #[test]
    fn path_request_jobs_replace_queued_jobs_with_the_same_key() {
        let (stamper, _rx) = frozen_stamper();
        stamper.inner.lock_queues().worker_alive = true; // keep the worker from starting
        stamper.enqueue_path_request(pr_job(1, 1, None)).unwrap();
        stamper.enqueue_path_request(pr_job(1, 2, None)).unwrap();
        stamper.enqueue_path_request(pr_job(1, 3, Some(7))).unwrap();
        stamper.enqueue_path_request(pr_job(1, 4, Some(7))).unwrap();
        stamper.enqueue_path_request(pr_job(1, 5, Some(8))).unwrap();
        assert_eq!(stamper.queued(), 3);
        let queued = drain_queued(&stamper);
        let mut iface7 = [1u8; 16].to_vec();
        iface7.extend_from_slice(&7u64.to_be_bytes());
        let mut iface8 = [1u8; 16].to_vec();
        iface8.extend_from_slice(&8u64.to_be_bytes());
        assert_eq!(
            queued,
            vec![
                (Some([1u8; 16].to_vec()), PRIORITY_PATH_REQUEST),
                (Some(iface7), PRIORITY_PATH_REQUEST),
                (Some(iface8), PRIORITY_PATH_REQUEST),
            ]
        );
    }

    #[test]
    fn announce_jobs_are_keyed_on_the_destination_and_queued_after_path_requests() {
        let (stamper, _rx) = frozen_stamper();
        stamper.inner.lock_queues().worker_alive = true;
        let (first, _) = announce_job(0x11);
        let (replacement, _) = announce_job(0x11);
        let (other, _) = announce_job(0x22);
        let first_hash = first.dest.hash.0;
        let other_hash = other.dest.hash.0;
        stamper.enqueue_announce(first).unwrap();
        stamper.enqueue_announce(other).unwrap();
        stamper.enqueue_announce(replacement).unwrap();
        stamper.enqueue_path_request(pr_job(3, 3, None)).unwrap();
        assert_eq!(stamper.queued(), 3);
        let queued = drain_queued(&stamper);
        assert_eq!(
            queued,
            vec![
                (Some([3u8; 16].to_vec()), PRIORITY_PATH_REQUEST),
                (Some(other_hash.to_vec()), PRIORITY_ANNOUNCE),
                (Some(first_hash.to_vec()), PRIORITY_ANNOUNCE),
            ],
            "the replaced announce moves to the back; path requests drain first"
        );
    }

    #[test]
    fn full_queues_reject_new_jobs_per_priority() {
        let (stamper, _rx) = frozen_stamper();
        stamper.inner.lock_queues().worker_alive = true;
        for i in 0..PATH_REQUEST_QUEUE_LENGTH {
            stamper
                .enqueue_path_request(pr_job(i as u8, 0, None))
                .unwrap();
        }
        assert_eq!(
            stamper.enqueue_path_request(pr_job(0xF0, 0, None)),
            Err(QueueFull)
        );
        // A keyed replacement still fits: the old entry is removed first.
        stamper.enqueue_path_request(pr_job(0, 9, None)).unwrap();
        // The announce queue has its own capacity.
        let (job, _) = announce_job(0x33);
        stamper.enqueue_announce(job).unwrap();
        assert_eq!(stamper.queued(), PATH_REQUEST_QUEUE_LENGTH + 1);
    }

    #[test]
    fn path_request_stamp_cache_is_bounded_and_evicts_oldest() {
        let mut cache = PathRequestStampCache::new(3);
        for i in 0u8..5 {
            cache.insert(vec![i], vec![i; 14]);
        }
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&[0]).is_none());
        assert!(cache.get(&[1]).is_none());
        assert_eq!(cache.get(&[4]), Some(vec![4; 14]));
        // Re-inserting an existing key does not grow the order list.
        cache.insert(vec![4], vec![0xAA; 14]);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&[4]), Some(vec![0xAA; 14]));
    }

    #[test]
    fn worker_stamps_a_path_request_and_posts_it_to_the_driver() {
        let (tx, rx) = event::channel();
        let stamper = Stamper::with_targets(tx, None, fast_targets());
        let started = Instant::now();
        stamper
            .enqueue_path_request(pr_job(0xAB, 0x01, Some(4)))
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "enqueue must not grind"
        );

        let event = rx
            .recv_timeout(RECV_TIMEOUT)
            .expect("worker posts the stamped request");
        let Event::SendStampedPathRequest(stamped) = event else {
            panic!("unexpected event {event:?}");
        };
        assert_eq!(stamped.destination_hash, [0xAB; 16]);
        assert_eq!(stamped.tag, vec![0x01; 16]);
        assert_eq!(stamped.interface, Some(InterfaceId(4)));
        assert_eq!(stamped.ext_payload[0], constants::EXT_PAYLOAD_MARKER);
        assert_eq!(stamped.ext_payload[1], 0x00);
        let material = Stamper::path_request_stamp_material(&[0xAB; 16], &[0x01; 16]);
        let workblock = stamp_workblock(&material, 0);
        assert!(stamp_valid(
            &stamped.ext_payload[constants::EXT_HEADER_LENGTH..],
            fast_targets().path_request_value,
            &workblock
        ));
        assert_eq!(
            stamper.cached_path_request_stamp(&[0xAB; 16], &[0x01; 16]),
            Some(stamped.ext_payload[constants::EXT_HEADER_LENGTH..].to_vec())
        );

        // The same destination and tag on another interface reuses the
        // cached stamp byte for byte.
        stamper
            .enqueue_path_request(pr_job(0xAB, 0x01, Some(5)))
            .unwrap();
        let event = rx.recv_timeout(RECV_TIMEOUT).unwrap();
        let Event::SendStampedPathRequest(again) = event else {
            panic!("unexpected event {event:?}");
        };
        assert_eq!(again.ext_payload, stamped.ext_payload);
        assert_eq!(again.interface, Some(InterfaceId(5)));
        assert_eq!(stamper.cached_path_request_stamps(), 1);
    }

    #[test]
    fn worker_grinds_persists_and_emits_a_stamped_announce() {
        let dir = tempfile::tempdir().unwrap();
        let store = DestinationStampStore::new(dir.path());
        let (tx, rx) = event::channel();
        let stamper = Stamper::with_targets(tx, Some(store.clone()), fast_targets());
        let (job, identity) = announce_job(0x44);
        let dest = job.dest.clone();
        stamper.enqueue_announce(job).unwrap();

        let first = rx.recv_timeout(RECV_TIMEOUT).unwrap();
        let Event::StoreSharedAnnounce {
            dest_hash,
            app_data,
            ..
        } = first
        else {
            panic!("expected the shared announce record first, got {first:?}");
        };
        assert_eq!(dest_hash, dest.hash.0);
        let wire_app_data = app_data.expect("stamped announces always carry app data");
        assert_eq!(
            wire_app_data.len(),
            1 + constants::EXT_PAYLOAD_LENGTH,
            "caller app data followed by the stamp extension"
        );
        assert_eq!(wire_app_data[0], 0x44);

        let second = rx.recv_timeout(RECV_TIMEOUT).unwrap();
        let Event::SendOutbound { raw, dest_type, .. } = second else {
            panic!("expected the announce itself, got {second:?}");
        };
        assert_eq!(dest_type, constants::DESTINATION_SINGLE);
        let packet = RawPacket::unpack(&raw).unwrap();
        assert_eq!(packet.flags.packet_type, constants::PACKET_TYPE_ANNOUNCE);
        assert_eq!(packet.destination_hash, dest.hash.0);

        // The stamp is persisted at the value the next synchronous announce
        // reloads it with.
        let name_hash = rns_core::destination::name_hash("stamper", &["test"]);
        let material = crate::stamps::destination_stamp_material(
            &dest.hash.0,
            &identity.get_public_key().unwrap(),
            &name_hash,
        );
        let (stamp, value) = store
            .load(&dest.hash.0, &material, fast_targets().destination_value)
            .expect("stamp persisted");
        assert!(value.meets(fast_targets().destination_value));
        let ext = &wire_app_data[1..];
        assert_eq!(ext[0], constants::EXT_PAYLOAD_MARKER);
        assert_eq!(
            &ext[constants::EXT_HEADER_LENGTH..][..constants::STAMP_LENGTH],
            &stamp[..]
        );
    }

    #[test]
    fn stamped_announce_carries_the_destination_link_cost() {
        let dir = tempfile::tempdir().unwrap();
        let store = DestinationStampStore::new(dir.path());
        let (tx, _rx) = event::channel();
        let (job, identity) = announce_job(0x45);
        let dest = job.dest.clone();

        let announced_cost = |tx: &event::EventSender| {
            let (packet, _) = crate::node::build_announce_packet(
                tx,
                Some(&store),
                true,
                fast_targets(),
                &dest,
                &identity,
                Some(b"app"),
            )
            .unwrap();
            let announce = rns_core::announce::AnnounceData::unpack(
                packet.data(),
                packet.flags.context_flag == constants::FLAG_SET,
            )
            .unwrap();
            let mut validated = announce.validate(&dest.hash.0).unwrap();
            assert_eq!(
                validated.apply_stamp(&dest.hash.0, fast_targets().destination_value),
                rns_core::announce::AnnounceStampStatus::Valid
            );
            assert_eq!(validated.app_data.as_deref(), Some(b"app".as_slice()));
            validated.lr_cost
        };

        // Without `set_link_cost` the default `LR_COST` is announced, with
        // its fraction since upstream 796ef2d4.
        assert_eq!(
            announced_cost(&tx),
            Some(constants::LINK_REQUEST_STAMP_COST)
        );
        // `set_link_cost` clamps to `LINK_COST_CAP` and is announced as set.
        let cost = StampCost::from_f64(14.2);
        assert_eq!(tx.link_request_costs().set(dest.hash.0, 14.2), cost);
        assert_eq!(announced_cost(&tx), Some(cost));
        let cap = StampCost::from_whole(u32::from(constants::LINK_COST_CAP));
        assert_eq!(tx.link_request_costs().set(dest.hash.0, 1000.0), cap);
        assert_eq!(announced_cost(&tx), Some(cap));
        assert_eq!(
            tx.link_request_costs().set(dest.hash.0, 0.0),
            StampCost::ZERO
        );
        assert_eq!(announced_cost(&tx), Some(StampCost::ZERO));
    }

    #[test]
    fn dropping_the_stamper_stops_the_worker() {
        let (tx, _rx) = event::channel();
        let stamper = Stamper::with_targets(tx, None, fast_targets());
        stamper
            .enqueue_path_request(pr_job(0xCD, 0x02, None))
            .unwrap();
        let inner = Arc::clone(&stamper.inner);
        drop(stamper);
        let deadline = Instant::now() + RECV_TIMEOUT;
        while inner.lock_queues().worker_alive {
            assert!(Instant::now() < deadline, "worker did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn path_request_timeout_defaults_to_upstream_and_is_settable() {
        let (tx, _rx) = event::channel();
        let stamper = Stamper::new(tx, None);
        assert_eq!(
            stamper.path_request_timeout(),
            Duration::from_secs(constants::PATH_REQUEST_STAMP_TIMEOUT)
        );
        stamper.set_path_request_timeout(Duration::from_millis(20));
        assert_eq!(stamper.path_request_timeout(), Duration::from_millis(20));
    }

    #[test]
    fn path_request_stamp_timeout_cancels_emission() {
        // Transport.stamp_path_request (d7749b0b): a watchdog cancels the
        // grind after PR_STAMP_TIMEOUT and the request is not emitted.
        let (tx, rx) = event::channel();
        let stamper = Stamper::with_targets(
            tx,
            None,
            StampTargets {
                path_request_value: StampCost::from_whole(u32::from(constants::STAMP_COST_CAP)),
                ..fast_targets()
            },
        );
        stamper.set_path_request_timeout(Duration::from_millis(50));
        let started = Instant::now();
        stamp_path_request(&stamper.inner, pr_job(0xEE, 0x03, Some(2)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the grind must stop at the timeout"
        );
        assert!(
            rx.try_recv().is_err(),
            "no stamped path request is emitted after a timeout"
        );
        assert_eq!(
            stamper.cached_path_request_stamps(),
            0,
            "a cancelled grind is not cached"
        );

        // The same job at a reachable value within the timeout is emitted.
        stamper.set_targets(fast_targets());
        stamper.set_path_request_timeout(Duration::from_secs(60));
        stamp_path_request(&stamper.inner, pr_job(0xEE, 0x03, Some(2)));
        let event = rx.recv_timeout(RECV_TIMEOUT).unwrap();
        assert!(matches!(event, Event::SendStampedPathRequest(_)));
    }

    #[test]
    fn destination_target_value_is_clamped_between_default_and_cap() {
        // Destination.target_value = min(STAMP_COST_CAP,
        // max(_target_value, DESTINATION_VALUE)).
        let (job, _) = announce_job(0x55);
        let mut dest = job.dest;
        let targets = StampTargets::default();
        assert_eq!(targets.destination_value, StampCost::from_whole(25));
        assert_eq!(targets.destination_target(&dest), StampCost::from_whole(25));
        dest.set_value(10.0);
        assert_eq!(
            targets.destination_target(&dest),
            StampCost::from_whole(25),
            "a lower target still generates at least the default"
        );
        dest.set_value(40.75);
        assert_eq!(
            targets.destination_target(&dest),
            StampCost::from_f64(40.75)
        );
        dest.set_value(255.0);
        let cap = StampCost::from_whole(u32::from(constants::STAMP_COST_CAP));
        assert_eq!(dest.target_value, Some(cap));
        assert_eq!(
            targets.destination_target(&dest),
            StampCost::from_whole(u32::from(constants::STAMP_COST_CAP))
        );
        // A configured default above the destination's own target wins.
        dest.set_value(30.0);
        let raised = StampTargets {
            destination_value: StampCost::from_whole(35),
            ..targets
        };
        assert_eq!(raised.destination_target(&dest), StampCost::from_whole(35));
    }
}
