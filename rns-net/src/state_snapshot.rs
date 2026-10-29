//! A copy of link and interface statistics the driver publishes for readers
//! that must not wait on the driver's event queue.
//!
//! [`crate::RnsNode::query`] answers from the driver thread, in order with
//! every other control event: behind a burst of thousands of queued sends a
//! query waits for all of them, and while the driver is blocked (for example
//! in an application callback) it does not return at all. That ordering is
//! what makes a query a barrier, so it stays. This module adds the cheap
//! alternative: the driver replaces a shared [`StateSnapshot`] on its periodic
//! tick and when link or interface state changes, and readers take the latest
//! one under a lock held only for an `Arc` clone.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::event::{InterfaceStatsResponse, LinkInfoEntry};

/// Link and interface statistics as the driver last published them.
///
/// A snapshot is a consistent copy taken in one go on the driver thread, but
/// it is not live: it may lag the driver by up to one tick interval
/// (`global.tick_interval_ms`, 1 s by default) and by however long the driver
/// was blocked. It is not an ordering barrier either: events queued before
/// the read, such as sends, may not be reflected. Use
/// [`crate::RnsNode::query`], [`crate::RnsNode::links`] or
/// [`crate::RnsNode::query_link`] for an exact answer ordered after earlier
/// events.
#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    /// Increases by one with each publish; 0 means the driver has not
    /// published yet and the snapshot is empty.
    pub sequence: u64,
    /// Wall-clock time of the publish, in seconds since the Unix epoch
    /// (0.0 before the first publish).
    pub published_at: f64,
    /// Every link the driver manages, as [`crate::RnsNode::links`] reports
    /// them at publish time.
    pub links: Vec<LinkInfoEntry>,
    /// Interface statistics, as [`crate::QueryRequest::InterfaceStats`]
    /// reports them at publish time.
    pub interfaces: InterfaceStatsResponse,
}

impl StateSnapshot {
    /// The link with `link_id`, if it existed at publish time.
    pub fn link(&self, link_id: &[u8; 16]) -> Option<&LinkInfoEntry> {
        self.links.iter().find(|link| &link.link_id == link_id)
    }
}

/// The published snapshot, shared between the driver and its handles.
#[derive(Debug, Default)]
pub(crate) struct SnapshotCell {
    current: RwLock<Arc<StateSnapshot>>,
}

impl SnapshotCell {
    /// The latest published snapshot. Never waits on the driver: the lock is
    /// held by a publisher only to swap a pointer.
    pub(crate) fn load(&self) -> Arc<StateSnapshot> {
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Replace the published snapshot.
    pub(crate) fn store(&self, snapshot: StateSnapshot) {
        let snapshot = Arc::new(snapshot);
        // Drop the previous snapshot after releasing the lock.
        let _previous = std::mem::replace(
            &mut *self.current.write().unwrap_or_else(|p| p.into_inner()),
            snapshot,
        );
    }
}

/// When the driver publishes: on every tick, as soon as a state change was
/// marked, and from the event loop when ticks are stuck behind a long queue.
#[derive(Debug)]
pub(crate) struct PublishSchedule {
    /// A link or interface changed state since the last publish.
    dirty: bool,
    /// Managed links at the last publish; a link created or removed without
    /// an explicit mark still triggers a publish.
    link_count: usize,
    sequence: u64,
    last_published: Option<Instant>,
    /// Events handled since the event loop last checked the publish age.
    events_since_check: u32,
}

/// The event loop checks the publish age once per this many events, so a
/// saturated driver pays one clock read per batch.
const AGE_CHECK_EVENTS: u32 = 64;

impl Default for PublishSchedule {
    fn default() -> Self {
        Self {
            // Publish the initial state on the first loop iteration.
            dirty: true,
            link_count: 0,
            sequence: 0,
            last_published: None,
            events_since_check: 0,
        }
    }
}

impl PublishSchedule {
    pub(crate) fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Whether state changed since the last publish, given the number of
    /// links the driver now manages.
    pub(crate) fn needs_publish(&self, link_count: usize) -> bool {
        self.dirty || link_count != self.link_count
    }

    /// Count one handled event; true when the last publish is older than
    /// `max_age`, so a tick queued behind the backlog does not hold the
    /// snapshot back.
    pub(crate) fn event_handled(&mut self, max_age: Duration) -> bool {
        self.events_since_check += 1;
        if self.events_since_check < AGE_CHECK_EVENTS {
            return false;
        }
        self.events_since_check = 0;
        self.last_published
            .is_none_or(|published| published.elapsed() >= max_age)
    }

    /// Record a publish of `link_count` links and return its sequence number.
    pub(crate) fn published(&mut self, link_count: usize) -> u64 {
        self.dirty = false;
        self.link_count = link_count;
        self.events_since_check = 0;
        self.last_published = Some(Instant::now());
        self.sequence += 1;
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_starts_empty_and_returns_the_latest_store() {
        let cell = SnapshotCell::default();
        let held = cell.load();
        assert_eq!(held.sequence, 0);
        assert!(held.links.is_empty());
        cell.store(StateSnapshot {
            sequence: 1,
            published_at: 5.0,
            ..Default::default()
        });
        assert_eq!(cell.load().sequence, 1);
        // An earlier reader keeps its copy.
        assert_eq!(held.sequence, 0);
    }

    #[test]
    fn schedule_checks_age_once_per_batch() {
        let mut schedule = PublishSchedule::default();
        assert!(schedule.needs_publish(0));
        assert_eq!(schedule.published(0), 1);
        assert!(!schedule.needs_publish(0));
        assert!(schedule.needs_publish(1));
        for _ in 0..AGE_CHECK_EVENTS - 1 {
            assert!(!schedule.event_handled(Duration::ZERO));
        }
        assert!(schedule.event_handled(Duration::ZERO));
        for _ in 0..AGE_CHECK_EVENTS {
            assert!(!schedule.event_handled(Duration::from_secs(3600)));
        }
        schedule.mark_dirty();
        assert!(schedule.needs_publish(0));
        assert_eq!(schedule.published(1), 2);
        assert!(!schedule.needs_publish(1));
    }
}
