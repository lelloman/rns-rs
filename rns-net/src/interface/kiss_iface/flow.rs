//! A KISS port's flow control and beacon, without I/O.
//!
//! Both ways of running a port (reader and writer threads, or the driver
//! loop, see [`crate::engine::FOLD_IO`]) keep one [`FlowState`] per port and
//! write the frames it hands back themselves.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{Ax25Address, KissIfaceConfig};
use crate::kiss;

/// How long flow control waits for the TNC's ready report before sending
/// the next frame anyway.
pub(super) const FLOW_TIMEOUT: Duration = Duration::from_secs(5);

/// A beacon is padded to at least this many bytes.
pub(super) const BEACON_MIN_LEN: usize = 15;

/// KISS-frame `data`, wrapped in an AX.25 UI frame first when the port
/// has an AX.25 source address.
pub(super) fn frame(ax25_source: Option<&Ax25Address>, data: &[u8]) -> Vec<u8> {
    match ax25_source {
        Some(source) => kiss::frame(&super::super::ax25_kiss::encode_ui_frame(source, data)),
        None => kiss::frame(data),
    }
}

/// The beacon (upstream's station ID): sent `interval` after the first
/// frame written since the last beacon.
pub(super) struct Beacon {
    interval: Duration,
    /// The framed beacon, padded to [`BEACON_MIN_LEN`].
    frame: Vec<u8>,
}

impl Beacon {
    /// The port's beacon, if it has both an interval and data.
    pub(super) fn from_config(config: &KissIfaceConfig) -> Option<Self> {
        let (interval, data) = (config.beacon_interval?, config.beacon_data.as_ref()?);
        let mut padded = data.clone();
        padded.resize(padded.len().max(BEACON_MIN_LEN), 0);
        Some(Self {
            interval: Duration::from_secs(interval.into()),
            frame: kiss::frame(&padded),
        })
    }
}

/// Flow control and the beacon interval of one port.
pub(super) struct FlowState {
    pub(super) flow_control: bool,
    /// Whether the TNC may take a frame now (always, without flow control).
    pub(super) ready: bool,
    /// When flow control was last locked.
    pub(super) lock_time: Instant,
    /// Framed data held until the TNC reports ready, and its size.
    pub(super) queue: VecDeque<Vec<u8>>,
    pub(super) queue_bytes: usize,
    /// When a frame other than the beacon was first written since the last
    /// beacon (upstream's `first_tx`).
    pub(super) first_tx: Option<Instant>,
}

impl FlowState {
    pub(super) fn new(flow_control: bool) -> Self {
        Self {
            flow_control,
            ready: true,
            lock_time: Instant::now(),
            queue: VecDeque::new(),
            queue_bytes: 0,
            first_tx: None,
        }
    }

    /// Whether a frame would be written now rather than held for the TNC.
    pub(super) fn sends_now(&self) -> bool {
        !self.flow_control || (self.ready && self.queue.is_empty())
    }

    /// Note that a data frame is written now: it locks flow control until
    /// the TNC reports ready again and, as upstream, starts the beacon
    /// interval, with flow control or without.
    pub(super) fn transmit(&mut self) {
        if self.flow_control {
            self.ready = false;
            self.lock_time = Instant::now();
        }
        self.first_tx.get_or_insert_with(Instant::now);
    }

    /// Take a framed data frame: returned to be written now, or held until
    /// the TNC is ready.
    pub(super) fn submit(&mut self, frame: Vec<u8>) -> Option<Vec<u8>> {
        if self.sends_now() {
            self.transmit();
            return Some(frame);
        }
        self.queue_bytes += frame.len();
        self.queue.push_back(frame);
        None
    }

    /// The TNC is ready: returns the next held frame to write, or notes it
    /// is ready.
    pub(super) fn tnc_ready(&mut self) -> Option<Vec<u8>> {
        match self.queue.pop_front() {
            Some(frame) => {
                self.queue_bytes -= frame.len();
                self.transmit();
                Some(frame)
            }
            None => {
                self.ready = true;
                None
            }
        }
    }

    /// Unlock flow control the TNC left locked too long: returns the next
    /// held frame to write, if any.
    pub(super) fn unlock_if_stuck(&mut self, name: &str) -> Option<Vec<u8>> {
        if !self.flow_control || self.ready || self.lock_time.elapsed() <= FLOW_TIMEOUT {
            return None;
        }
        log::warn!("[{}] unlocking flow control due to timeout", name);
        self.tnc_ready()
    }

    /// The beacon frame to write now, if one is due; call
    /// [`Self::beacon_sent`] once it is written.
    pub(super) fn due_beacon<'a>(
        &self,
        beacon: Option<&'a Beacon>,
        name: &str,
    ) -> Option<&'a [u8]> {
        let beacon = beacon?;
        if self.first_tx?.elapsed() <= beacon.interval {
            return None;
        }
        log::debug!("[{}] transmitting beacon data", name);
        Some(&beacon.frame)
    }

    /// The beacon was written: the interval restarts with the next frame.
    pub(super) fn beacon_sent(&mut self) {
        self.first_tx = None;
    }

    /// Drop the frames held for the TNC.
    pub(super) fn discard_queue(&mut self) {
        self.queue.clear();
        self.queue_bytes = 0;
    }

    /// A reopened port: the TNC is ready and nothing is held.
    pub(super) fn reset(&mut self) {
        self.ready = true;
        self.discard_queue();
    }
}
