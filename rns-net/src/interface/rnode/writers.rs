//! Each subinterface's writer and the flow control it waits on.

use super::*;

/// Writer for a specific RNode subinterface.
/// Wraps a shared serial writer with subinterface-specific data framing.
pub(super) struct RNodeSubWriter {
    pub(super) confirmed_pending: Option<Vec<u8>>,
    pub(super) writer: Arc<Mutex<DeviceWriter>>,
    pub(super) index: u8,
    pub(super) flow_control: bool,
    pub(super) flow_state: Arc<Mutex<SubFlowState>>,
    pub(super) multi: bool,
}

pub(super) struct SubFlowState {
    pub(super) ready: bool,
    pub(super) queue: std::collections::VecDeque<Vec<u8>>,
    /// When a frame other than the station ID was first written since the
    /// last ID (upstream's `first_tx`).
    pub(super) first_tx: Option<std::time::Instant>,
    /// The station ID callsign, when the interface identifies itself.
    pub(super) station_id: Option<Arc<[u8]>>,
}

impl SubFlowState {
    /// A subinterface ready to send, identifying with `station_id`.
    pub(super) fn new(station_id: Option<Arc<[u8]>>) -> Self {
        Self {
            ready: true,
            queue: std::collections::VecDeque::new(),
            first_tx: None,
            station_id,
        }
    }

    /// Whether a frame would be written now rather than queued.
    fn sends_now(&self, flow_control: bool) -> bool {
        !flow_control || (self.ready && self.queue.is_empty())
    }

    /// Note that a frame of the interface's traffic is written now: with
    /// flow control, nothing more is until the device reports ready.
    fn transmit(&mut self, flow_control: bool) {
        if flow_control {
            self.ready = false;
        }
        self.first_tx.get_or_insert_with(std::time::Instant::now);
    }

    /// Note that `data` was written: the station ID restarts the interval,
    /// anything else starts it if it is not running.
    fn wrote(&mut self, data: &[u8]) {
        if self.station_id.as_deref() == Some(data) {
            self.first_tx = None;
        } else {
            self.first_tx.get_or_insert_with(std::time::Instant::now);
        }
    }
}

pub(super) fn make_sub_writer(
    writer: Arc<Mutex<DeviceWriter>>,
    index: u8,
    flow_control: bool,
    flow_state: Arc<Mutex<SubFlowState>>,
    multi: bool,
) -> Box<dyn Writer> {
    Box::new(RNodeSubWriter {
        confirmed_pending: None,
        writer,
        index,
        flow_control,
        flow_state,
        multi,
    })
}

impl Writer for RNodeSubWriter {
    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.flow_control {
            return self.send_frame(data);
        }
        self.confirmed_pending = Some(self.frame(data));
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(frame) = self.confirmed_pending.as_deref() else {
            return Ok(());
        };
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        if !state.sends_now(true) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.transmit(true);
        drop(state);
        let written = lock_or_recover(&self.writer, "rnode shared writer").write_all(frame);
        self.confirmed_pending = None;
        written
    }
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        if !state.sends_now(self.flow_control) {
            state.queue.push_back(data.to_vec());
            return Ok(());
        }
        state.transmit(self.flow_control);
        drop(state);
        let frame = self.frame(data);
        lock_or_recover(&self.writer, "rnode shared writer").write_all(&frame)
    }

    fn enqueue_confirmed(
        &mut self,
        data: &[u8],
        completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        // Driver-run (see `sends_inline`): a confirmed frame is taken only
        // when it is written at once; else WouldBlock leaves the completion
        // untouched and the driver retries.
        let frame = self.frame(data);
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        let mut writer = lock_or_recover(&self.writer, "rnode shared writer");
        if !state.sends_now(self.flow_control) || !writer.fits(frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RNode cannot take a frame yet",
            ));
        }
        writer.write_all(&frame)?;
        state.transmit(self.flow_control);
        drop((writer, state));
        if let Some(completion) = completion.take() {
            completion.finish(Ok(()));
        }
        Ok(())
    }

    fn sends_inline(&self) -> bool {
        // With interface I/O folded the shared device writer never blocks.
        crate::engine::FOLD_IO
    }

    fn flush_pending(&mut self) {
        lock_or_recover(&self.writer, "rnode shared writer").drain();
    }
}

impl RNodeSubWriter {
    pub(super) fn frame(&self, data: &[u8]) -> Vec<u8> {
        data_frame(self.multi, self.index, data)
    }
}

/// A data frame for the radio at `index`, addressed by virtual port on a
/// multi-radio device.
fn data_frame(multi: bool, index: u8, data: &[u8]) -> Vec<u8> {
    if multi {
        rnode_kiss::rnode_multi_data_frame(index, data)
    } else {
        rnode_kiss::rnode_data_frame(index, data)
    }
}

pub(super) type RNodeWriters = Vec<(InterfaceId, Box<dyn Writer>)>;

pub(super) fn reset_flow_states(flow_states: &[Arc<Mutex<SubFlowState>>]) {
    for flow_state in flow_states {
        let mut state = lock_or_recover(flow_state, "rnode flow state");
        state.ready = true;
        state.queue.clear();
    }
}

/// Process flow control queue for a subinterface.
pub(super) fn process_flow_queue(
    flow_state: &Arc<Mutex<SubFlowState>>,
    writer: &Arc<Mutex<DeviceWriter>>,
    index: u8,
    multi: bool,
) {
    let mut state = lock_or_recover(flow_state, "rnode flow state");
    if let Some(data) = state.queue.pop_front() {
        state.ready = false;
        state.wrote(&data);
        drop(state);
        let frame = data_frame(multi, index, &data);
        // A device that fails is noticed and reopened by the reader.
        if let Err(e) = lock_or_recover(writer, "rnode shared writer").write_all(&frame) {
            log::debug!("rnode subinterface {index}: queued frame not written: {e}");
        }
    } else {
        state.ready = true;
    }
}

/// Upstream's station identification: once `id_interval` seconds have
/// passed since the first frame sent after the last identification, send
/// `id_callsign` on every subinterface, through flow control as any frame.
/// Returns when it is next due, if a frame is waiting for one.
pub(super) fn identify_station(
    config: &RNodeConfig,
    flow_states: &[Arc<Mutex<SubFlowState>>],
    writer: &Arc<Mutex<DeviceWriter>>,
) -> Option<std::time::Instant> {
    let callsign = config.id_callsign.as_deref()?;
    let due = station_id_due(config, flow_states)?;
    if std::time::Instant::now() <= due {
        return Some(due);
    }
    if config.multi {
        log::debug!(
            "Interface RNodeMultiInterface[{}] is transmitting beacon data on all subinterfaces: {}",
            config.name,
            String::from_utf8_lossy(callsign)
        );
    } else {
        log::debug!(
            "Interface {} is transmitting beacon data: {}",
            super::setup::display_name(config),
            String::from_utf8_lossy(callsign)
        );
    }
    for (fs, sub) in flow_states.iter().zip(&config.subinterfaces) {
        let mut state = lock_or_recover(fs, "rnode flow state");
        state.first_tx = None;
        if sub.flow_control && !state.ready {
            state.queue.push_back(callsign.to_vec());
            continue;
        }
        if sub.flow_control {
            state.ready = false;
        }
        drop(state);
        let frame = data_frame(config.multi, sub.vport, callsign);
        if let Err(e) = lock_or_recover(writer, "rnode shared writer").write_all(&frame) {
            log::debug!("[{}] station ID not written: {e}", config.name);
        }
    }
    None
}

/// When the station ID is next due: `id_interval` after the first frame
/// sent since the last one, if any was.
pub(super) fn station_id_due(
    config: &RNodeConfig,
    flow_states: &[Arc<Mutex<SubFlowState>>],
) -> Option<std::time::Instant> {
    let interval = config.id_interval?;
    config.id_callsign.as_ref()?;
    let first_tx = flow_states
        .iter()
        .filter_map(|fs| lock_or_recover(fs, "rnode flow state").first_tx)
        .min()?;
    Some(first_tx + Duration::from_secs(u64::from(interval)))
}
