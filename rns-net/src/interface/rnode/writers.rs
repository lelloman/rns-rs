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
        self.confirmed_pending = Some(if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        });
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(frame) = self.confirmed_pending.as_deref() else {
            return Ok(());
        };
        let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
        if !state.ready || !state.queue.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.ready = false;
        drop(state);
        let written = lock_or_recover(&self.writer, "rnode shared writer").write_all(frame);
        self.confirmed_pending = None;
        written
    }
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        };
        if self.flow_control {
            let mut state = lock_or_recover(&self.flow_state, "rnode flow state");
            if state.ready {
                state.ready = false;
                drop(state);
                lock_or_recover(&self.writer, "rnode shared writer").write_all(&frame)
            } else {
                state.queue.push_back(data.to_vec());
                Ok(())
            }
        } else {
            lock_or_recover(&self.writer, "rnode shared writer").write_all(&frame)
        }
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
        if (self.flow_control && (!state.ready || !state.queue.is_empty()))
            || !writer.fits(frame.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "RNode cannot take a frame yet",
            ));
        }
        writer.write_all(&frame)?;
        if self.flow_control {
            state.ready = false;
        }
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
        if self.multi {
            rnode_kiss::rnode_multi_data_frame(self.index, data)
        } else {
            rnode_kiss::rnode_data_frame(self.index, data)
        }
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
        drop(state);
        let frame = if multi {
            rnode_kiss::rnode_multi_data_frame(index, &data)
        } else {
            rnode_kiss::rnode_data_frame(index, &data)
        };
        // A device that fails is noticed and reopened by the reader.
        if let Err(e) = lock_or_recover(writer, "rnode shared writer").write_all(&frame) {
            log::debug!("rnode subinterface {index}: queued frame not written: {e}");
        }
    } else {
        state.ready = true;
    }
}
