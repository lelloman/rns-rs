//! Reading stream sockets and accepting connections on the driver loop,
//! shared by the interfaces whose I/O runs there.

use std::io;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender, LoopContext};
use crate::hdlc;

/// Bytes read from one stream socket per readiness before other sources
/// get a turn; the socket is re-armed and served again on the next pass.
pub(crate) const STREAM_READ_BUDGET: usize = 256 * 1024;

/// How a read pass over a stream socket ended.
pub(crate) enum StreamRead {
    /// The socket is drained or the read budget is spent: watch it again.
    Rearm,
    /// Inbound data is full: read again once the driver has drained it, so
    /// TCP flow control slows the sender meanwhile.
    Suspend,
    /// The peer closed the connection.
    Closed,
    Failed(io::Error),
    /// The driver is gone.
    DriverGone,
}

/// Read a readable stream socket on the driver thread until it is empty or
/// [`STREAM_READ_BUDGET`] is spent, and queue the frames decoded from it,
/// reporting the bytes and frames of each read to `on_read`.
/// Reads nothing while inbound data is full, so data queued past capacity
/// is bounded by one read per socket.
pub(crate) fn read_stream_frames(
    fd: std::os::fd::RawFd,
    decoder: &mut hdlc::Decoder,
    cx: &mut LoopContext<'_>,
    tx: &EventSender,
    id: InterfaceId,
    name: &str,
    mut on_read: impl FnMut(usize, usize),
) -> StreamRead {
    if !tx.inbound_data_has_room() {
        return StreamRead::Suspend;
    }
    let mut read = 0;
    while read < STREAM_READ_BUDGET {
        // SAFETY: `cx.buf` is a valid writable buffer for the call.
        // MSG_DONTWAIT keeps the socket's own mode untouched.
        let n = unsafe {
            libc::recv(
                fd,
                cx.buf.as_mut_ptr().cast(),
                cx.buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return StreamRead::Rearm,
                io::ErrorKind::Interrupted => continue,
                _ => return StreamRead::Failed(e),
            }
        }
        if n == 0 {
            return StreamRead::Closed;
        }
        let n = n as usize;
        read += n;
        let decoded = decoder.feed_reused(&cx.buf[..n]);
        for &frame_len in &decoded.invalid_frame_lengths {
            log::debug!(
                "[{}] invalid HDLC frame of {} bytes received on interface {}, dropping frame",
                name,
                frame_len,
                id.0,
            );
        }
        on_read(n, decoded.frames.len());
        let frames = decoded.frames.drain(..).map(|frame| Event::Frame {
            interface_id: id,
            data: frame,
            rssi: None,
            snr: None,
        });
        match tx.push_from_loop(frames) {
            Ok(true) => {}
            Ok(false) => return StreamRead::Suspend,
            Err(_) => return StreamRead::DriverGone,
        }
        // A short read emptied the receive queue: another `recv` would only
        // return EAGAIN. Data or a close arriving later is reported again
        // (level-triggered) or after the re-arm (oneshot).
        if n < cx.buf.len() {
            break;
        }
    }
    StreamRead::Rearm
}

/// What the accept loop does after `accept` returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptStep {
    /// No connection is pending: wait for readiness.
    Drained,
    /// The error concerned one pending connection only: try the next one.
    Next,
    /// The error is likely to persist (e.g. out of descriptors or memory):
    /// stop watching the listener until the next tick.
    Pause,
}

pub(crate) fn accept_error_step(error: &io::Error) -> AcceptStep {
    match error.kind() {
        io::ErrorKind::WouldBlock => AcceptStep::Drained,
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable => AcceptStep::Next,
        // Linux reports some network errors of a pending connection
        // through accept; they concern that connection only.
        _ if error.raw_os_error() == Some(libc::EPROTO) => AcceptStep::Next,
        _ => AcceptStep::Pause,
    }
}
