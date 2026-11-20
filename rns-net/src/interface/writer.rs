//! The [`Writer`] trait and the frame bytes it sends.

use std::io;
use std::time::Duration;

use super::{loop_writer, EgressControl};

/// Writable end of an interface. Held by the driver.
///
/// Each implementation wraps a socket + framing.
pub trait Writer: Send {
    /// Write one frame to the interface.
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    /// Write one frame without silently dropping it. WouldBlock means the
    /// frame was accepted and `flush` must finish it before success is reported.
    /// Writers with intentional drop policies must override this method.
    fn send_frame_confirmed(&mut self, data: &[u8]) -> io::Result<()> {
        self.send_frame(data)
    }

    /// Internal async-writer admission. Leaves completion untouched on failure.
    #[doc(hidden)]
    fn enqueue_confirmed(
        &mut self,
        _data: &[u8],
        _completion: &mut Option<crate::link_send::Completion>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "confirmed sends require an async interface writer",
        ))
    }

    /// Like [`Writer::send_frame`], but a writer with its own worker may
    /// postpone waking it until [`Writer::wake`]. The driver uses this for
    /// forwarded frames and wakes each touched writer once per event batch.
    fn send_frame_deferred(&mut self, data: &[u8]) -> io::Result<()> {
        self.send_frame(data)
    }

    /// Deferred send of shared frame bytes; writers with a worker queue may
    /// retain the shared buffer instead of copying it.
    fn send_shared_deferred(
        &mut self,
        data: &rns_core::transport::types::PacketBytes,
    ) -> io::Result<()> {
        self.send_frame_deferred(data)
    }

    /// Wake a worker postponed by [`Writer::send_frame_deferred`].
    fn wake(&mut self) {}

    /// Write out what a driver-run writer has buffered (see `loop_writer`).
    /// The driver calls this on every writer before it waits for more
    /// input, so frames from one pass leave in as few writes as possible.
    fn flush_pending(&mut self) {}

    /// Write several frames in order, stopping at the first error.
    fn send_frames(&mut self, frames: &[crate::interface::FrameBytes]) -> io::Result<()> {
        for frame in frames {
            self.send_frame(frame)?;
        }
        Ok(())
    }

    /// Resume bytes accepted by a previous call that returned `WouldBlock`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Share an exact byte admission budget with the async producer when this
    /// writer uses dataplane egress control.
    fn egress_control(&self) -> Option<EgressControl> {
        None
    }

    /// Whether the driver calls this writer directly, without a worker
    /// thread: its sends never block (a datagram the socket cannot take is
    /// dropped, as the network may drop it), and it settles confirmed sends
    /// itself through [`Writer::enqueue_confirmed`].
    fn sends_inline(&self) -> bool {
        false
    }

    /// A stream socket the driver may write directly, without a worker
    /// thread (see `loop_writer`). Writers returning one must only frame
    /// with HDLC and write the result to this descriptor.
    fn loop_socket(&self) -> Option<std::os::fd::RawFd> {
        None
    }

    /// Byte-budget egress rules for a [`Writer::loop_socket`] writer, taken
    /// once when the driver starts writing it. Without them the driver
    /// applies its default backpressure.
    #[doc(hidden)]
    fn loop_egress(&mut self) -> Option<loop_writer::LoopEgress> {
        None
    }

    /// For a [`Writer::loop_socket`] writer: write buffered frames once the
    /// oldest has waited this long, rather than only when the driver has
    /// handled everything it received. Trades CPU (more, smaller writes) for
    /// latency and throughput toward a peer that waits on these frames.
    fn loop_flush_after(&self) -> Option<Duration> {
        None
    }

    /// Called by the driver once per tick, so driver-run writers can detect
    /// a peer that stopped reading even when nothing new is sent.
    #[doc(hidden)]
    fn tick(&mut self) {}

    /// Release the interface as it is torn down.
    fn shutdown(&mut self) {}
}

/// Frame bytes queued for a writer: owned, or shared with the driver's
/// forwarding buffer so queueing a forwarded frame does not copy it.
pub enum FrameBytes {
    /// Bytes owned by the queue.
    Owned(Vec<u8>),
    /// Bytes shared with the driver.
    Shared(rns_core::transport::types::PacketBytes),
}

impl std::ops::Deref for FrameBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            FrameBytes::Owned(bytes) => bytes,
            FrameBytes::Shared(bytes) => bytes,
        }
    }
}

#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone",
    feature = "iface-i2p"
))]
pub(crate) struct UnavailableWriter;

#[cfg(any(
    feature = "iface-tcp",
    feature = "iface-serial",
    feature = "iface-kiss",
    feature = "iface-backbone",
    feature = "iface-i2p"
))]
impl Writer for UnavailableWriter {
    fn send_frame(&mut self, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "interface is not connected",
        ))
    }
}
