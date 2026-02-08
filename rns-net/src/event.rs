//! Event types for the driver loop.

use std::fmt;
use std::sync::mpsc;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use crate::interface::Writer;

/// Events sent to the driver thread.
pub enum Event {
    /// A decoded frame arrived from an interface.
    Frame { interface_id: InterfaceId, data: Vec<u8> },
    /// An interface came online after (re)connecting.
    /// Carries a new writer if the connection was re-established.
    /// Carries InterfaceInfo if this is a new dynamic interface (e.g. TCP server client).
    InterfaceUp(InterfaceId, Option<Box<dyn Writer>>, Option<InterfaceInfo>),
    /// An interface went offline (socket closed, error).
    InterfaceDown(InterfaceId),
    /// Periodic maintenance tick (1s interval).
    Tick,
    /// Shut down the driver loop.
    Shutdown,
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Frame { interface_id, data } => {
                f.debug_struct("Frame")
                    .field("interface_id", interface_id)
                    .field("data_len", &data.len())
                    .finish()
            }
            Event::InterfaceUp(id, writer, info) => {
                f.debug_tuple("InterfaceUp")
                    .field(id)
                    .field(&writer.is_some())
                    .field(&info.is_some())
                    .finish()
            }
            Event::InterfaceDown(id) => f.debug_tuple("InterfaceDown").field(id).finish(),
            Event::Tick => write!(f, "Tick"),
            Event::Shutdown => write!(f, "Shutdown"),
        }
    }
}

pub type EventSender = mpsc::Sender<Event>;
pub type EventReceiver = mpsc::Receiver<Event>;

pub fn channel() -> (EventSender, EventReceiver) {
    mpsc::channel()
}
