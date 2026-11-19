use alloc::vec::Vec;
use core::fmt;

/// Channel message type, carried in each envelope.
pub type MessageType = u16;
/// Envelope sequence number; wraps at `CHANNEL_SEQ_MODULUS`.
pub type Sequence = u16;

/// Actions produced by Channel for the caller to dispatch.
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelAction {
    /// Send plaintext envelope bytes on the link with CHANNEL context.
    SendOnLink {
        /// Packed envelope.
        raw: Vec<u8>,
        /// Envelope sequence number.
        sequence: Sequence,
    },
    /// Message received and decoded.
    MessageReceived {
        /// Message type from the envelope.
        msgtype: MessageType,
        /// Message payload.
        payload: Vec<u8>,
        /// Envelope sequence number.
        sequence: Sequence,
    },
    /// Max retries exceeded — tear down the link.
    TeardownLink,
    /// Max retries exceeded while the link runs over a path it can fall
    /// back from (see [`Channel::set_hold_on_exhaustion`]): the caller
    /// should switch the link to its other path. Every outstanding envelope
    /// is resent, with its tries reset, by the `SendOnLink` actions that
    /// follow.
    ///
    /// [`Channel::set_hold_on_exhaustion`]: super::Channel::set_hold_on_exhaustion
    PathFailed,
}

/// Errors in channel operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Send window is full.
    NotReady,
    /// Packed envelope exceeds the link MDU.
    MessageTooBig,
    /// Envelope is shorter than its header or its declared length.
    InvalidEnvelope,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelError::NotReady => write!(f, "Channel is not ready to send"),
            ChannelError::MessageTooBig => write!(f, "Message too big for packet"),
            ChannelError::InvalidEnvelope => write!(f, "Invalid envelope data"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_error_display() {
        assert_eq!(
            format!("{}", ChannelError::NotReady),
            "Channel is not ready to send"
        );
    }
}
