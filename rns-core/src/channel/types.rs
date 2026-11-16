use alloc::vec::Vec;
use core::fmt;

pub type MessageType = u16;
pub type Sequence = u16;

/// Actions produced by Channel for the caller to dispatch.
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelAction {
    /// Send plaintext envelope bytes on the link with CHANNEL context.
    SendOnLink { raw: Vec<u8>, sequence: Sequence },
    /// Message received and decoded.
    MessageReceived {
        msgtype: MessageType,
        payload: Vec<u8>,
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
    NotReady,
    MessageTooBig,
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
