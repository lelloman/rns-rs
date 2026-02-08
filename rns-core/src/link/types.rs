use alloc::vec::Vec;
use core::fmt;

/// Link identifier — truncated hash of the LINKREQUEST hashable part.
pub type LinkId = [u8; 16];

/// Link lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Pending,
    Handshake,
    Active,
    Stale,
    Closed,
}

/// Reason a link was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    Timeout,
    InitiatorClosed,
    DestinationClosed,
}

/// Link encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    Aes128Cbc,
    Aes256Cbc,
}

impl LinkMode {
    pub fn mode_byte(self) -> u8 {
        match self {
            LinkMode::Aes128Cbc => 0x00,
            LinkMode::Aes256Cbc => 0x01,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, LinkError> {
        match b {
            0x00 => Ok(LinkMode::Aes128Cbc),
            0x01 => Ok(LinkMode::Aes256Cbc),
            _ => Err(LinkError::UnsupportedMode),
        }
    }

    /// Derived key length for this mode (bytes).
    pub fn derived_key_length(self) -> usize {
        match self {
            LinkMode::Aes128Cbc => 32,
            LinkMode::Aes256Cbc => 64,
        }
    }
}

/// Actions produced by LinkEngine for the caller to dispatch.
#[derive(Debug, Clone)]
pub enum LinkAction {
    /// Link state changed.
    StateChanged {
        link_id: LinkId,
        new_state: LinkState,
        reason: Option<TeardownReason>,
    },
    /// Decrypted data received for application dispatch.
    DataReceived {
        link_id: LinkId,
        plaintext: Vec<u8>,
        context: u8,
    },
    /// Remote peer identified via LINKIDENTIFY.
    RemoteIdentified {
        link_id: LinkId,
        identity_hash: [u8; 16],
        public_key: [u8; 64],
    },
    /// Link fully established.
    LinkEstablished {
        link_id: LinkId,
        rtt: f64,
        is_initiator: bool,
    },
}

/// Errors in link operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    InvalidState,
    InvalidData,
    InvalidSignature,
    UnsupportedMode,
    CryptoError,
    NoSessionKey,
    HandshakeFailed,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::InvalidState => write!(f, "Invalid link state"),
            LinkError::InvalidData => write!(f, "Invalid data"),
            LinkError::InvalidSignature => write!(f, "Invalid signature"),
            LinkError::UnsupportedMode => write!(f, "Unsupported link mode"),
            LinkError::CryptoError => write!(f, "Cryptographic error"),
            LinkError::NoSessionKey => write!(f, "No session key established"),
            LinkError::HandshakeFailed => write!(f, "Handshake failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_mode_byte_roundtrip() {
        assert_eq!(LinkMode::from_byte(LinkMode::Aes128Cbc.mode_byte()).unwrap(), LinkMode::Aes128Cbc);
        assert_eq!(LinkMode::from_byte(LinkMode::Aes256Cbc.mode_byte()).unwrap(), LinkMode::Aes256Cbc);
    }

    #[test]
    fn test_link_mode_invalid() {
        assert_eq!(LinkMode::from_byte(0x05), Err(LinkError::UnsupportedMode));
    }

    #[test]
    fn test_derived_key_length() {
        assert_eq!(LinkMode::Aes128Cbc.derived_key_length(), 32);
        assert_eq!(LinkMode::Aes256Cbc.derived_key_length(), 64);
    }

    #[test]
    fn test_link_state_values() {
        assert_ne!(LinkState::Pending, LinkState::Active);
        assert_eq!(LinkState::Closed, LinkState::Closed);
    }

    #[test]
    fn test_teardown_reason_values() {
        assert_ne!(TeardownReason::Timeout, TeardownReason::InitiatorClosed);
    }
}
