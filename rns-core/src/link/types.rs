use alloc::vec::Vec;
use core::fmt;

/// Link identifier — truncated hash of the LINKREQUEST hashable part.
pub type LinkId = [u8; 16];

/// Link lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Initiator sent the link request and waits for the proof.
    Pending,
    /// Responder sent the proof and waits for the RTT packet.
    Handshake,
    /// Handshake complete; data can flow.
    Active,
    /// Nothing heard from the peer for the stale time; closes on the next watchdog run unless traffic arrives.
    Stale,
    /// Link is closed.
    Closed,
}

/// Reason a link was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    /// Establishment timed out, or the link went stale and was closed.
    Timeout,
    /// The initiator closed the link.
    InitiatorClosed,
    /// The destination (responder) closed the link.
    DestinationClosed,
}

/// Link encryption mode.
///
/// Both CBC modes are wire values, but as upstream's `Link.ENABLED_MODES`
/// only AES-256-CBC is enabled: see [`LinkMode::is_enabled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// AES-128 in CBC mode (mode byte `0x00`), as upstream's `Link.MODE_AES128_CBC`.
    Aes128Cbc,
    /// AES-256 in CBC mode (mode byte `0x01`), as upstream's `Link.MODE_AES256_CBC`.
    Aes256Cbc,
}

impl LinkMode {
    /// The modes links may use, upstream's `Link.ENABLED_MODES`.
    pub const ENABLED: [LinkMode; 1] = [LinkMode::Aes256Cbc];

    /// Whether links may use this mode. Upstream refuses any other mode
    /// when an initiator creates a link, and drops a link request that
    /// signals one without sending a proof.
    pub fn is_enabled(self) -> bool {
        Self::ENABLED.contains(&self)
    }

    /// The mode's name in upstream's `Link.MODE_DESCRIPTIONS`.
    pub fn description(self) -> &'static str {
        match self {
            LinkMode::Aes128Cbc => "AES_128_CBC",
            LinkMode::Aes256Cbc => "AES_256_CBC",
        }
    }

    /// Mode value as carried in link request and proof signalling.
    pub fn mode_byte(self) -> u8 {
        match self {
            LinkMode::Aes128Cbc => 0x00,
            LinkMode::Aes256Cbc => 0x01,
        }
    }

    /// Parse a mode value; fails with [`LinkError::UnsupportedMode`] for any other value.
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
        /// Link whose state changed.
        link_id: LinkId,
        /// State the link moved to.
        new_state: LinkState,
        /// Why the link closed; `None` unless `new_state` is [`LinkState::Closed`].
        reason: Option<TeardownReason>,
    },
    /// Decrypted data received for application dispatch.
    DataReceived {
        /// Link the data arrived on.
        link_id: LinkId,
        /// Decrypted payload.
        plaintext: Vec<u8>,
        /// Packet context byte.
        context: u8,
    },
    /// Remote peer identified via LINKIDENTIFY.
    RemoteIdentified {
        /// Link the peer identified on.
        link_id: LinkId,
        /// Truncated hash of the peer's identity.
        identity_hash: [u8; 16],
        /// Peer's public key (X25519 then Ed25519).
        public_key: [u8; 64],
    },
    /// Link fully established.
    LinkEstablished {
        /// Link that became active.
        link_id: LinkId,
        /// Measured round-trip time in seconds.
        rtt: f64,
        /// Whether this end initiated the link.
        is_initiator: bool,
    },
    /// The watchdog wants a keepalive probe (`0xff`, context KEEPALIVE)
    /// sent on the link. Only initiators send them; the engine has already
    /// recorded it as sent.
    SendKeepalive {
        /// Link to send the keepalive on.
        link_id: LinkId,
    },
}

/// Errors in link operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Operation is not valid in the link's current state or role.
    InvalidState,
    /// Packet data is malformed.
    InvalidData,
    /// A key or signature failed to parse or verify.
    InvalidSignature,
    /// Link mode is unknown or differs from the requested one.
    UnsupportedMode,
    /// The link mode is defined but not enabled; only
    /// [`LinkMode::ENABLED`] modes may be used.
    ModeNotEnabled(LinkMode),
    /// Key derivation, signing, encryption or decryption failed.
    CryptoError,
    /// No session key has been derived yet.
    NoSessionKey,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::InvalidState => write!(f, "Invalid link state"),
            LinkError::InvalidData => write!(f, "Invalid data"),
            LinkError::InvalidSignature => write!(f, "Invalid signature"),
            LinkError::UnsupportedMode => write!(f, "Unsupported link mode"),
            // Upstream's text, which it logs when it drops such a request.
            LinkError::ModeNotEnabled(mode) => {
                write!(f, "Requested link mode {} not enabled", mode.description())
            }
            LinkError::CryptoError => write!(f, "Cryptographic error"),
            LinkError::NoSessionKey => write!(f, "No session key established"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_mode_byte_roundtrip() {
        assert_eq!(
            LinkMode::from_byte(LinkMode::Aes128Cbc.mode_byte()).unwrap(),
            LinkMode::Aes128Cbc
        );
        assert_eq!(
            LinkMode::from_byte(LinkMode::Aes256Cbc.mode_byte()).unwrap(),
            LinkMode::Aes256Cbc
        );
    }

    #[test]
    fn only_aes_256_cbc_is_enabled() {
        assert!(LinkMode::Aes256Cbc.is_enabled());
        assert!(!LinkMode::Aes128Cbc.is_enabled());
        assert_eq!(
            LinkError::ModeNotEnabled(LinkMode::Aes128Cbc).to_string(),
            "Requested link mode AES_128_CBC not enabled"
        );
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
