use alloc::vec::Vec;
use core::fmt;

// --- Channel message type constants (0xFE00..=0xFE04) ---

pub const UPGRADE_REQUEST: u16 = 0xFE00;
pub const UPGRADE_ACCEPT: u16 = 0xFE01;
pub const UPGRADE_REJECT: u16 = 0xFE02;
pub const UPGRADE_READY: u16 = 0xFE03;
pub const UPGRADE_COMPLETE: u16 = 0xFE04;

/// Check if a channel message type is a hole-punch signaling message.
pub fn is_holepunch_msgtype(msgtype: u16) -> bool {
    (UPGRADE_REQUEST..=UPGRADE_COMPLETE).contains(&msgtype)
}

// --- Reject reasons ---

pub const REJECT_POLICY: u8 = 0x01;
pub const REJECT_BUSY: u8 = 0x02;
pub const REJECT_UNSUPPORTED: u8 = 0x03;

// --- Fail reasons ---

pub const FAIL_TIMEOUT: u8 = 0x01;
pub const FAIL_PROBE: u8 = 0x02;

// --- Timeouts (seconds) ---

/// Time to wait for UPGRADE_ACCEPT after sending UPGRADE_REQUEST.
pub const PROPOSE_TIMEOUT: f64 = 10.0;

/// Time to wait for endpoint discovery (probe).
pub const DISCOVER_TIMEOUT: f64 = 10.0;

/// Time to wait for UPGRADE_READY after receiving UPGRADE_ACCEPT.
pub const READY_TIMEOUT: f64 = 10.0;

/// Total time for the punch phase.
pub const PUNCH_TIMEOUT: f64 = 10.0;

/// Minimum interval between hole-punch proposals on the same link.
pub const PROPOSAL_COOLDOWN: f64 = 60.0;

/// Hole-punch engine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolePunchState {
    /// No active hole-punch session.
    Idle,
    /// Discovering our public endpoint via STUN probe.
    Discovering,
    /// Initiator: UPGRADE_REQUEST sent, waiting for accept/reject.
    Proposing,
    /// Initiator: received UPGRADE_ACCEPT, waiting for UPGRADE_READY from responder.
    WaitingReady,
    /// Endpoints exchanged, punch in progress.
    Punching,
    /// Direct connection established.
    Connected,
    /// Hole punch failed.
    Failed,
}

/// A network endpoint (IP address + port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// IPv4 (4 bytes) or IPv6 (16 bytes).
    pub addr: Vec<u8>,
    pub port: u16,
}

/// Actions produced by HolePunchEngine for the caller to dispatch.
#[derive(Debug, Clone)]
pub enum HolePunchAction {
    /// Send a signaling message over the link's channel.
    SendSignal {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    /// Discover our public endpoint by probing the given address.
    DiscoverEndpoints {
        probe_addr: Endpoint,
    },
    /// Start UDP hole punching to the given peer endpoint.
    StartUdpPunch {
        peer_public: Endpoint,
        punch_token: [u8; 32],
        session_id: [u8; 16],
    },
    /// Direct connection succeeded.
    Succeeded {
        session_id: [u8; 16],
    },
    /// Hole punch failed.
    Failed {
        session_id: [u8; 16],
        reason: u8,
    },
}

/// Errors from hole-punch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolePunchError {
    InvalidState,
    InvalidPayload,
    SessionMismatch,
    NoProbeAddr,
    NoDerivedKey,
}

impl fmt::Display for HolePunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HolePunchError::InvalidState => write!(f, "Invalid hole-punch state"),
            HolePunchError::InvalidPayload => write!(f, "Invalid payload"),
            HolePunchError::SessionMismatch => write!(f, "Session ID mismatch"),
            HolePunchError::NoProbeAddr => write!(f, "No probe address configured"),
            HolePunchError::NoDerivedKey => write!(f, "No derived key available"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_holepunch_msgtype() {
        assert!(is_holepunch_msgtype(UPGRADE_REQUEST));
        assert!(is_holepunch_msgtype(UPGRADE_ACCEPT));
        assert!(is_holepunch_msgtype(UPGRADE_REJECT));
        assert!(is_holepunch_msgtype(UPGRADE_READY));
        assert!(is_holepunch_msgtype(UPGRADE_COMPLETE));
        assert!(!is_holepunch_msgtype(0x0000));
        assert!(!is_holepunch_msgtype(0xFDFF));
        assert!(!is_holepunch_msgtype(0xFE05));
    }
}
