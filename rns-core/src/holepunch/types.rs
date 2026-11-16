use alloc::vec::Vec;
use core::fmt;

// --- Signalling wire format ---
//
// Direct Link signalling travels in Reticulum link DATA packets with the
// packet context [`CONTEXT_DIRECT_LINK`], encrypted with the link key like
// any other link packet. The plaintext is
//
//   [version: u8] [kind: u8] [body: msgpack map]
//
// Upstream Reticulum drops link packets with a context it does not know
// without a reply or proof, so a peer that does not implement Direct Link
// never notices the capability query (`HELLO`) and never answers it.

/// Link packet context carrying Direct Link signalling (an rns-rs extension;
/// upstream Reticulum assigns no meaning to it and ignores it).
pub const CONTEXT_DIRECT_LINK: u8 = 0x80;

/// Signalling format version this implementation speaks. Messages carrying
/// another version are dropped. `HELLO` is always sent in version 1 framing
/// and advertises the highest version the sender speaks in its `v` field.
pub const DIRECT_LINK_VERSION: u8 = 1;

/// Capability query and answer: "I implement Direct Link".
pub const HELLO: u8 = 0x00;
pub const UPGRADE_REQUEST: u8 = 0x01;
pub const UPGRADE_ACCEPT: u8 = 0x02;
pub const UPGRADE_REJECT: u8 = 0x03;
pub const UPGRADE_READY: u8 = 0x04;
/// "I stopped using the direct path of this session; use the link's
/// original path." Sent over the original path.
pub const FALLBACK: u8 = 0x05;

/// Check if a signalling kind is one of the upgrade negotiation messages.
pub fn is_holepunch_msgtype(kind: u8) -> bool {
    (UPGRADE_REQUEST..=UPGRADE_READY).contains(&kind)
}

/// Frame a signalling message: version, kind, body.
pub fn encode_signal(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(DIRECT_LINK_VERSION);
    out.push(kind);
    out.extend_from_slice(body);
    out
}

/// Split a signalling message into its kind and body. `None` for a message
/// too short to carry a header or framed in a version this node does not
/// speak.
pub fn decode_signal(data: &[u8]) -> Option<(u8, &[u8])> {
    match data {
        [DIRECT_LINK_VERSION, kind, body @ ..] => Some((*kind, body)),
        _ => None,
    }
}

// --- Reject reasons ---

pub const REJECT_POLICY: u8 = 0x01;
pub const REJECT_BUSY: u8 = 0x02;
pub const REJECT_UNSUPPORTED: u8 = 0x03;
/// The responder accepted, but could not learn its public endpoint from the
/// facilitator named in the request.
pub const REJECT_NO_ENDPOINT: u8 = 0x04;

// --- Fail reasons ---
//
// Reported locally (never sent), from 0x10 so they never collide with the
// reject reasons above, which come from the peer.

/// A step did not complete in time (no ACCEPT, READY or punch answer).
pub const FAIL_TIMEOUT: u8 = 0x10;
/// Our endpoint could not be learned from the facilitator.
pub const FAIL_PROBE: u8 = 0x11;
/// The proposal could not start: no facilitator is configured, the link is
/// not active, or a proposal on the link was made less than
/// [`PROPOSAL_COOLDOWN`] seconds ago.
pub const FAIL_NOT_STARTED: u8 = 0x12;

// --- Timeouts (seconds) ---

/// How long an initiator waits for the peer to answer its `HELLO` before
/// treating the peer as not implementing Direct Link.
pub const HELLO_TIMEOUT: f64 = 8.0;

/// Interval between `HELLO` retransmissions while waiting for an answer.
pub const HELLO_RETRY_INTERVAL: f64 = 2.5;

/// Interval between UPGRADE_REQUEST retransmissions while the initiator waits
/// for the responder's ACCEPT and READY. The responder answers a repeated
/// request with the replies it already sent.
pub const REQUEST_RETRY_INTERVAL: f64 = 2.0;

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

/// Protocol used for endpoint discovery (probing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeProtocol {
    /// Custom RNSP probe protocol (requires own facilitator).
    Rnsp = 0,
    /// Standard STUN (RFC 5389) — works with any public STUN server.
    Stun = 1,
}

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
    /// Send a signalling message to the link peer (kind and body; the caller
    /// frames it with [`encode_signal`]).
    SendSignal {
        link_id: [u8; 16],
        msgtype: u8,
        payload: Vec<u8>,
    },
    /// Discover our public endpoint by probing the given address.
    DiscoverEndpoints {
        probe_addr: Endpoint,
        protocol: ProbeProtocol,
    },
    /// Start UDP hole punching to the given peer endpoint.
    StartUdpPunch {
        peer_public: Endpoint,
        punch_token: [u8; 32],
        session_id: [u8; 16],
    },
    /// Direct connection succeeded.
    Succeeded { session_id: [u8; 16] },
    /// Hole punch failed.
    Failed { session_id: [u8; 16], reason: u8 },
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
        assert!(!is_holepunch_msgtype(HELLO));
        assert!(!is_holepunch_msgtype(FALLBACK));
        assert!(!is_holepunch_msgtype(0xFF));
    }

    #[test]
    fn signal_framing_round_trips_and_checks_the_version() {
        let framed = encode_signal(UPGRADE_ACCEPT, &[0x81, 0xA1, 0x73]);
        assert_eq!(framed[..2], [DIRECT_LINK_VERSION, UPGRADE_ACCEPT]);
        assert_eq!(
            decode_signal(&framed),
            Some((UPGRADE_ACCEPT, &[0x81, 0xA1, 0x73][..]))
        );
        assert_eq!(
            decode_signal(&encode_signal(HELLO, &[])),
            Some((HELLO, &[][..]))
        );
        // Another version, or no header at all, is not understood.
        assert_eq!(decode_signal(&[2, UPGRADE_REQUEST, 0x80]), None);
        assert_eq!(decode_signal(&[DIRECT_LINK_VERSION]), None);
        assert_eq!(decode_signal(&[]), None);
    }

    #[test]
    fn direct_link_context_is_not_an_upstream_context() {
        use crate::constants::*;
        for upstream in [
            CONTEXT_NONE,
            CONTEXT_RESOURCE,
            CONTEXT_RESOURCE_ADV,
            CONTEXT_RESOURCE_REQ,
            CONTEXT_RESOURCE_HMU,
            CONTEXT_RESOURCE_PRF,
            CONTEXT_RESOURCE_ICL,
            CONTEXT_RESOURCE_RCL,
            CONTEXT_CACHE_REQUEST,
            CONTEXT_REQUEST,
            CONTEXT_RESPONSE,
            CONTEXT_PATH_RESPONSE,
            CONTEXT_COMMAND,
            CONTEXT_COMMAND_STATUS,
            CONTEXT_CHANNEL,
            CONTEXT_KEEPALIVE,
            CONTEXT_LINKIDENTIFY,
            CONTEXT_LINKCLOSE,
            CONTEXT_LINKPROOF,
            CONTEXT_LRRTT,
            CONTEXT_LRPROOF,
        ] {
            assert_ne!(CONTEXT_DIRECT_LINK, upstream);
        }
    }
}
