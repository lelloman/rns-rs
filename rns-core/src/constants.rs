// =============================================================================
// Reticulum protocol constants
// Ported from Python RNS source
// =============================================================================

// --- From Reticulum.py ---

/// Maximum transmission unit in bytes
pub const MTU: usize = 500;

/// Truncated hash length in bits
pub const TRUNCATED_HASHLENGTH: usize = 128;

/// Minimum header size: 2 (flags + hops) + 1 (context) + 16 (dest hash)
pub const HEADER_MINSIZE: usize = 2 + 1 + (TRUNCATED_HASHLENGTH / 8);

/// Maximum header size: 2 (flags + hops) + 1 (context) + 32 (transport_id + dest hash)
pub const HEADER_MAXSIZE: usize = 2 + 1 + (TRUNCATED_HASHLENGTH / 8) * 2;

/// Minimum IFAC size
pub const IFAC_MIN_SIZE: usize = 1;

/// Maximum data unit: MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
pub const MDU: usize = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE;

// --- From Identity.py ---

/// Full key size in bits (256 X25519 + 256 Ed25519)
pub const KEYSIZE: usize = 512;

/// Ratchet key size in bits
pub const RATCHETSIZE: usize = 256;

/// Token overhead in bytes (16 IV + 32 HMAC)
pub const TOKEN_OVERHEAD: usize = 48;

/// AES-128 block size in bytes
pub const AES128_BLOCKSIZE: usize = 16;

/// Full hash length in bits (SHA-256)
pub const HASHLENGTH: usize = 256;

/// Signature length in bits (Ed25519)
pub const SIGLENGTH: usize = KEYSIZE;

/// Name hash length in bits
pub const NAME_HASH_LENGTH: usize = 80;

/// Derived key length in bytes
pub const DERIVED_KEY_LENGTH: usize = 64;

// --- From Packet.py ---

/// Packet types
pub const PACKET_TYPE_DATA: u8 = 0x00;
pub const PACKET_TYPE_ANNOUNCE: u8 = 0x01;
pub const PACKET_TYPE_LINKREQUEST: u8 = 0x02;
pub const PACKET_TYPE_PROOF: u8 = 0x03;

/// Header types
pub const HEADER_1: u8 = 0x00;
pub const HEADER_2: u8 = 0x01;

/// Packet context types
pub const CONTEXT_NONE: u8 = 0x00;
pub const CONTEXT_RESOURCE: u8 = 0x01;
pub const CONTEXT_RESOURCE_ADV: u8 = 0x02;
pub const CONTEXT_RESOURCE_REQ: u8 = 0x03;
pub const CONTEXT_RESOURCE_HMU: u8 = 0x04;
pub const CONTEXT_RESOURCE_PRF: u8 = 0x05;
pub const CONTEXT_RESOURCE_ICL: u8 = 0x06;
pub const CONTEXT_RESOURCE_RCL: u8 = 0x07;
pub const CONTEXT_CACHE_REQUEST: u8 = 0x08;
pub const CONTEXT_REQUEST: u8 = 0x09;
pub const CONTEXT_RESPONSE: u8 = 0x0A;
pub const CONTEXT_PATH_RESPONSE: u8 = 0x0B;
pub const CONTEXT_COMMAND: u8 = 0x0C;
pub const CONTEXT_COMMAND_STATUS: u8 = 0x0D;
pub const CONTEXT_CHANNEL: u8 = 0x0E;
pub const CONTEXT_KEEPALIVE: u8 = 0xFA;
pub const CONTEXT_LINKIDENTIFY: u8 = 0xFB;
pub const CONTEXT_LINKCLOSE: u8 = 0xFC;
pub const CONTEXT_LINKPROOF: u8 = 0xFD;
pub const CONTEXT_LRRTT: u8 = 0xFE;
pub const CONTEXT_LRPROOF: u8 = 0xFF;

/// Context flag values
pub const FLAG_SET: u8 = 0x01;
pub const FLAG_UNSET: u8 = 0x00;

/// Encrypted MDU: floor((MDU - TOKEN_OVERHEAD - KEYSIZE/16) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
pub const ENCRYPTED_MDU: usize = {
    let numerator = MDU - TOKEN_OVERHEAD - KEYSIZE / 16;
    (numerator / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
};

/// Plain MDU (same as MDU)
pub const PLAIN_MDU: usize = MDU;

/// Explicit proof length: HASHLENGTH/8 + SIGLENGTH/8 = 32 + 64 = 96
pub const EXPL_LENGTH: usize = HASHLENGTH / 8 + SIGLENGTH / 8;

/// Implicit proof length: SIGLENGTH/8 = 64
pub const IMPL_LENGTH: usize = SIGLENGTH / 8;

/// Receipt status constants
pub const RECEIPT_FAILED: u8 = 0x00;
pub const RECEIPT_SENT: u8 = 0x01;
pub const RECEIPT_DELIVERED: u8 = 0x02;
pub const RECEIPT_CULLED: u8 = 0xFF;

// --- From Destination.py ---

/// Destination types
pub const DESTINATION_SINGLE: u8 = 0x00;
pub const DESTINATION_GROUP: u8 = 0x01;
pub const DESTINATION_PLAIN: u8 = 0x02;
pub const DESTINATION_LINK: u8 = 0x03;

/// Destination directions
pub const DESTINATION_IN: u8 = 0x11;
pub const DESTINATION_OUT: u8 = 0x12;

// --- From Transport.py ---

/// Transport types
pub const TRANSPORT_BROADCAST: u8 = 0x00;
pub const TRANSPORT_TRANSPORT: u8 = 0x01;
pub const TRANSPORT_RELAY: u8 = 0x02;
pub const TRANSPORT_TUNNEL: u8 = 0x03;

/// Maximum hops
pub const PATHFINDER_M: u8 = 128;

// --- PATHFINDER algorithm ---

/// Retransmit retries (total sends = PATHFINDER_R + 1)
pub const PATHFINDER_R: u8 = 1;

/// Grace period between retries (seconds)
pub const PATHFINDER_G: f64 = 5.0;

/// Random window for announce rebroadcast (seconds)
pub const PATHFINDER_RW: f64 = 0.5;

/// Path expiry = 7 days (seconds)
pub const PATHFINDER_E: f64 = 604800.0;

// --- Path expiry by interface mode ---

/// Access Point path expiry = 1 day
pub const AP_PATH_TIME: f64 = 86400.0;

/// Roaming path expiry = 6 hours
pub const ROAMING_PATH_TIME: f64 = 21600.0;

// --- Table limits ---

/// How many local rebroadcasts of an announce is allowed
pub const LOCAL_REBROADCASTS_MAX: u8 = 2;

/// Maximum number of random blobs per destination to keep in memory
pub const MAX_RANDOM_BLOBS: usize = 64;

/// Maximum number of announce timestamps to keep per destination
pub const MAX_RATE_TIMESTAMPS: usize = 16;

/// Maximum packet hashlist size before rotation
pub const HASHLIST_MAXSIZE: usize = 1_000_000;

// --- Timeouts ---

/// Reverse table entry timeout (8 minutes)
pub const REVERSE_TIMEOUT: f64 = 480.0;

/// Destination table entry timeout (7 days)
pub const DESTINATION_TIMEOUT: f64 = 604800.0;

/// Link stale time = 2 * KEEPALIVE(360) = 720 seconds
pub const LINK_STALE_TIME: f64 = 720.0;

/// Link timeout = STALE_TIME * 1.25 = 900 seconds
pub const LINK_TIMEOUT: f64 = 900.0;

/// Link establishment timeout per hop (seconds)
pub const LINK_ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = 6.0;

// --- Path request ---

/// Default timeout for path requests (seconds)
pub const PATH_REQUEST_TIMEOUT: f64 = 15.0;

/// Grace time before a path announcement is made (seconds)
pub const PATH_REQUEST_GRACE: f64 = 0.4;

/// Extra grace time for roaming-mode interfaces (seconds)
pub const PATH_REQUEST_RG: f64 = 1.5;

/// Minimum interval for automated path requests (seconds)
pub const PATH_REQUEST_MI: f64 = 20.0;

/// Maximum amount of unique path request tags to remember
pub const MAX_PR_TAGS: usize = 32000;

// --- Job intervals ---

/// Announce check interval (seconds)
pub const ANNOUNCES_CHECK_INTERVAL: f64 = 1.0;

/// Table culling interval (seconds)
pub const TABLES_CULL_INTERVAL: f64 = 5.0;

/// Link check interval (seconds)
pub const LINKS_CHECK_INTERVAL: f64 = 1.0;

// --- Interface modes (from Interface.py) ---

pub const MODE_FULL: u8 = 0x01;
pub const MODE_POINT_TO_POINT: u8 = 0x02;
pub const MODE_ACCESS_POINT: u8 = 0x03;
pub const MODE_ROAMING: u8 = 0x04;
pub const MODE_BOUNDARY: u8 = 0x05;
pub const MODE_GATEWAY: u8 = 0x06;

// --- Path states ---

pub const STATE_UNKNOWN: u8 = 0x00;
pub const STATE_UNRESPONSIVE: u8 = 0x01;
pub const STATE_RESPONSIVE: u8 = 0x02;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_constants() {
        // MTU = 500
        assert_eq!(MTU, 500);

        // HEADER_MINSIZE = 2 + 1 + 16 = 19
        assert_eq!(HEADER_MINSIZE, 19);

        // HEADER_MAXSIZE = 2 + 1 + 32 = 35
        assert_eq!(HEADER_MAXSIZE, 35);

        // MDU = 500 - 35 - 1 = 464
        assert_eq!(MDU, 464);

        // ENCRYPTED_MDU = floor((464 - 48 - 32) / 16) * 16 - 1 = floor(384/16)*16 - 1 = 24*16 - 1 = 383
        assert_eq!(ENCRYPTED_MDU, 383);

        // PLAIN_MDU = MDU = 464
        assert_eq!(PLAIN_MDU, 464);

        // EXPL_LENGTH = 32 + 64 = 96
        assert_eq!(EXPL_LENGTH, 96);

        // IMPL_LENGTH = 64
        assert_eq!(IMPL_LENGTH, 64);

        // NAME_HASH_LENGTH = 80 bits = 10 bytes
        assert_eq!(NAME_HASH_LENGTH / 8, 10);

        // KEYSIZE = 512 bits = 64 bytes
        assert_eq!(KEYSIZE / 8, 64);

        // SIGLENGTH = 512 bits = 64 bytes
        assert_eq!(SIGLENGTH / 8, 64);

        // TRUNCATED_HASHLENGTH = 128 bits = 16 bytes
        assert_eq!(TRUNCATED_HASHLENGTH / 8, 16);
    }

    #[test]
    fn test_transport_constants() {
        // PATHFINDER_E = 7 days in seconds
        assert_eq!(PATHFINDER_E, 60.0 * 60.0 * 24.0 * 7.0);

        // AP_PATH_TIME = 1 day
        assert_eq!(AP_PATH_TIME, 60.0 * 60.0 * 24.0);

        // ROAMING_PATH_TIME = 6 hours
        assert_eq!(ROAMING_PATH_TIME, 60.0 * 60.0 * 6.0);

        // LINK_STALE_TIME = 2 * 360
        assert_eq!(LINK_STALE_TIME, 720.0);

        // LINK_TIMEOUT = STALE_TIME * 1.25
        assert_eq!(LINK_TIMEOUT, LINK_STALE_TIME * 1.25);

        // REVERSE_TIMEOUT = 8 minutes
        assert_eq!(REVERSE_TIMEOUT, 8.0 * 60.0);

        // DESTINATION_TIMEOUT = 7 days
        assert_eq!(DESTINATION_TIMEOUT, 60.0 * 60.0 * 24.0 * 7.0);
    }
}
