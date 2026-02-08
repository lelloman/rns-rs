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

// --- From Link.py ---

/// Link ephemeral public key size: 32 (X25519) + 32 (Ed25519)
pub const LINK_ECPUBSIZE: usize = 64;

/// Link key size in bytes
pub const LINK_KEYSIZE: usize = 32;

/// Link MTU signalling bytes size
pub const LINK_MTU_SIZE: usize = 3;

/// Maximum keepalive interval in seconds
pub const LINK_KEEPALIVE_MAX: f64 = 360.0;

/// Minimum keepalive interval in seconds
pub const LINK_KEEPALIVE_MIN: f64 = 5.0;

/// Maximum RTT used for keepalive scaling
pub const LINK_KEEPALIVE_MAX_RTT: f64 = 1.75;

/// RTT timeout factor for stale→close transition
pub const LINK_KEEPALIVE_TIMEOUT_FACTOR: f64 = 4.0;

/// Grace period for stale→close transition
pub const LINK_STALE_GRACE: f64 = 5.0;

/// Factor to compute stale_time from keepalive
pub const LINK_STALE_FACTOR: f64 = 2.0;

/// Traffic timeout factor
pub const LINK_TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;

/// Link MDU: floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
pub const LINK_MDU: usize = {
    let numerator = MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD;
    (numerator / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
};

/// Link MTU bytemask (21-bit MTU field)
pub const LINK_MTU_BYTEMASK: u32 = 0x1FFFFF;

/// Link mode bytemask (3-bit mode field in upper byte)
pub const LINK_MODE_BYTEMASK: u8 = 0xE0;

// --- From Channel.py ---

/// Initial window size at channel setup
pub const CHANNEL_WINDOW: u16 = 2;

/// Absolute minimum window size
pub const CHANNEL_WINDOW_MIN: u16 = 2;

/// Minimum window limit for slow links
pub const CHANNEL_WINDOW_MIN_LIMIT_SLOW: u16 = 2;

/// Minimum window limit for medium-speed links
pub const CHANNEL_WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;

/// Minimum window limit for fast links
pub const CHANNEL_WINDOW_MIN_LIMIT_FAST: u16 = 16;

/// Maximum window size for slow links
pub const CHANNEL_WINDOW_MAX_SLOW: u16 = 5;

/// Maximum window size for medium-speed links
pub const CHANNEL_WINDOW_MAX_MEDIUM: u16 = 12;

/// Maximum window size for fast links
pub const CHANNEL_WINDOW_MAX_FAST: u16 = 48;

/// Minimum flexibility between window_max and window_min
pub const CHANNEL_WINDOW_FLEXIBILITY: u16 = 4;

/// Maximum sequence number
pub const CHANNEL_SEQ_MAX: u16 = 0xFFFF;

/// Sequence number modulus
pub const CHANNEL_SEQ_MODULUS: u32 = 0x10000;

/// Maximum number of send tries per envelope
pub const CHANNEL_MAX_TRIES: u8 = 5;

/// RTT threshold for fast links
pub const CHANNEL_RTT_FAST: f64 = 0.18;

/// RTT threshold for medium links
pub const CHANNEL_RTT_MEDIUM: f64 = 0.75;

/// RTT threshold for slow links
pub const CHANNEL_RTT_SLOW: f64 = 1.45;

/// Number of consecutive fast rounds to upgrade window
pub const CHANNEL_FAST_RATE_THRESHOLD: u16 = 10;

/// Channel envelope overhead: msgtype(2) + seq(2) + len(2)
pub const CHANNEL_ENVELOPE_OVERHEAD: usize = 6;

// --- From Buffer.py ---

/// System message type for stream data
pub const STREAM_DATA_MSGTYPE: u16 = 0xFF00;

/// Maximum stream ID (14 bits)
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// Stream data overhead: 2 (stream header) + 6 (channel envelope)
pub const STREAM_DATA_OVERHEAD: usize = 2 + CHANNEL_ENVELOPE_OVERHEAD;

// --- From Resource.py ---

/// Initial window size at beginning of transfer
pub const RESOURCE_WINDOW: usize = 4;

/// Absolute minimum window size during transfer
pub const RESOURCE_WINDOW_MIN: usize = 2;

/// Maximum window size for slow links
pub const RESOURCE_WINDOW_MAX_SLOW: usize = 10;

/// Maximum window size for very slow links
pub const RESOURCE_WINDOW_MAX_VERY_SLOW: usize = 4;

/// Maximum window size for fast links
pub const RESOURCE_WINDOW_MAX_FAST: usize = 75;

/// Global maximum window (for calculations)
pub const RESOURCE_WINDOW_MAX: usize = RESOURCE_WINDOW_MAX_FAST;

/// Minimum flexibility between window_max and window_min
pub const RESOURCE_WINDOW_FLEXIBILITY: usize = 4;

/// Sustained fast-rate rounds before enabling fast window
/// = WINDOW_MAX_SLOW - WINDOW - 2 = 10 - 4 - 2 = 4
pub const RESOURCE_FAST_RATE_THRESHOLD: usize = RESOURCE_WINDOW_MAX_SLOW - RESOURCE_WINDOW - 2;

/// Sustained very-slow-rate rounds before capping to very slow
pub const RESOURCE_VERY_SLOW_RATE_THRESHOLD: usize = 2;

/// Fast rate threshold: 50 Kbps in bytes/sec = 50000 / 8 = 6250.0
pub const RESOURCE_RATE_FAST: f64 = (50 * 1000) as f64 / 8.0;

/// Very slow rate threshold: 2 Kbps in bytes/sec = 2000 / 8 = 250.0
pub const RESOURCE_RATE_VERY_SLOW: f64 = (2 * 1000) as f64 / 8.0;

/// Number of bytes in a map hash
pub const RESOURCE_MAPHASH_LEN: usize = 4;

/// Resource SDU = Packet.MDU (NOT ENCRYPTED_MDU)
pub const RESOURCE_SDU: usize = MDU;

/// Random hash size prepended to resource data
pub const RESOURCE_RANDOM_HASH_SIZE: usize = 4;

/// Maximum efficient resource size (1 MB - 1)
pub const RESOURCE_MAX_EFFICIENT_SIZE: usize = 1 * 1024 * 1024 - 1;

/// Maximum metadata size (16 MB - 1)
pub const RESOURCE_METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;

/// Maximum auto-compress size (64 MB)
pub const RESOURCE_AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;

/// Part timeout factor (before RTT measured)
pub const RESOURCE_PART_TIMEOUT_FACTOR: f64 = 4.0;

/// Part timeout factor (after first RTT measured)
pub const RESOURCE_PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;

/// Proof timeout factor (reduced when awaiting proof)
pub const RESOURCE_PROOF_TIMEOUT_FACTOR: f64 = 3.0;

/// Maximum retries for part transfers
pub const RESOURCE_MAX_RETRIES: usize = 16;

/// Maximum retries for advertisement
pub const RESOURCE_MAX_ADV_RETRIES: usize = 4;

/// Sender grace time (seconds)
pub const RESOURCE_SENDER_GRACE_TIME: f64 = 10.0;

/// Processing grace for advertisement response (seconds)
pub const RESOURCE_PROCESSING_GRACE: f64 = 1.0;

/// Retry grace time (seconds)
pub const RESOURCE_RETRY_GRACE_TIME: f64 = 0.25;

/// Per-retry delay (seconds)
pub const RESOURCE_PER_RETRY_DELAY: f64 = 0.5;

/// Maximum watchdog sleep interval (seconds)
pub const RESOURCE_WATCHDOG_MAX_SLEEP: f64 = 1.0;

/// Response max grace time (seconds)
pub const RESOURCE_RESPONSE_MAX_GRACE_TIME: f64 = 10.0;

/// Advertisement overhead in bytes (fixed msgpack overhead)
pub const RESOURCE_ADVERTISEMENT_OVERHEAD: usize = 134;

/// Maximum hashmap entries per advertisement segment
/// = floor((LINK_MDU - ADVERTISEMENT_OVERHEAD) / MAPHASH_LEN)
pub const RESOURCE_HASHMAP_MAX_LEN: usize = (LINK_MDU - RESOURCE_ADVERTISEMENT_OVERHEAD) / RESOURCE_MAPHASH_LEN;

/// Collision guard size = 2 * WINDOW_MAX + HASHMAP_MAX_LEN
pub const RESOURCE_COLLISION_GUARD_SIZE: usize = 2 * RESOURCE_WINDOW_MAX + RESOURCE_HASHMAP_MAX_LEN;

/// Hashmap not exhausted flag
pub const RESOURCE_HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;

/// Hashmap exhausted flag
pub const RESOURCE_HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

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
    fn test_link_constants() {
        assert_eq!(LINK_ECPUBSIZE, 64);
        assert_eq!(LINK_MTU_SIZE, 3);
        // LINK_MDU = floor((500 - 1 - 19 - 48) / 16) * 16 - 1 = floor(432/16)*16 - 1 = 27*16 - 1 = 431
        assert_eq!(LINK_MDU, 431);
        assert_eq!(CHANNEL_ENVELOPE_OVERHEAD, 6);
        assert_eq!(STREAM_DATA_OVERHEAD, 8);
        assert_eq!(STREAM_ID_MAX, 0x3FFF);
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

    #[test]
    fn test_resource_constants() {
        // SDU = MDU = 464 (NOT ENCRYPTED_MDU)
        assert_eq!(RESOURCE_SDU, 464);
        assert_eq!(RESOURCE_SDU, MDU);

        // FAST_RATE_THRESHOLD = WINDOW_MAX_SLOW - WINDOW - 2 = 10 - 4 - 2 = 4
        assert_eq!(RESOURCE_FAST_RATE_THRESHOLD, 4);

        // RATE_FAST = 50000 / 8 = 6250.0
        assert_eq!(RESOURCE_RATE_FAST, 6250.0);

        // RATE_VERY_SLOW = 2000 / 8 = 250.0
        assert_eq!(RESOURCE_RATE_VERY_SLOW, 250.0);

        // HASHMAP_MAX_LEN = floor((431 - 134) / 4) = floor(297/4) = 74
        assert_eq!(RESOURCE_HASHMAP_MAX_LEN, 74);

        // COLLISION_GUARD_SIZE = 2 * 75 + 74 = 224
        assert_eq!(RESOURCE_COLLISION_GUARD_SIZE, 224);

        // Window constants
        assert_eq!(RESOURCE_WINDOW, 4);
        assert_eq!(RESOURCE_WINDOW_MIN, 2);
        assert_eq!(RESOURCE_WINDOW_MAX_SLOW, 10);
        assert_eq!(RESOURCE_WINDOW_MAX_VERY_SLOW, 4);
        assert_eq!(RESOURCE_WINDOW_MAX_FAST, 75);
        assert_eq!(RESOURCE_WINDOW_MAX, 75);
        assert_eq!(RESOURCE_WINDOW_FLEXIBILITY, 4);
    }
}
