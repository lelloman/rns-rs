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
}
