use core::fmt;

/// Resource transfer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceStatus {
    None = 0x00,
    Queued = 0x01,
    Advertised = 0x02,
    Transferring = 0x03,
    AwaitingProof = 0x04,
    Assembling = 0x05,
    Complete = 0x06,
    Failed = 0x07,
    Corrupt = 0x08,
    Rejected = 0x09,
}

/// Advertisement flags byte.
///
/// ```text
/// Bit 0: encrypted
/// Bit 1: compressed
/// Bit 2: split (multi-segment)
/// Bit 3: is_request
/// Bit 4: is_response
/// Bit 5: has_metadata
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
}

impl AdvFlags {
    pub fn to_byte(self) -> u8 {
        let mut f: u8 = 0;
        if self.encrypted {
            f |= 0x01;
        }
        if self.compressed {
            f |= 0x02;
        }
        if self.split {
            f |= 0x04;
        }
        if self.is_request {
            f |= 0x08;
        }
        if self.is_response {
            f |= 0x10;
        }
        if self.has_metadata {
            f |= 0x20;
        }
        f
    }

    pub fn from_byte(f: u8) -> Self {
        AdvFlags {
            encrypted: (f & 0x01) != 0,
            compressed: (f & 0x02) != 0,
            split: (f & 0x04) != 0,
            is_request: (f & 0x08) != 0,
            is_response: (f & 0x10) != 0,
            has_metadata: (f & 0x20) != 0,
        }
    }
}

/// Actions returned by ResourceSender/ResourceReceiver.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceAction {
    /// Send advertisement packet (packed msgpack bytes).
    SendAdvertisement(alloc::vec::Vec<u8>),
    /// Send a resource part (encrypted part data).
    SendPart(alloc::vec::Vec<u8>),
    /// Send a request for parts (request_data bytes).
    SendRequest(alloc::vec::Vec<u8>),
    /// Send hashmap update (hmu_data bytes).
    SendHmu(alloc::vec::Vec<u8>),
    /// Send proof (proof_data: resource_hash + proof).
    SendProof(alloc::vec::Vec<u8>),
    /// Send cancel from initiator (RESOURCE_ICL).
    SendCancelInitiator(alloc::vec::Vec<u8>),
    /// Send cancel/reject from receiver (RESOURCE_RCL).
    SendCancelReceiver(alloc::vec::Vec<u8>),
    /// Resource data received successfully (data, metadata).
    DataReceived {
        data: alloc::vec::Vec<u8>,
        metadata: Option<alloc::vec::Vec<u8>>,
    },
    /// Transfer completed (proof validated).
    Completed,
    /// Transfer failed.
    Failed(ResourceError),
    /// Progress update: (received_parts, total_parts).
    ProgressUpdate {
        received: usize,
        total: usize,
    },
}

/// Resource errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    InvalidAdvertisement,
    InvalidPart,
    InvalidProof,
    HashMismatch,
    DecryptionFailed,
    DecompressionFailed,
    Timeout,
    Rejected,
    TooLarge,
    MaxRetriesExceeded,
    MsgpackError,
    InvalidState,
    CollisionDetected,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceError::InvalidAdvertisement => write!(f, "Invalid resource advertisement"),
            ResourceError::InvalidPart => write!(f, "Invalid resource part"),
            ResourceError::InvalidProof => write!(f, "Invalid resource proof"),
            ResourceError::HashMismatch => write!(f, "Resource hash mismatch"),
            ResourceError::DecryptionFailed => write!(f, "Resource decryption failed"),
            ResourceError::DecompressionFailed => write!(f, "Resource decompression failed"),
            ResourceError::Timeout => write!(f, "Resource transfer timeout"),
            ResourceError::Rejected => write!(f, "Resource rejected"),
            ResourceError::TooLarge => write!(f, "Resource too large"),
            ResourceError::MaxRetriesExceeded => write!(f, "Max retries exceeded"),
            ResourceError::MsgpackError => write!(f, "Msgpack error"),
            ResourceError::InvalidState => write!(f, "Invalid resource state"),
            ResourceError::CollisionDetected => write!(f, "Hashmap collision detected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adv_flags_roundtrip() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: false,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: true,
        };
        let byte = flags.to_byte();
        assert_eq!(byte, 0x01 | 0x04 | 0x10 | 0x20);
        let back = AdvFlags::from_byte(byte);
        assert_eq!(back, flags);
    }

    #[test]
    fn test_adv_flags_all_set() {
        let flags = AdvFlags {
            encrypted: true,
            compressed: true,
            split: true,
            is_request: true,
            is_response: true,
            has_metadata: true,
        };
        assert_eq!(flags.to_byte(), 0x3f);
        assert_eq!(AdvFlags::from_byte(0x3f), flags);
    }

    #[test]
    fn test_adv_flags_none_set() {
        let flags = AdvFlags {
            encrypted: false,
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
        };
        assert_eq!(flags.to_byte(), 0x00);
        assert_eq!(AdvFlags::from_byte(0x00), flags);
    }

    #[test]
    fn test_adv_flags_encrypted_only() {
        let flags = AdvFlags::from_byte(0x01);
        assert!(flags.encrypted);
        assert!(!flags.compressed);
        assert!(!flags.split);
    }

    #[test]
    fn test_adv_flags_compressed_only() {
        let flags = AdvFlags::from_byte(0x02);
        assert!(!flags.encrypted);
        assert!(flags.compressed);
    }

    #[test]
    fn test_status_ordering() {
        assert!(ResourceStatus::None < ResourceStatus::Queued);
        assert!(ResourceStatus::Queued < ResourceStatus::Advertised);
        assert!(ResourceStatus::Advertised < ResourceStatus::Transferring);
        assert!(ResourceStatus::Transferring < ResourceStatus::AwaitingProof);
        assert!(ResourceStatus::AwaitingProof < ResourceStatus::Complete);
        assert!(ResourceStatus::Complete < ResourceStatus::Failed);
    }

    #[test]
    fn test_resource_status_values() {
        assert_eq!(ResourceStatus::None as u8, 0x00);
        assert_eq!(ResourceStatus::Queued as u8, 0x01);
        assert_eq!(ResourceStatus::Advertised as u8, 0x02);
        assert_eq!(ResourceStatus::Transferring as u8, 0x03);
        assert_eq!(ResourceStatus::AwaitingProof as u8, 0x04);
        assert_eq!(ResourceStatus::Assembling as u8, 0x05);
        assert_eq!(ResourceStatus::Complete as u8, 0x06);
        assert_eq!(ResourceStatus::Failed as u8, 0x07);
        assert_eq!(ResourceStatus::Corrupt as u8, 0x08);
        assert_eq!(ResourceStatus::Rejected as u8, 0x09);
    }
}
