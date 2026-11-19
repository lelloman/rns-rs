use core::fmt;

/// Resource transfer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceStatus {
    /// Initial receiver state, before the transfer starts.
    None = 0x00,
    /// Sender created, not yet advertised.
    Queued = 0x01,
    /// Advertisement sent, waiting for the first part request.
    Advertised = 0x02,
    /// Parts are being requested and sent.
    Transferring = 0x03,
    /// Sender has sent every part and waits for the receiver's proof.
    AwaitingProof = 0x04,
    /// Receiver holds every part and is decrypting, decompressing and verifying them.
    Assembling = 0x05,
    /// Transfer finished successfully.
    Complete = 0x06,
    /// Transfer failed or was cancelled.
    Failed = 0x07,
    /// Received data was found invalid during assembly.
    Corrupt = 0x08,
    /// Resource was rejected by the receiver.
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
/// Bit 6: app_flag (application-defined, carried to the receiver)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvFlags {
    /// Data is encrypted for the link (bit 0).
    pub encrypted: bool,
    /// Data is compressed (bit 1).
    pub compressed: bool,
    /// Resource is one segment of a larger split transfer (bit 2).
    pub split: bool,
    /// Resource carries a link request (bit 3).
    pub is_request: bool,
    /// Resource carries a response to a link request (bit 4).
    pub is_response: bool,
    /// Data is prefixed with metadata (bit 5).
    pub has_metadata: bool,
    /// Application-defined flag carried to the receiver (bit 6).
    pub app_flag: bool,
}

impl AdvFlags {
    /// Pack the flags into the advertisement flags byte.
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
        if self.app_flag {
            f |= 0x40;
        }
        f
    }

    /// Unpack an advertisement flags byte; bit 7 is ignored.
    pub fn from_byte(f: u8) -> Self {
        AdvFlags {
            encrypted: (f & 0x01) != 0,
            compressed: (f & 0x02) != 0,
            split: (f & 0x04) != 0,
            is_request: (f & 0x08) != 0,
            is_response: (f & 0x10) != 0,
            has_metadata: (f & 0x20) != 0,
            app_flag: (f & 0x40) != 0,
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
    /// Tear down the link due to an unrecoverable resource failure.
    TeardownLink,
    /// Resource data received successfully, with its metadata and the
    /// advertised application flag.
    DataReceived {
        /// Assembled resource data.
        data: alloc::vec::Vec<u8>,
        /// Metadata sent with the resource, if any.
        metadata: Option<alloc::vec::Vec<u8>>,
        /// Application flag from the advertisement.
        app_flag: bool,
    },
    /// Transfer completed (proof validated).
    Completed,
    /// Transfer failed.
    Failed(ResourceError),
    /// Progress update: (received_parts, total_parts).
    ProgressUpdate {
        /// Parts received so far.
        received: usize,
        /// Total parts in the transfer.
        total: usize,
    },
}

/// Resource errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Advertisement could not be decoded or has invalid fields.
    InvalidAdvertisement,
    /// Part data or the metadata within it is malformed.
    InvalidPart,
    /// Proof data is malformed.
    InvalidProof,
    /// Assembled data does not hash to the advertised resource hash.
    HashMismatch,
    /// Assembled parts could not be decrypted.
    DecryptionFailed,
    /// Assembled data could not be decompressed.
    DecompressionFailed,
    /// Transfer timed out.
    Timeout,
    /// Resource was rejected or cancelled by the peer.
    Rejected,
    /// Resource exceeds a size limit.
    TooLarge,
    /// Receiver gave up after too many retries.
    MaxRetriesExceeded,
    /// Operation is not valid in the current transfer state, or local assembly failed.
    InvalidState,
    /// No collision-free part hashmap was found within the retry limit.
    CollisionDetected,
    /// The advertised part count differs from ceil(transfer size / SDU).
    PartCountMismatch,
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
            ResourceError::InvalidState => write!(f, "Invalid resource state"),
            ResourceError::CollisionDetected => write!(f, "Hashmap collision detected"),
            ResourceError::PartCountMismatch => {
                write!(f, "Resource part count does not match transfer size")
            }
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
            app_flag: false,
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
            app_flag: true,
        };
        assert_eq!(flags.to_byte(), 0x7f);
        assert_eq!(AdvFlags::from_byte(0x7f), flags);
    }

    #[test]
    fn test_adv_flags_app_flag_is_bit_6() {
        // Python packs the application flag as `self.a << 6`.
        let flags = AdvFlags::from_byte(0x41);
        assert!(flags.app_flag);
        assert!(flags.encrypted);
        assert!(!flags.has_metadata);
        assert_eq!(flags.to_byte(), 0x41);
        assert!(!AdvFlags::from_byte(0x3f).app_flag);
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
            app_flag: false,
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

    #[test]
    fn errors_describe_themselves() {
        assert_eq!(
            ResourceError::PartCountMismatch.to_string(),
            "Resource part count does not match transfer size"
        );
        assert_eq!(
            ResourceError::Timeout.to_string(),
            "Resource transfer timeout"
        );
    }
}
