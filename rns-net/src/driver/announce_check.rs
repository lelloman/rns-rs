//! Checking an announce held in the verification queue, shared by the
//! verification thread and the compact engine's driver.

use rns_core::announce::{AnnounceData, ValidatedAnnounce};
use rns_core::transport::announce_verify_queue::PendingAnnounce;

/// The outcome of checking a queued announce.
pub(crate) enum AnnounceCheck {
    Valid {
        validated: Box<ValidatedAnnounce>,
        sig_cache_key: [u8; 32],
    },
    Invalid {
        sig_cache_key: [u8; 32],
    },
}

pub(crate) fn check_pending_announce(pending: &PendingAnnounce) -> AnnounceCheck {
    let has_ratchet = pending.packet.flags.context_flag == rns_core::constants::FLAG_SET;
    let announce = match AnnounceData::unpack(pending.packet.data(), has_ratchet) {
        Ok(announce) => announce,
        Err(_) => {
            // An announce that does not unpack has no signature: its cache
            // key is the destination with an all-zero one.
            let mut material = [0u8; 80];
            material[..16].copy_from_slice(&pending.packet.destination_hash);
            return AnnounceCheck::Invalid {
                sig_cache_key: rns_core::hash::full_hash(&material),
            };
        }
    };
    let sig_cache_key = announce.signature_cache_key(&pending.packet.destination_hash);
    match announce.validate(&pending.packet.destination_hash) {
        Ok(validated) => AnnounceCheck::Valid {
            validated: Box::new(validated),
            sig_cache_key,
        },
        Err(_) => AnnounceCheck::Invalid { sig_cache_key },
    }
}
