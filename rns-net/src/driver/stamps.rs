//! Stamping of this node's own announces, path requests and link requests.

use super::*;

/// Stamping of this node's own announces, path requests and link requests.
pub(crate) struct Stamps {
    /// Grinds own path request and announce stamps off the driver thread.
    /// Replaced by the node's shared instance at startup.
    pub(crate) stamper: Arc<crate::stamper::Stamper>,
    /// `Transport.STAMP_DESTINATIONS`, shared with the node handle whose
    /// announce API reads it; settable as `global.stamp_destinations`.
    pub(crate) stamp_destinations: Arc<AtomicBool>,
    /// The `[stamps]` config section this node started with. Link request
    /// stamping reads `stamp_lrs`, `always_stamp_lrs` and `lr_stamp_timeout`
    /// from it; the other options are applied to the engine, the stamper
    /// and the node handle at startup.
    pub(crate) settings: crate::config::StampsSection,
}

impl Stamps {
    pub(crate) fn new(tx: crate::event::EventSender) -> Self {
        Self {
            stamper: Arc::new(crate::stamper::Stamper::new(tx, None)),
            stamp_destinations: Arc::new(AtomicBool::new(rns_core::constants::STAMP_DESTINATIONS)),
            settings: crate::config::StampsSection::default(),
        }
    }
}
