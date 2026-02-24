/// Maximum number of announce timestamps to keep per direction.
pub const ANNOUNCE_SAMPLE_MAX: usize = 6;

/// Traffic statistics for an interface.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rxb: u64,
    pub txb: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub started: f64,
    /// Recent incoming announce timestamps (bounded).
    pub ia_timestamps: Vec<f64>,
    /// Recent outgoing announce timestamps (bounded).
    pub oa_timestamps: Vec<f64>,
}

impl InterfaceStats {
    /// Record an incoming announce timestamp.
    pub fn record_incoming_announce(&mut self, now: f64) {
        self.ia_timestamps.push(now);
        if self.ia_timestamps.len() > ANNOUNCE_SAMPLE_MAX {
            self.ia_timestamps.remove(0);
        }
    }

    /// Record an outgoing announce timestamp.
    pub fn record_outgoing_announce(&mut self, now: f64) {
        self.oa_timestamps.push(now);
        if self.oa_timestamps.len() > ANNOUNCE_SAMPLE_MAX {
            self.oa_timestamps.remove(0);
        }
    }

    /// Compute announce frequency (per second) from timestamps.
    fn compute_frequency(timestamps: &[f64]) -> f64 {
        if timestamps.len() < 2 {
            return 0.0;
        }
        let span = timestamps[timestamps.len() - 1] - timestamps[0];
        if span <= 0.0 {
            return 0.0;
        }
        (timestamps.len() - 1) as f64 / span
    }

    /// Incoming announce frequency (per second).
    pub fn incoming_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.ia_timestamps)
    }

    /// Outgoing announce frequency (per second).
    pub fn outgoing_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.oa_timestamps)
    }
}
