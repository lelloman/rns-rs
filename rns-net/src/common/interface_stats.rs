/// Maximum number of announce timestamps to keep per direction.
pub const ANNOUNCE_SAMPLE_MAX: usize = 12;

/// Minimum number of incoming announce samples before ingress-control frequency is meaningful.
pub const INCOMING_ANNOUNCE_MIN_SAMPLE: usize = 8;

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
    fn compute_frequency(timestamps: &[f64], min_sample: usize) -> f64 {
        let sample_count = timestamps.len();
        if sample_count <= min_sample {
            return 0.0;
        }
        let span = timestamps[sample_count - 1] - timestamps[0];
        if span <= 0.0 {
            return 0.0;
        }
        sample_count as f64 / span
    }

    /// Incoming announce frequency (per second).
    pub fn incoming_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.ia_timestamps, INCOMING_ANNOUNCE_MIN_SAMPLE)
    }

    /// Outgoing announce frequency (per second).
    pub fn outgoing_announce_freq(&self) -> f64 {
        Self::compute_frequency(&self.oa_timestamps, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_frequency_waits_for_minimum_sample_count() {
        let mut stats = InterfaceStats::default();

        for i in 0..8 {
            stats.record_incoming_announce(i as f64);
        }

        assert_eq!(
            stats.incoming_announce_freq(),
            0.0,
            "incoming announce frequency must stay zero until more than 8 samples exist"
        );
    }

    #[test]
    fn announce_frequency_keeps_twelve_samples() {
        let mut stats = InterfaceStats::default();

        for i in 0..12 {
            stats.record_incoming_announce(i as f64);
            stats.record_outgoing_announce(i as f64);
        }

        assert_eq!(stats.ia_timestamps.len(), 12);
        assert_eq!(stats.oa_timestamps.len(), 12);

        stats.record_incoming_announce(12.0);
        stats.record_outgoing_announce(12.0);

        assert_eq!(stats.ia_timestamps.len(), 12);
        assert_eq!(stats.oa_timestamps.len(), 12);
        assert_eq!(stats.ia_timestamps[0], 1.0);
        assert_eq!(stats.oa_timestamps[0], 1.0);
    }

    #[test]
    fn incoming_frequency_uses_sample_count_over_oldest_span() {
        let mut stats = InterfaceStats::default();

        for i in 0..12 {
            stats.record_incoming_announce(i as f64);
        }

        let expected = 12.0 / 11.0;
        assert!(
            (stats.incoming_announce_freq() - expected).abs() < f64::EPSILON,
            "incoming frequency should be samples / span, got {} expected {}",
            stats.incoming_announce_freq(),
            expected
        );
    }
}
