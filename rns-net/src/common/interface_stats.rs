/// Maximum number of announce timestamps to keep per direction.
pub const ANNOUNCE_SAMPLE_MAX: usize = 48;

/// Maximum number of path request timestamps to keep per direction.
pub(crate) const PATH_REQUEST_SAMPLE_MAX: usize = 48;

/// Minimum number of incoming announce samples before ingress-control frequency is meaningful.
pub(crate) const INCOMING_ANNOUNCE_MIN_SAMPLE: usize = 2;

/// Minimum number of incoming path request samples before frequency is meaningful.
pub(crate) const INCOMING_PATH_REQUEST_MIN_SAMPLE: usize = 2;

/// Age (seconds) past which the oldest announce sample decays, upstream's
/// `AR_FREQ_DECAY` (1 / `AR_MINFREQ_HZ`).
pub(crate) const AR_FREQ_DECAY: f64 = 10.0;

/// Age (seconds) past which the oldest path request sample decays,
/// upstream's `PR_FREQ_DECAY` (1 / `PR_MINFREQ_HZ`).
pub(crate) const PR_FREQ_DECAY: f64 = 10.0;

/// What an RNode reports about its channel and itself (upstream
/// `RNodeInterface`'s `r_airtime_*`, `r_channel_load_*`, `r_noise_floor`,
/// `r_interference`, battery and temperature), as interface statistics
/// carry it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RadioStats {
    /// This device's airtime over 15 s, percent.
    pub airtime_short: f64,
    /// This device's airtime over 1 h, percent.
    pub airtime_long: f64,
    /// Channel load over 15 s, percent.
    pub channel_load_short: f64,
    /// Channel load over 1 h, percent.
    pub channel_load_long: f64,
    /// Current channel RSSI, dBm, once reported.
    pub current_rssi: Option<i16>,
    /// Noise floor, dBm, once reported.
    pub noise_floor: Option<i16>,
    /// RSSI of interference on the channel now, if any.
    pub interference: Option<i16>,
    /// When interference was last seen (Unix time) and its RSSI.
    pub interference_last: Option<(f64, i16)>,
    /// 0 unknown, 1 discharging, 2 charging, 3 charged.
    pub battery_state: u8,
    /// Battery charge, percent.
    pub battery_percent: u8,
    /// Device temperature, °C, when it reports one.
    pub temperature: Option<i16>,
}

impl RadioStats {
    /// Upstream `get_battery_state_string`.
    pub fn battery_state_name(&self) -> &'static str {
        match self.battery_state {
            0x01 => "discharging",
            0x02 => "charging",
            0x03 => "charged",
            _ => "unknown",
        }
    }
}

/// Traffic statistics for an interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficRates {
    /// Received bits per second in the current sampling window.
    pub rxs: f64,
    /// Transmitted bits per second in the current sampling window.
    pub txs: f64,
    /// Received packets per second in the current sampling window.
    pub rxpps: f64,
    /// Transmitted packets per second in the current sampling window.
    pub txpps: f64,
    /// Received announce bits per second.
    pub arxs: f64,
    /// Transmitted announce bits per second.
    pub atxs: f64,
    /// Received path request bits per second.
    pub prxs: f64,
    /// Transmitted path request bits per second.
    pub ptxs: f64,
    /// Filtered inbound bits per second (upstream 134dc677).
    pub frxs: f64,
    /// Filtered outbound bits per second.
    pub ftxs: f64,
}

/// Traffic statistics for an interface.
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// Bytes received and accepted.
    pub rxb: u64,
    /// Bytes transmitted.
    pub txb: u64,
    /// Received bytes dropped where upstream's `preprocess_inbound` drops
    /// them (upstream 134dc677); they are moved out of `rxb`.
    pub frxb: u64,
    /// Filtered outbound bytes. Upstream reports it and never counts any.
    pub ftxb: u64,
    /// Bytes of announces received.
    pub arxb: u64,
    /// Bytes of announces transmitted.
    pub atxb: u64,
    /// Announces received.
    pub arxc: u64,
    /// Announces transmitted.
    pub atxc: u64,
    /// Announces dropped as filtered (upstream 819076c3).
    pub afrxc: u64,
    /// Bytes of path requests received.
    pub prxb: u64,
    /// Bytes of path requests transmitted.
    pub ptxb: u64,
    /// Path requests received.
    pub prxc: u64,
    /// Path requests transmitted.
    pub ptxc: u64,
    /// Inbound packets dropped as malformed, such as an oversized or
    /// truncated announce.
    pub protocol_violations: u64,
    /// Inbound packets dropped for failing IFAC, or for carrying the IFAC
    /// flag on an interface without IFAC.
    pub ifac_violations: u64,
    /// Inbound packets the transport packet filter dropped.
    pub packet_filter_hits: u64,
    /// Inbound packets dropped because their hop count reached `HOP_LIMITER`.
    pub hop_limiter_hits: u64,
    /// Inbound path requests whose stamp met `PATH_REQUEST_STAMP_COST`.
    pub stamped_path_requests: u64,
    /// Rates over the last sampling window, refreshed about once a second.
    pub traffic_rates: TrafficRates,
    /// Packets received and accepted.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// CPU load a Weave device reports, percent.
    pub cpu_load: Option<f64>,
    /// Memory in use on a Weave device, percent.
    pub mem_load: Option<f64>,
    /// The Weave switch ID of the connected device.
    pub switch_id: Option<[u8; 4]>,
    /// The Weave endpoint ID of the connected device.
    pub endpoint_id: Option<[u8; 8]>,
    /// The Weave switch a peer endpoint is reached through.
    pub via_switch_id: Option<[u8; 4]>,
    /// Number of peers a Weave interface knows.
    pub peers: Option<usize>,
    /// Last reported receive signal strength in dBm.
    pub rssi: Option<i16>,
    /// Last reported signal-to-noise ratio in dB.
    pub snr: Option<f32>,
    /// Signal quality percentage derived from SNR and spreading factor.
    pub signal_quality: Option<f64>,
    /// Radio frequency, Hz.
    pub frequency: Option<u32>,
    /// Radio bandwidth, Hz.
    pub bandwidth: Option<u32>,
    /// Transmit power, dBm.
    pub txpower: Option<i8>,
    /// LoRa spreading factor.
    pub spreading_factor: Option<u8>,
    /// LoRa coding rate.
    pub coding_rate: Option<u8>,
    /// Radio channel, when the interface reports one.
    pub channel: Option<u32>,
    /// Modulation name, such as `LoRa`.
    pub modulation: Option<String>,
    /// Channel and device state an RNode reports.
    pub radio: Option<RadioStats>,
    /// When the interface entry was created, Unix time in seconds.
    pub started: f64,
    /// Recent incoming announce timestamps (bounded).
    pub ia_timestamps: Vec<f64>,
    /// Recent outgoing announce timestamps (bounded).
    pub oa_timestamps: Vec<f64>,
    /// Recent incoming path request timestamps (bounded).
    pub ip_timestamps: Vec<f64>,
    /// Recent outgoing path request timestamps (bounded).
    pub op_timestamps: Vec<f64>,
}

impl InterfaceStats {
    /// Record incoming announce traffic after the packet has been accepted.
    pub fn record_incoming_announce_bytes(&mut self, now: f64, size: usize) {
        self.arxc = self.arxc.saturating_add(1);
        self.arxb = self.arxb.saturating_add(size as u64);
        self.record_incoming_announce(now);
    }

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

    /// Record outgoing announce traffic.
    pub fn record_outgoing_announce_bytes(&mut self, now: f64, size: usize) {
        self.atxc = self.atxc.saturating_add(1);
        self.atxb = self.atxb.saturating_add(size as u64);
        self.record_outgoing_announce(now);
    }

    /// Record an incoming path request timestamp.
    pub fn record_incoming_path_request(&mut self, now: f64) {
        self.ip_timestamps.push(now);
        if self.ip_timestamps.len() > PATH_REQUEST_SAMPLE_MAX {
            self.ip_timestamps.remove(0);
        }
    }

    /// Record accepted incoming path-request traffic.
    pub fn record_incoming_path_request_bytes(&mut self, now: f64, size: usize) {
        self.prxc = self.prxc.saturating_add(1);
        self.prxb = self.prxb.saturating_add(size as u64);
        self.record_incoming_path_request(now);
    }

    /// Record an outgoing path request timestamp.
    pub fn record_outgoing_path_request(&mut self, now: f64) {
        self.op_timestamps.push(now);
        if self.op_timestamps.len() > PATH_REQUEST_SAMPLE_MAX {
            self.op_timestamps.remove(0);
        }
    }

    /// Record outgoing path-request traffic.
    pub fn record_outgoing_path_request_bytes(&mut self, now: f64, size: usize) {
        self.ptxc = self.ptxc.saturating_add(1);
        self.ptxb = self.ptxb.saturating_add(size as u64);
        self.record_outgoing_path_request(now);
    }

    /// Frequency (per second) of the samples in `timestamps` at `now`, as
    /// upstream's `incoming_announce_frequency` and its siblings compute it:
    /// zero unless there are more than `min_sample` samples, otherwise the
    /// sample count over the time since the oldest one.
    fn compute_frequency(timestamps: &[f64], min_sample: usize, now: f64) -> f64 {
        let sample_count = timestamps.len();
        let Some(oldest) = timestamps.first().filter(|_| sample_count > min_sample) else {
            return 0.0;
        };
        let span = now - oldest;
        if span <= 0.0 {
            return 0.0;
        }
        sample_count as f64 / span
    }

    /// The decay step that follows each of upstream's frequency reads: with
    /// more than `min_sample` samples, the oldest goes once it is older than
    /// `decay` seconds. One sample at most goes per read.
    fn decay(timestamps: &mut Vec<f64>, min_sample: usize, decay: f64, now: f64) {
        if timestamps.len() > min_sample
            && timestamps
                .first()
                .is_some_and(|oldest| now - oldest > decay)
        {
            timestamps.remove(0);
        }
    }

    /// The frequencies and sample counts the transport engine works from,
    /// at `now`, without decaying any sample.
    pub fn frequencies(&self, now: f64) -> FrequencySample {
        FrequencySample {
            ia_freq: self.incoming_announce_freq(now),
            ia_samples: self.ia_timestamps.len(),
            ip_freq: self.incoming_path_request_freq(now),
            op_freq: self.outgoing_path_request_freq(now),
            op_samples: self.op_timestamps.len(),
        }
    }

    /// Read every frequency as upstream's once-a-second traffic count
    /// does, decaying each set of samples after its read, and return what
    /// the transport engine is given, with the sample counts left after
    /// the decay.
    pub fn sample_frequencies(&mut self, now: f64) -> FrequencySample {
        let read = self.frequencies(now);
        Self::decay(
            &mut self.ia_timestamps,
            INCOMING_ANNOUNCE_MIN_SAMPLE,
            AR_FREQ_DECAY,
            now,
        );
        Self::decay(&mut self.oa_timestamps, 1, AR_FREQ_DECAY, now);
        Self::decay(
            &mut self.ip_timestamps,
            INCOMING_PATH_REQUEST_MIN_SAMPLE,
            PR_FREQ_DECAY,
            now,
        );
        Self::decay(&mut self.op_timestamps, 1, PR_FREQ_DECAY, now);
        FrequencySample {
            ia_samples: self.ia_timestamps.len(),
            op_samples: self.op_timestamps.len(),
            ..read
        }
    }

    /// Incoming announce frequency (per second) at `now`.
    pub fn incoming_announce_freq(&self, now: f64) -> f64 {
        Self::compute_frequency(&self.ia_timestamps, INCOMING_ANNOUNCE_MIN_SAMPLE, now)
    }

    /// Number of incoming announce samples currently held.
    pub fn incoming_announce_samples(&self) -> usize {
        self.ia_timestamps.len()
    }

    /// Outgoing announce frequency (per second) at `now`.
    pub fn outgoing_announce_freq(&self, now: f64) -> f64 {
        Self::compute_frequency(&self.oa_timestamps, 1, now)
    }

    /// Incoming path request frequency (per second) at `now`.
    pub fn incoming_path_request_freq(&self, now: f64) -> f64 {
        Self::compute_frequency(&self.ip_timestamps, INCOMING_PATH_REQUEST_MIN_SAMPLE, now)
    }

    /// Outgoing path request frequency (per second) at `now`.
    pub fn outgoing_path_request_freq(&self, now: f64) -> f64 {
        Self::compute_frequency(&self.op_timestamps, 1, now)
    }

    /// Number of outgoing path request samples currently held.
    pub fn outgoing_path_request_samples(&self) -> usize {
        self.op_timestamps.len()
    }
}

/// The frequencies and sample counts the transport engine works from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrequencySample {
    /// Incoming announce frequency, per second.
    pub ia_freq: f64,
    /// Incoming announce samples held.
    pub ia_samples: usize,
    /// Incoming path request frequency, per second.
    pub ip_freq: f64,
    /// Outgoing path request frequency, per second.
    pub op_freq: f64,
    /// Outgoing path request samples held.
    pub op_samples: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_frequency_waits_for_minimum_sample_count() {
        let mut stats = InterfaceStats::default();

        for i in 0..INCOMING_ANNOUNCE_MIN_SAMPLE {
            stats.record_incoming_announce(i as f64);
        }

        assert_eq!(
            stats.incoming_announce_freq(100.0),
            0.0,
            "incoming announce frequency must stay zero until more than the minimum samples exist"
        );
        assert_eq!(
            stats.incoming_announce_samples(),
            INCOMING_ANNOUNCE_MIN_SAMPLE
        );
    }

    #[test]
    fn announce_frequency_keeps_bounded_samples() {
        let mut stats = InterfaceStats::default();

        for i in 0..ANNOUNCE_SAMPLE_MAX {
            stats.record_incoming_announce(i as f64);
            stats.record_outgoing_announce(i as f64);
        }

        assert_eq!(stats.ia_timestamps.len(), ANNOUNCE_SAMPLE_MAX);
        assert_eq!(stats.oa_timestamps.len(), ANNOUNCE_SAMPLE_MAX);

        stats.record_incoming_announce(ANNOUNCE_SAMPLE_MAX as f64);
        stats.record_outgoing_announce(ANNOUNCE_SAMPLE_MAX as f64);

        assert_eq!(stats.ia_timestamps.len(), ANNOUNCE_SAMPLE_MAX);
        assert_eq!(stats.oa_timestamps.len(), ANNOUNCE_SAMPLE_MAX);
        assert_eq!(stats.ia_timestamps[0], 1.0);
        assert_eq!(stats.oa_timestamps[0], 1.0);
    }

    #[test]
    fn incoming_frequency_uses_sample_count_over_time_since_oldest() {
        let mut stats = InterfaceStats::default();

        for i in 0..12 {
            stats.record_incoming_announce(i as f64);
        }

        // As upstream, the span runs to now, not to the newest sample, so
        // the frequency falls while no announce arrives.
        assert_eq!(stats.incoming_announce_freq(11.0), 12.0 / 11.0);
        assert_eq!(stats.incoming_announce_freq(24.0), 12.0 / 24.0);
        assert_eq!(stats.incoming_announce_freq(0.0), 0.0);
    }

    #[test]
    fn path_request_frequency_tracks_incoming_and_outgoing_samples() {
        let mut stats = InterfaceStats::default();

        for i in 0..=INCOMING_PATH_REQUEST_MIN_SAMPLE {
            stats.record_incoming_path_request(i as f64);
        }
        stats.record_outgoing_path_request(10.0);
        stats.record_outgoing_path_request(12.0);

        assert_eq!(stats.incoming_path_request_freq(2.0), 3.0 / 2.0);
        assert_eq!(stats.outgoing_path_request_freq(12.0), 2.0 / 2.0);
        assert_eq!(stats.outgoing_path_request_samples(), 2);
        // An outgoing frequency needs two samples, an incoming one three.
        stats.op_timestamps.pop();
        assert_eq!(stats.outgoing_path_request_freq(12.0), 0.0);
    }

    /// As upstream, each read decays the oldest sample once it is older
    /// than the decay time, one sample per read, and never below the
    /// minimum a frequency needs.
    #[test]
    fn sampling_decays_one_stale_sample_per_read() {
        let mut stats = InterfaceStats::default();
        for i in 0..5 {
            stats.record_incoming_announce(i as f64);
            stats.record_outgoing_announce(i as f64);
            stats.record_incoming_path_request(i as f64);
            stats.record_outgoing_path_request(i as f64);
        }

        // Nothing is older than the decay time yet.
        let sample = stats.sample_frequencies(AR_FREQ_DECAY);
        assert_eq!(sample.ia_freq, 5.0 / AR_FREQ_DECAY);
        assert_eq!(sample.ip_freq, 5.0 / PR_FREQ_DECAY);
        assert_eq!(sample.op_freq, 5.0 / PR_FREQ_DECAY);
        assert_eq!((sample.ia_samples, sample.op_samples), (5, 5));

        // The frequency is read before the oldest sample goes.
        let now = 100.0;
        let sample = stats.sample_frequencies(now);
        assert_eq!(sample.ia_freq, 5.0 / now);
        assert_eq!((sample.ia_samples, sample.op_samples), (4, 4));
        assert_eq!(stats.oa_timestamps.len(), 4);
        assert_eq!(stats.ip_timestamps.len(), 4);

        for _ in 0..10 {
            stats.sample_frequencies(now);
        }
        assert_eq!(stats.ia_timestamps.len(), INCOMING_ANNOUNCE_MIN_SAMPLE);
        assert_eq!(stats.ip_timestamps.len(), INCOMING_PATH_REQUEST_MIN_SAMPLE);
        assert_eq!(stats.oa_timestamps.len(), 1);
        assert_eq!(stats.op_timestamps.len(), 1);
        assert_eq!(stats.sample_frequencies(now).ia_freq, 0.0);
    }

    #[test]
    fn detailed_traffic_counts_bytes_without_changing_timestamp_bounds() {
        let mut stats = InterfaceStats::default();

        stats.record_incoming_announce_bytes(1.0, 101);
        stats.record_outgoing_announce_bytes(2.0, 202);
        stats.record_incoming_path_request_bytes(3.0, 303);
        stats.record_outgoing_path_request_bytes(4.0, 404);

        assert_eq!((stats.arxb, stats.atxb), (101, 202));
        assert_eq!((stats.arxc, stats.atxc), (1, 1));
        assert_eq!((stats.prxb, stats.ptxb), (303, 404));
        assert_eq!((stats.prxc, stats.ptxc), (1, 1));
        assert_eq!(stats.ia_timestamps, vec![1.0]);
        assert_eq!(stats.oa_timestamps, vec![2.0]);
        assert_eq!(stats.ip_timestamps, vec![3.0]);
        assert_eq!(stats.op_timestamps, vec![4.0]);
    }

    #[test]
    fn path_request_frequency_keeps_bounded_samples() {
        let mut stats = InterfaceStats::default();

        for i in 0..PATH_REQUEST_SAMPLE_MAX {
            stats.record_incoming_path_request(i as f64);
            stats.record_outgoing_path_request(i as f64);
        }

        stats.record_incoming_path_request(PATH_REQUEST_SAMPLE_MAX as f64);
        stats.record_outgoing_path_request(PATH_REQUEST_SAMPLE_MAX as f64);

        assert_eq!(stats.ip_timestamps.len(), PATH_REQUEST_SAMPLE_MAX);
        assert_eq!(stats.op_timestamps.len(), PATH_REQUEST_SAMPLE_MAX);
        assert_eq!(stats.ip_timestamps[0], 1.0);
        assert_eq!(stats.op_timestamps[0], 1.0);
    }
}
