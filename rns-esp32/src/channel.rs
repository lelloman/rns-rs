//! When the node may transmit, as upstream RNode firmware decides it:
//! listen before talk (CSMA with a DIFS and a random backoff that pauses
//! while the channel is busy) and airtime limits. Used by both the RNode
//! bridge and the standalone node.
//!
//! Pure logic over millisecond timestamps, so it runs in host tests; the
//! firmware feeds it the radio's carrier detect and a random source.

use std::collections::VecDeque;

use crate::modem;

/// RNode firmware `AIRTIME_BINLEN_MS`.
pub const AIRTIME_BINLEN_MS: u64 = 7_500;
/// RNode firmware `AIRTIME_LONGTERM_MS`.
pub const AIRTIME_LONGTERM_MS: u64 = 3_600_000;
/// RNode firmware `AIRTIME_BINS`.
pub const AIRTIME_BINS: usize = (AIRTIME_LONGTERM_MS / AIRTIME_BINLEN_MS) as usize;

/// RNode firmware `CSMA_SLOT_SYMBOLS`, `CSMA_SLOT_MIN_MS`, `CSMA_SLOT_MAX_MS`.
const CSMA_SLOT_SYMBOLS: f64 = 12.0;
const CSMA_SLOT_MIN_MS: u64 = 24;
const CSMA_SLOT_MAX_MS: u64 = 100;
/// RNode firmware `CSMA_CW_BANDS`, `CSMA_CW_PER_BAND_WINDOWS`,
/// `CSMA_BAND_1_MAX_AIRTIME` (percent).
const CSMA_CW_BANDS: u32 = 4;
const CSMA_CW_PER_BAND_WINDOWS: u32 = 15;
const CSMA_BAND_1_MAX_AIRTIME: f64 = 7.0;

/// Time on air of one LoRa packet of `payload_len` bytes, in milliseconds
/// (Semtech's formula: explicit header, CRC on, as this firmware sends).
pub fn packet_airtime_ms(
    payload_len: usize,
    spreading_factor: u8,
    bandwidth: u32,
    coding_rate: u8,
    preamble_symbols: u16,
) -> f64 {
    let symbol_ms = modem::symbol_time_ms(spreading_factor, bandwidth);
    let sf = spreading_factor as f64;
    let de = if modem::low_data_rate(spreading_factor, bandwidth) {
        1.0
    } else {
        0.0
    };
    let crc = 1.0;
    let numerator = 8.0 * payload_len as f64 - 4.0 * sf + 28.0 + 16.0 * crc;
    let payload_symbols =
        8.0 + ((numerator / (4.0 * (sf - 2.0 * de))).ceil() * coding_rate as f64).max(0.0);
    (preamble_symbols as f64 + 4.25 + payload_symbols) * symbol_ms
}

/// An airtime limit the host set with `CMD_ST_ALOCK` / `CMD_LT_ALOCK`: the
/// command carries hundredths of a percent. Zero, or 100 % and above, means
/// no limit, as upstream.
pub fn airtime_limit(command_value: u16) -> Option<f64> {
    let fraction = command_value as f64 / 10_000.0;
    (fraction > 0.0 && fraction < 1.0).then_some(fraction)
}

/// Airtime spent transmitting, in 7.5 s bins over the last hour.
pub struct Airtime {
    bins: Vec<f64>,
    /// Absolute index (`now / AIRTIME_BINLEN_MS`) of the newest bin written.
    current: u64,
}

impl Default for Airtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Airtime {
    pub fn new() -> Self {
        Self {
            bins: vec![0.0; AIRTIME_BINS],
            current: 0,
        }
    }

    /// Clear the bins that elapsed since the last update.
    fn advance(&mut self, now_ms: u64) {
        let bin = now_ms / AIRTIME_BINLEN_MS;
        if bin <= self.current {
            return;
        }
        let elapsed = (bin - self.current).min(AIRTIME_BINS as u64);
        for step in 1..=elapsed {
            self.bins[((self.current + step) % AIRTIME_BINS as u64) as usize] = 0.0;
        }
        self.current = bin;
    }

    /// Account a transmission of `airtime_ms` ending at `now_ms`.
    pub fn add(&mut self, now_ms: u64, airtime_ms: f64) {
        self.advance(now_ms);
        self.bins[(self.current % AIRTIME_BINS as u64) as usize] += airtime_ms;
    }

    /// Share of time spent transmitting over the current and previous bin.
    pub fn short_term(&mut self, now_ms: u64) -> f64 {
        self.advance(now_ms);
        let n = AIRTIME_BINS as u64;
        let current = self.bins[(self.current % n) as usize];
        let previous = self.bins[((self.current + n - 1) % n) as usize];
        (current + previous) / (2 * AIRTIME_BINLEN_MS) as f64
    }

    /// Share of time spent transmitting over the last hour.
    pub fn long_term(&mut self, now_ms: u64) -> f64 {
        self.advance(now_ms);
        self.bins.iter().sum::<f64>() / AIRTIME_LONGTERM_MS as f64
    }

    /// Upstream `airtime_lock`: a limit is set and reached.
    pub fn locked(
        &mut self,
        now_ms: u64,
        short_limit: Option<f64>,
        long_limit: Option<f64>,
    ) -> bool {
        short_limit.is_some_and(|limit| self.short_term(now_ms) >= limit)
            || long_limit.is_some_and(|limit| self.long_term(now_ms) >= limit)
    }
}

/// Listen before talk: the channel must stay free for a DIFS, then for a
/// random number of slots, counted only while it is free.
pub struct Csma {
    slot_ms: u64,
    difs_ms: u64,
    band: u32,
    /// Backoff for the pending transmission, in ms; drawn when it starts.
    target_ms: Option<u64>,
    /// Free time counted towards the backoff.
    passed_ms: u64,
    /// When the channel was last seen free after being busy.
    free_since: Option<u64>,
    /// When backoff time was last counted.
    counted_at: Option<u64>,
}

impl Csma {
    /// Slot time as upstream: 12 symbols, between 24 and 100 ms; DIFS is
    /// two slots.
    pub fn new(spreading_factor: u8, bandwidth: u32) -> Self {
        let symbols_ms = modem::symbol_time_ms(spreading_factor, bandwidth) * CSMA_SLOT_SYMBOLS;
        // Truncated, as upstream stores it in an int.
        let slot_ms = (symbols_ms as u64).clamp(CSMA_SLOT_MIN_MS, CSMA_SLOT_MAX_MS);
        Self {
            slot_ms,
            difs_ms: 2 * slot_ms,
            band: 1,
            target_ms: None,
            passed_ms: 0,
            free_since: None,
            counted_at: None,
        }
    }

    pub fn slot_ms(&self) -> u64 {
        self.slot_ms
    }

    pub fn difs_ms(&self) -> u64 {
        self.difs_ms
    }

    /// The contention window band, 1 to 4.
    pub fn band(&self) -> u32 {
        self.band
    }

    /// Widen the contention window as this node's own airtime grows: band 1
    /// up to 7 %, then bands 2 to 4 over the rest, as upstream intends.
    pub fn set_airtime(&mut self, short_term: f64) {
        let percent = short_term * 100.0;
        self.band = if percent <= CSMA_BAND_1_MAX_AIRTIME {
            1
        } else {
            let span = (100.0 - CSMA_BAND_1_MAX_AIRTIME) / (CSMA_CW_BANDS - 1) as f64;
            (2 + ((percent - CSMA_BAND_1_MAX_AIRTIME) / span) as u32).min(CSMA_CW_BANDS)
        };
    }

    /// The contention window of the current band, in slots.
    pub fn window(&self) -> (u32, u32) {
        (
            (self.band - 1) * CSMA_CW_PER_BAND_WINDOWS,
            self.band * CSMA_CW_PER_BAND_WINDOWS - 1,
        )
    }

    /// Whether a pending transmission may go now. `random(lo, hi)` returns a
    /// number in `lo..=hi`. Call it repeatedly while something is queued.
    pub fn may_transmit(
        &mut self,
        now_ms: u64,
        channel_free: bool,
        random: &mut impl FnMut(u32, u32) -> u32,
    ) -> bool {
        if self.target_ms.is_none() {
            let (lo, hi) = self.window();
            self.target_ms = Some(random(lo, hi) as u64 * self.slot_ms);
            self.passed_ms = 0;
        }
        if !channel_free {
            // Busy: restart the DIFS, keep the backoff already counted.
            self.free_since = None;
            self.counted_at = None;
            return false;
        }
        let free_since = *self.free_since.get_or_insert(now_ms);
        if now_ms.saturating_sub(free_since) < self.difs_ms {
            return false;
        }
        let counted_at = self.counted_at.replace(now_ms).unwrap_or(now_ms);
        self.passed_ms += now_ms.saturating_sub(counted_at);
        if self.passed_ms >= self.target_ms.unwrap_or(0) {
            self.target_ms = None;
            self.passed_ms = 0;
            self.free_since = None;
            self.counted_at = None;
            return true;
        }
        false
    }
}

/// Frames waiting for the channel, as upstream's TX queue: nothing goes
/// while an airtime limit is reached; otherwise, once listen before talk
/// allows, everything queued goes in one channel access.
pub struct TxChannel {
    queue: VecDeque<Vec<u8>>,
    max_frames: usize,
    csma: Csma,
    airtime: Airtime,
    short_limit: Option<f64>,
    long_limit: Option<f64>,
    spreading_factor: u8,
    bandwidth: u32,
    coding_rate: u8,
}

impl TxChannel {
    /// A queue of up to `max_frames` frames on the given LoRa channel.
    pub fn new(spreading_factor: u8, bandwidth: u32, coding_rate: u8, max_frames: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_frames,
            csma: Csma::new(spreading_factor, bandwidth),
            airtime: Airtime::new(),
            short_limit: None,
            long_limit: None,
            spreading_factor,
            bandwidth,
            coding_rate,
        }
    }

    /// Switch to another LoRa channel. Accounted airtime and limits stay.
    pub fn reconfigure(&mut self, spreading_factor: u8, bandwidth: u32, coding_rate: u8) {
        self.csma = Csma::new(spreading_factor, bandwidth);
        self.spreading_factor = spreading_factor;
        self.bandwidth = bandwidth;
        self.coding_rate = coding_rate;
    }

    /// Short-term airtime limit, a fraction of time (`None`: no limit).
    pub fn set_short_term_limit(&mut self, limit: Option<f64>) {
        self.short_limit = limit;
    }

    /// Long-term airtime limit, a fraction of time (`None`: no limit).
    pub fn set_long_term_limit(&mut self, limit: Option<f64>) {
        self.long_limit = limit;
    }

    /// Queue a frame; `false` when the queue is full and the frame dropped,
    /// as upstream refuses frames then.
    pub fn push(&mut self, frame: Vec<u8>) -> bool {
        if self.queue.len() >= self.max_frames {
            return false;
        }
        self.queue.push_back(frame);
        true
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Listen before talk for the current channel.
    pub fn csma(&self) -> &Csma {
        &self.csma
    }

    /// This node's short- and long-term airtime, fractions of time; also
    /// updates the contention window, which widens with airtime.
    pub fn airtime(&mut self, now_ms: u64) -> (f64, f64) {
        let short_term = self.airtime.short_term(now_ms);
        self.csma.set_airtime(short_term);
        (short_term, self.airtime.long_term(now_ms))
    }

    /// How often to call [`Self::take_ready`] while frames are queued.
    pub fn poll_interval_ms(&self) -> u64 {
        (self.csma.slot_ms() / 4).max(1)
    }

    /// The queued frames, when the channel lets them go now. Call it
    /// repeatedly while frames are queued; `channel_free` (carrier detect)
    /// is only asked when the airtime limits allow sending. Account each
    /// frame sent with [`Self::record_sent`].
    pub fn take_ready(
        &mut self,
        now_ms: u64,
        channel_free: impl FnOnce() -> bool,
        random: &mut impl FnMut(u32, u32) -> u32,
    ) -> Option<VecDeque<Vec<u8>>> {
        if self.queue.is_empty()
            || self
                .airtime
                .locked(now_ms, self.short_limit, self.long_limit)
        {
            return None;
        }
        let short_term = self.airtime.short_term(now_ms);
        self.csma.set_airtime(short_term);
        if !self.csma.may_transmit(now_ms, channel_free(), random) {
            return None;
        }
        Some(std::mem::take(&mut self.queue))
    }

    /// Account the airtime of a frame sent, ending at `now_ms`.
    pub fn record_sent(&mut self, now_ms: u64, frame: &[u8]) {
        let airtime = self.frame_airtime_ms(frame);
        self.airtime.add(now_ms, airtime);
    }

    /// Airtime of a frame: one LoRa packet, or two for a split frame.
    pub fn frame_airtime_ms(&self, frame: &[u8]) -> f64 {
        let preamble =
            modem::preamble_symbols(self.spreading_factor, self.bandwidth, self.coding_rate);
        crate::airframe::packets(frame, 0)
            .unwrap_or_default()
            .iter()
            .map(|packet| {
                packet_airtime_ms(
                    packet.len(),
                    self.spreading_factor,
                    self.bandwidth,
                    self.coding_rate,
                    preamble,
                )
            })
            .sum()
    }
}

/// RNode firmware `STATUS_INTERVAL_MS`: how often the channel is sampled.
pub const SAMPLE_INTERVAL_MS: u64 = 3;
/// RNode firmware `DCD_SAMPLES`: carrier samples behind the channel load.
const DCD_SAMPLES: usize = 2_500;
/// RNode firmware `UTIL_UPDATE_INTERVAL_MS`.
const UTIL_UPDATE_INTERVAL_MS: u64 = 1_000;
/// RNode firmware `NOISE_FLOOR_SAMPLES`.
const NOISE_FLOOR_SAMPLES: usize = 128;
/// RNode firmware `CSMA_INFR_THRESHOLD_DB`, `CSMA_RFENV_RECAL_MS`,
/// `CSMA_RFENV_RECAL_LIMIT_DB`.
const INTERFERENCE_THRESHOLD_DB: i16 = 11;
const RF_ENV_RECAL_MS: u64 = 2_500;
const RF_ENV_RECAL_LIMIT_DB: i16 = -83;
/// RNode firmware's value for an RSSI not measured yet.
const RSSI_UNKNOWN: i16 = -292;

/// What the channel looks like, as RNode firmware measures it: carrier
/// detect and RSSI sampled every [`SAMPLE_INTERVAL_MS`] give the channel
/// load (busy samples plus this node's airtime), the noise floor (mean RSSI
/// of quiet samples) and interference (RSSI well above the noise floor
/// with no LoRa carrier).
pub struct ChannelMonitor {
    busy: Vec<bool>,
    busy_next: usize,
    last_sample_ms: Option<u64>,
    last_update_ms: Option<u64>,
    /// Peak channel load per airtime bin, over the last hour.
    load_bins: Vec<f64>,
    load_bin: u64,
    channel_load: f64,
    current_rssi: i16,
    noise: [i16; NOISE_FLOOR_SAMPLES],
    noise_next: usize,
    noise_sampled: bool,
    noise_floor: i16,
    interference: bool,
    interference_since: Option<u64>,
}

impl Default for ChannelMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelMonitor {
    pub fn new() -> Self {
        Self {
            busy: vec![false; DCD_SAMPLES],
            busy_next: 0,
            last_sample_ms: None,
            last_update_ms: None,
            load_bins: vec![0.0; AIRTIME_BINS],
            load_bin: 0,
            channel_load: 0.0,
            current_rssi: RSSI_UNKNOWN,
            noise: [0; NOISE_FLOOR_SAMPLES],
            noise_next: 0,
            noise_sampled: false,
            noise_floor: RSSI_UNKNOWN,
            interference: false,
            interference_since: None,
        }
    }

    /// Whether the next sample is due.
    pub fn sample_due(&self, now_ms: u64) -> bool {
        self.last_sample_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= SAMPLE_INTERVAL_MS)
    }

    /// Record a sample: whether a LoRa carrier is on the channel, and the
    /// RSSI. Returns `true` once a second, when the channel load is
    /// updated (with `airtime_short`, this node's own share): the moment
    /// RNode firmware reports channel stats.
    pub fn sample(&mut self, now_ms: u64, carrier: bool, rssi: i16, airtime_short: f64) -> bool {
        self.last_sample_ms = Some(now_ms);
        self.current_rssi = rssi;
        self.update_interference(now_ms, carrier, rssi);
        self.update_noise_floor(carrier, rssi);
        self.busy[self.busy_next] = carrier;
        self.busy_next = (self.busy_next + 1) % DCD_SAMPLES;

        if self
            .last_update_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < UTIL_UPDATE_INTERVAL_MS)
        {
            return false;
        }
        self.last_update_ms = Some(now_ms);
        let busy = self.busy.iter().filter(|&&b| b).count() as f64 / DCD_SAMPLES as f64;
        self.channel_load = (busy + airtime_short).min(1.0);
        self.advance_load_bins(now_ms);
        let bin = (self.load_bin % AIRTIME_BINS as u64) as usize;
        if self.channel_load > self.load_bins[bin] {
            self.load_bins[bin] = self.channel_load;
        }
        true
    }

    fn update_interference(&mut self, now_ms: u64, carrier: bool, rssi: i16) {
        // Not before the floor is measured: against RNode firmware's initial
        // -292 dBm every sample would count.
        self.interference =
            self.noise_sampled && !carrier && rssi > self.noise_floor + INTERFERENCE_THRESHOLD_DB;
        // Persistent "interference" at a low level is more likely a changed
        // RF environment (antenna, LNA, location): sample the floor anew.
        if self.interference && rssi < RF_ENV_RECAL_LIMIT_DB {
            let since = *self.interference_since.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= RF_ENV_RECAL_MS {
                self.noise_sampled = false;
                self.interference_since = None;
            }
        } else {
            self.interference_since = None;
        }
    }

    fn update_noise_floor(&mut self, carrier: bool, rssi: i16) {
        if carrier || (self.noise_sampled && rssi >= self.noise_floor + INTERFERENCE_THRESHOLD_DB) {
            return;
        }
        self.noise[self.noise_next] = rssi;
        self.noise_next += 1;
        if self.noise_next >= NOISE_FLOOR_SAMPLES {
            self.noise_next = 0;
            self.noise_sampled = true;
            let sum: i32 = self.noise.iter().map(|&n| n as i32).sum();
            self.noise_floor = (sum / NOISE_FLOOR_SAMPLES as i32) as i16;
        }
    }

    fn advance_load_bins(&mut self, now_ms: u64) {
        let bin = now_ms / AIRTIME_BINLEN_MS;
        if bin <= self.load_bin {
            return;
        }
        let elapsed = (bin - self.load_bin).min(AIRTIME_BINS as u64);
        for step in 1..=elapsed {
            self.load_bins[((self.load_bin + step) % AIRTIME_BINS as u64) as usize] = 0.0;
        }
        self.load_bin = bin;
    }

    /// Channel load over the last 7.5 s, this node's airtime included.
    pub fn channel_load(&self) -> f64 {
        self.channel_load
    }

    /// Mean of the peak load per airtime bin over the last hour.
    pub fn long_term_channel_load(&self) -> f64 {
        self.load_bins.iter().sum::<f64>() / AIRTIME_BINS as f64
    }

    pub fn current_rssi(&self) -> i16 {
        self.current_rssi
    }

    pub fn noise_floor(&self) -> i16 {
        self.noise_floor
    }

    /// The RSSI of interference on the channel, if any.
    pub fn interference(&self) -> Option<i16> {
        self.interference.then_some(self.current_rssi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airtime_matches_the_lora_formula() {
        // SF8 / 125 kHz / CR 4/5, 18-symbol preamble: 2.048 ms symbols.
        // 183 bytes: 8 + ceil((1464 - 32 + 28 + 16) / 32) * 5 = 243 symbols.
        let ms = packet_airtime_ms(183, 8, 125_000, 5, 18);
        assert!((ms - (18.0 + 4.25 + 243.0) * 2.048).abs() < 1e-9, "{ms}");
        // Low data rate optimisation at SF12 / 125 kHz.
        let slow = packet_airtime_ms(10, 12, 125_000, 5, 18);
        assert!(slow > packet_airtime_ms(10, 11, 125_000, 5, 18));
    }

    #[test]
    fn limits_use_hundredths_of_a_percent() {
        assert_eq!(airtime_limit(0), None);
        assert_eq!(airtime_limit(10_000), None);
        assert_eq!(airtime_limit(100), Some(0.01));
        assert_eq!(airtime_limit(1_000), Some(0.1));
    }

    #[test]
    fn short_term_covers_two_bins_and_long_term_the_hour() {
        let mut airtime = Airtime::new();
        airtime.add(1_000, 1_500.0);
        assert!((airtime.short_term(1_000) - 0.1).abs() < 1e-9);
        // Next bin: still counted.
        assert!((airtime.short_term(8_000) - 0.1).abs() < 1e-9);
        // Two bins later: out of the short-term window, still in the hour.
        assert_eq!(airtime.short_term(16_000), 0.0);
        assert!((airtime.long_term(16_000) - 1_500.0 / 3_600_000.0).abs() < 1e-12);
        // An hour later it is gone.
        assert_eq!(airtime.long_term(1_000 + AIRTIME_LONGTERM_MS + 1), 0.0);
    }

    #[test]
    fn locks_while_a_limit_is_reached() {
        let mut airtime = Airtime::new();
        airtime.add(0, 1_500.0); // 10 % short term
        assert!(airtime.locked(0, Some(0.05), None));
        assert!(!airtime.locked(0, Some(0.2), None));
        assert!(!airtime.locked(0, None, None));
        assert!(airtime.locked(0, None, Some(0.0001)));
        assert!(
            !airtime.locked(20_000, Some(0.05), None),
            "short term expires"
        );
    }

    #[test]
    fn slot_is_twelve_symbols_clamped() {
        assert_eq!(Csma::new(8, 125_000).slot_ms(), 24); // 24.6 ms, truncated
        assert_eq!(Csma::new(9, 125_000).slot_ms(), 49); // 49.2 ms
        assert_eq!(Csma::new(7, 125_000).slot_ms(), 24); // 12.3 ms, at least 24
        assert_eq!(Csma::new(12, 125_000).slot_ms(), 100); // 393 ms, at most 100
    }

    #[test]
    fn waits_difs_then_backoff_on_a_free_channel() {
        let mut csma = Csma::new(8, 125_000); // slot 24, DIFS 48
        let mut random = |_, _| 3; // 72 ms backoff
        assert!(!csma.may_transmit(0, true, &mut random));
        assert!(!csma.may_transmit(47, true, &mut random));
        assert!(!csma.may_transmit(48, true, &mut random)); // backoff starts
        assert!(!csma.may_transmit(119, true, &mut random));
        assert!(csma.may_transmit(120, true, &mut random));
    }

    #[test]
    fn busy_channel_restarts_difs_but_keeps_backoff_counted() {
        let mut csma = Csma::new(8, 125_000);
        let mut random = |_, _| 4; // 96 ms backoff
        csma.may_transmit(0, true, &mut random);
        csma.may_transmit(48, true, &mut random);
        csma.may_transmit(108, true, &mut random); // 60 ms counted
        assert!(!csma.may_transmit(120, false, &mut random)); // carrier
        assert!(!csma.may_transmit(500, false, &mut random));
        assert!(!csma.may_transmit(510, true, &mut random)); // DIFS again
        assert!(!csma.may_transmit(558, true, &mut random)); // DIFS over, resume
        assert!(!csma.may_transmit(593, true, &mut random)); // 95 ms
        assert!(csma.may_transmit(594, true, &mut random)); // 96 ms
    }

    #[test]
    fn never_transmits_while_the_channel_stays_busy() {
        let mut csma = Csma::new(8, 125_000);
        let mut random = |_, _| 0;
        for t in (0..10_000).step_by(10) {
            assert!(!csma.may_transmit(t, false, &mut random));
        }
    }

    #[test]
    fn window_widens_with_own_airtime() {
        let mut csma = Csma::new(8, 125_000);
        assert_eq!(csma.window(), (0, 14));
        csma.set_airtime(0.20);
        assert_eq!(csma.window(), (15, 29));
        csma.set_airtime(0.99);
        assert_eq!(csma.window(), (45, 59));
    }

    fn first_slot(_lo: u32, _hi: u32) -> u32 {
        0
    }

    #[test]
    fn tx_channel_sends_everything_queued_after_the_difs() {
        let mut tx = TxChannel::new(8, 125_000, 5, 4);
        let difs = 2 * Csma::new(8, 125_000).slot_ms();
        assert!(tx.take_ready(0, || true, &mut first_slot).is_none());
        assert!(tx.push(vec![1; 10]));
        assert!(tx.push(vec![2; 10]));
        assert!(tx.take_ready(0, || true, &mut first_slot).is_none());
        let frames = tx.take_ready(difs, || true, &mut first_slot).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(tx.is_empty());
    }

    #[test]
    fn tx_channel_waits_while_the_channel_is_busy() {
        let mut tx = TxChannel::new(8, 125_000, 5, 4);
        let difs = 2 * Csma::new(8, 125_000).slot_ms();
        tx.push(vec![1; 10]);
        assert!(tx.take_ready(0, || false, &mut first_slot).is_none());
        assert!(tx.take_ready(difs, || false, &mut first_slot).is_none());
        // Free from here: the DIFS starts over.
        assert!(tx.take_ready(difs + 1, || true, &mut first_slot).is_none());
        assert!(tx
            .take_ready(2 * difs + 1, || true, &mut first_slot)
            .is_some());
    }

    #[test]
    fn tx_channel_queue_is_bounded() {
        let mut tx = TxChannel::new(8, 125_000, 5, 2);
        assert!(tx.push(vec![1]));
        assert!(tx.push(vec![2]));
        assert!(!tx.push(vec![3]));
    }

    #[test]
    fn tx_channel_holds_frames_while_an_airtime_limit_is_reached() {
        let mut tx = TxChannel::new(8, 125_000, 5, 4);
        let difs = 2 * Csma::new(8, 125_000).slot_ms();
        tx.set_short_term_limit(Some(0.1));
        // 2 s of airtime in the last 15 s is over 10 %.
        tx.airtime.add(0, 2_000.0);
        tx.push(vec![1; 10]);
        let mut asked = false;
        assert!(tx
            .take_ready(
                difs,
                || {
                    asked = true;
                    true
                },
                &mut first_slot
            )
            .is_none());
        assert!(!asked, "carrier detect is not read while locked");
        // Two bins later the airtime has aged out.
        let later = 2 * AIRTIME_BINLEN_MS;
        assert!(tx.take_ready(later, || true, &mut first_slot).is_none());
        assert!(tx
            .take_ready(later + difs, || true, &mut first_slot)
            .is_some());
    }

    #[test]
    fn tx_channel_accounts_split_frames_as_two_packets() {
        let mut tx = TxChannel::new(8, 125_000, 5, 4);
        let one = tx.frame_airtime_ms(&[0; 200]);
        let two = tx.frame_airtime_ms(&[0; 400]);
        assert!(two > 1.8 * one, "{one} {two}");
        tx.record_sent(1_000, &[0; 200]);
        assert!((tx.airtime.short_term(1_000) - one / 15_000.0).abs() < 1e-9);
    }

    #[test]
    fn monitor_samples_every_interval_and_reports_each_second() {
        let mut monitor = ChannelMonitor::new();
        assert!(monitor.sample_due(0));
        assert!(monitor.sample(0, false, -120, 0.0), "first sample reports");
        assert!(!monitor.sample_due(SAMPLE_INTERVAL_MS - 1));
        assert!(monitor.sample_due(SAMPLE_INTERVAL_MS));
        assert!(!monitor.sample(500, false, -120, 0.0));
        assert!(monitor.sample(1_000, false, -120, 0.0));
    }

    #[test]
    fn channel_load_counts_busy_samples_and_own_airtime() {
        let mut monitor = ChannelMonitor::new();
        let mut now = 0;
        // A quarter of the window busy.
        for i in 0..DCD_SAMPLES {
            monitor.sample(now, i % 4 == 0, -120, 0.0);
            now += SAMPLE_INTERVAL_MS;
        }
        monitor.sample(now + UTIL_UPDATE_INTERVAL_MS, false, -120, 0.1);
        assert!(
            (monitor.channel_load() - 0.35).abs() < 0.01,
            "{}",
            monitor.channel_load()
        );
        assert!(monitor.long_term_channel_load() > 0.0);
    }

    #[test]
    fn noise_floor_is_the_mean_of_quiet_samples() {
        let mut monitor = ChannelMonitor::new();
        assert_eq!(monitor.noise_floor(), RSSI_UNKNOWN);
        for i in 0..NOISE_FLOOR_SAMPLES as u64 {
            // Carrier samples do not count.
            monitor.sample(i * 10, true, -50, 0.0);
            monitor.sample(i * 10 + 5, false, if i % 2 == 0 { -118 } else { -120 }, 0.0);
        }
        assert_eq!(monitor.noise_floor(), -119);
        assert_eq!(monitor.interference(), None);
    }

    #[test]
    fn strong_signal_without_carrier_is_interference() {
        let mut monitor = ChannelMonitor::new();
        for i in 0..NOISE_FLOOR_SAMPLES as u64 {
            monitor.sample(i * 5, false, -120, 0.0);
        }
        monitor.sample(1_000, false, -95, 0.0);
        assert_eq!(monitor.interference(), Some(-95));
        // A LoRa carrier is not interference, and does not move the floor.
        monitor.sample(1_005, true, -60, 0.0);
        assert_eq!(monitor.interference(), None);
        assert_eq!(monitor.noise_floor(), -120);
    }

    #[test]
    fn persistent_low_level_interference_resamples_the_noise_floor() {
        let mut monitor = ChannelMonitor::new();
        for i in 0..NOISE_FLOOR_SAMPLES as u64 {
            monitor.sample(i * 5, false, -120, 0.0);
        }
        // The environment changed: -100 dBm everywhere from now on.
        let mut now = 1_000;
        while now < 1_000 + RF_ENV_RECAL_MS + 2 * NOISE_FLOOR_SAMPLES as u64 * 5 {
            monitor.sample(now, false, -100, 0.0);
            now += 5;
        }
        assert_eq!(monitor.noise_floor(), -100);
        assert_eq!(monitor.interference(), None);
    }
}
