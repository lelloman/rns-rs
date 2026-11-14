//! When the bridge may transmit, as upstream RNode firmware decides it:
//! listen before talk (CSMA with a DIFS and a random backoff that pauses
//! while the channel is busy) and the host's airtime limits.
//!
//! Pure logic over millisecond timestamps, so it runs in host tests; the
//! firmware feeds it the radio's carrier detect and a random source.

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
        let slot_ms = (symbols_ms.round() as u64).clamp(CSMA_SLOT_MIN_MS, CSMA_SLOT_MAX_MS);
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
        assert_eq!(Csma::new(8, 125_000).slot_ms(), 25); // 24.6 ms
        assert_eq!(Csma::new(7, 125_000).slot_ms(), 24); // 12.3 ms, at least 24
        assert_eq!(Csma::new(12, 125_000).slot_ms(), 100); // 393 ms, at most 100
    }

    #[test]
    fn waits_difs_then_backoff_on_a_free_channel() {
        let mut csma = Csma::new(8, 125_000); // slot 25, DIFS 50
        let mut random = |_, _| 3; // 75 ms backoff
        assert!(!csma.may_transmit(0, true, &mut random));
        assert!(!csma.may_transmit(49, true, &mut random));
        assert!(!csma.may_transmit(50, true, &mut random)); // backoff starts
        assert!(!csma.may_transmit(124, true, &mut random));
        assert!(csma.may_transmit(125, true, &mut random));
    }

    #[test]
    fn busy_channel_restarts_difs_but_keeps_backoff_counted() {
        let mut csma = Csma::new(8, 125_000);
        let mut random = |_, _| 4; // 100 ms backoff
        csma.may_transmit(0, true, &mut random);
        csma.may_transmit(50, true, &mut random);
        csma.may_transmit(110, true, &mut random); // 60 ms counted
        assert!(!csma.may_transmit(120, false, &mut random)); // carrier
        assert!(!csma.may_transmit(500, false, &mut random));
        assert!(!csma.may_transmit(510, true, &mut random)); // DIFS again
        assert!(!csma.may_transmit(560, true, &mut random)); // DIFS over, resume
        assert!(!csma.may_transmit(599, true, &mut random)); // 99 ms
        assert!(csma.may_transmit(600, true, &mut random)); // 100 ms
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
}
