//! LoRa modem settings derived from the channel as RNode firmware derives
//! them (`updateBitrate()` and `sx126x::handleLowDataRate()`), so a packet
//! from this firmware is demodulated by an RNode on the same channel and
//! the other way round: the preamble length and low data rate optimization
//! are not sent on air and must agree.

/// RNode firmware `LORA_PREAMBLE_SYMBOLS_MIN`.
const PREAMBLE_SYMBOLS_MIN: u16 = 18;
/// RNode firmware `LORA_PREAMBLE_TARGET_MS`.
const PREAMBLE_TARGET_MS: f64 = 24.0;
/// RNode firmware `LORA_PREAMBLE_FAST_DELTA`.
const PREAMBLE_FAST_DELTA_MS: f64 = 18.0;
/// RNode firmware `LORA_FAST_THRESHOLD_BPS`.
const FAST_THRESHOLD_BPS: u32 = 30_000;

/// The duration of one LoRa symbol in milliseconds.
pub fn symbol_time_ms(spreading_factor: u8, bandwidth: u32) -> f64 {
    let symbol_rate = bandwidth as f64 / (1u32 << spreading_factor) as f64;
    1000.0 / symbol_rate
}

/// The on-air bitrate as RNode firmware computes it, truncated to whole
/// bits per second.
pub fn bitrate(spreading_factor: u8, bandwidth: u32, coding_rate: u8) -> u32 {
    let sf = spreading_factor as f64;
    let chips = (1u32 << spreading_factor) as f64;
    (sf * ((4.0 / coding_rate as f64) / (chips / (bandwidth as f64 / 1000.0))) * 1000.0) as u32
}

/// The preamble in symbols: 24 ms (6 ms above 30 kbit/s), at least 18.
pub fn preamble_symbols(spreading_factor: u8, bandwidth: u32, coding_rate: u8) -> u16 {
    let mut target_ms = PREAMBLE_TARGET_MS;
    if bitrate(spreading_factor, bandwidth, coding_rate) > FAST_THRESHOLD_BPS {
        target_ms -= PREAMBLE_FAST_DELTA_MS;
    }
    let symbols = target_ms / symbol_time_ms(spreading_factor, bandwidth);
    if symbols < PREAMBLE_SYMBOLS_MIN as f64 {
        PREAMBLE_SYMBOLS_MIN
    } else {
        symbols.ceil() as u16
    }
}

/// Whether low data rate optimization is on. RNode firmware tests
/// `(1 << sf) / (bandwidth / 1000) > 16` in integers, so it is off at
/// SF11 / 125 kHz, whose symbols last 16.4 ms.
pub fn low_data_rate(spreading_factor: u8, bandwidth: u32) -> bool {
    let khz = bandwidth / 1000;
    khz > 0 && (1u32 << spreading_factor) / khz > 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_follows_rnode_firmware() {
        // 24 ms, at least 18 symbols.
        assert_eq!(preamble_symbols(7, 125_000, 5), 24);
        assert_eq!(preamble_symbols(8, 125_000, 5), 18);
        assert_eq!(preamble_symbols(12, 125_000, 5), 18);
        assert_eq!(preamble_symbols(6, 125_000, 5), 47);
        // Above 30 kbit/s the target is 6 ms.
        assert_eq!(bitrate(7, 500_000, 5), 21_875);
        assert_eq!(preamble_symbols(7, 500_000, 5), 94);
        assert_eq!(bitrate(6, 500_000, 5), 37_500);
        assert_eq!(preamble_symbols(6, 500_000, 5), 47);
    }

    #[test]
    fn low_data_rate_follows_rnode_firmware() {
        assert!(!low_data_rate(10, 125_000));
        // 16.4 ms symbols, but 2048 / 125 = 16 in integers.
        assert!(!low_data_rate(11, 125_000));
        assert!(low_data_rate(12, 125_000));
        assert!(!low_data_rate(10, 62_500));
        assert!(low_data_rate(11, 62_500));
        assert!(!low_data_rate(12, 250_000));
        assert!(low_data_rate(9, 20_800));
    }

    #[test]
    fn bitrate_matches_rnode_firmware() {
        assert_eq!(bitrate(8, 125_000, 5), 3125);
        assert_eq!(bitrate(7, 125_000, 5), 5468);
    }
}
