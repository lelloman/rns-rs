//! Checking radio settings, and the LoRa bitrate and airtime they give.

use super::*;

/// Validate subinterface configuration. Returns error message if invalid.
pub fn validate_sub_config(sub: &RNodeSubConfig) -> Option<String> {
    if sub.frequency < FREQ_MIN || sub.frequency > FREQ_MAX {
        return Some(format!(
            "Invalid frequency {} for {}",
            sub.frequency, sub.name
        ));
    }
    if sub.bandwidth < BW_MIN || sub.bandwidth > BW_MAX {
        return Some(format!(
            "Invalid bandwidth {} for {}",
            sub.bandwidth, sub.name
        ));
    }
    if sub.spreading_factor < SF_MIN || sub.spreading_factor > SF_MAX {
        return Some(format!(
            "Invalid SF {} for {}",
            sub.spreading_factor, sub.name
        ));
    }
    if sub.coding_rate < CR_MIN || sub.coding_rate > CR_MAX {
        return Some(format!("Invalid CR {} for {}", sub.coding_rate, sub.name));
    }
    if sub.txpower < TXPOWER_MIN || sub.txpower > TXPOWER_MAX {
        return Some(format!("Invalid TX power {} for {}", sub.txpower, sub.name));
    }
    if let Some(st) = sub.st_alock {
        if !(0.0..=100.0).contains(&st) {
            return Some(format!("Invalid ST airtime limit {} for {}", st, sub.name));
        }
    }
    if let Some(lt) = sub.lt_alock {
        if !(0.0..=100.0).contains(&lt) {
            return Some(format!("Invalid LT airtime limit {} for {}", lt, sub.name));
        }
    }
    None
}

/// Estimate the LoRa physical bit rate for announce bandwidth gating.
///
/// Formula: SF * (bandwidth / 2^SF) * (4 / coding_rate).
pub fn estimate_lora_bitrate_bps(sub: &RNodeSubConfig) -> u64 {
    let symbols_per_second = sub.bandwidth as f64 / (1u64 << sub.spreading_factor) as f64;
    let bits_per_symbol = sub.spreading_factor as f64 * (4.0 / sub.coding_rate as f64);
    (symbols_per_second * bits_per_symbol).round().max(1.0) as u64
}

/// LoRa airtime parameters of a subinterface, for airtime estimates.
pub fn lora_airtime_profile(sub: &RNodeSubConfig) -> AirtimeProfile {
    AirtimeProfile::Lora {
        bandwidth: sub.bandwidth,
        spreading_factor: sub.spreading_factor,
        coding_rate: sub.coding_rate,
        preamble_symbols: LORA_PREAMBLE_SYMBOLS,
        explicit_header: LORA_EXPLICIT_HEADER,
        crc: LORA_CRC,
    }
}
