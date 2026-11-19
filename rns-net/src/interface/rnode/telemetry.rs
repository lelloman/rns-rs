//! Radio statistics and the telemetry published from them.

use super::*;

/// Apply a device report to `radio`, as upstream `RNodeInterface` keeps
/// it. Returns whether it changed what the interface reports; PHY and CSMA
/// reports are only logged, as upstream.
pub(super) fn update_radio_stats(
    event: &rnode_kiss::RNodeEvent,
    radio: &mut RadioStats,
    now: f64,
) -> bool {
    const RSSI_OFFSET: i16 = 157;
    match *event {
        rnode_kiss::RNodeEvent::ChannelStats {
            airtime_short,
            airtime_long,
            channel_load_short,
            channel_load_long,
            current_rssi,
            noise_floor,
            interference,
        } => {
            radio.airtime_short = f64::from(airtime_short) / 100.0;
            radio.airtime_long = f64::from(airtime_long) / 100.0;
            radio.channel_load_short = f64::from(channel_load_short) / 100.0;
            radio.channel_load_long = f64::from(channel_load_long) / 100.0;
            radio.current_rssi = Some(i16::from(current_rssi) - RSSI_OFFSET);
            radio.noise_floor = Some(i16::from(noise_floor) - RSSI_OFFSET);
            radio.interference =
                (interference != 0xFF).then(|| i16::from(interference) - RSSI_OFFSET);
            if let Some(rssi) = radio.interference {
                radio.interference_last = Some((now, rssi));
            }
            true
        }
        rnode_kiss::RNodeEvent::Battery { state, percent } => {
            radio.battery_state = state;
            radio.battery_percent = percent.min(100);
            true
        }
        rnode_kiss::RNodeEvent::Temperature(raw) => {
            let celsius = i16::from(raw) - 120;
            radio.temperature = (-30..=90).contains(&celsius).then_some(celsius);
            true
        }
        // Logged by the caller, as upstream logs them.
        rnode_kiss::RNodeEvent::PhyStats { .. } | rnode_kiss::RNodeEvent::CsmaStats { .. } => false,
        _ => false,
    }
}

/// Log the radio timing and contention reports of an RNodeMultiInterface
/// device (a single RNode's are logged as upstream by its reports).
pub(super) fn log_multi_radio_report(event: &rnode_kiss::RNodeEvent, name: &str) {
    match *event {
        rnode_kiss::RNodeEvent::PhyStats {
            symbol_time_us,
            symbol_rate,
            preamble_symbols,
            preamble_ms,
            csma_slot_ms,
            difs_ms,
        } => log::debug!(
            "[{}] radio reports {:.2} ms symbols ({} baud), {}-symbol preamble ({} ms), \
             CSMA slot {} ms, DIFS {} ms",
            name,
            f64::from(symbol_time_us) / 1000.0,
            symbol_rate,
            preamble_symbols,
            preamble_ms,
            csma_slot_ms,
            difs_ms
        ),
        rnode_kiss::RNodeEvent::CsmaStats {
            band,
            window_min,
            window_max,
        } => log::trace!(
            "[{}] radio reports contention window band {} ({}-{} slots)",
            name,
            band,
            window_min,
            window_max
        ),
        _ => {}
    }
}

/// Telemetry carrying only the device's channel and self report.
pub(super) fn radio_telemetry<'a>(
    config: &'a RNodeConfig,
    radio: &'a RadioStats,
) -> impl Iterator<Item = Event> + 'a {
    (0..config.subinterfaces.len()).map(move |i| Event::InterfaceTelemetry {
        interface_id: InterfaceId(config.base_interface_id.0 + i as u64),
        telemetry: Box::new(InterfaceTelemetry {
            radio: Some(*radio),
            ..Default::default()
        }),
    })
}

pub(super) fn publish_radio_telemetry(tx: &EventSender, config: &RNodeConfig, radio: &RadioStats) {
    for event in radio_telemetry(config, radio) {
        let _ = tx.send(event);
    }
}

/// Python RNodeInterface's signal-quality mapping, clamped to 0..100 and
/// rounded to one decimal place.
pub(super) fn signal_quality(spreading_factor: u8, snr: f32) -> f64 {
    let sfs = spreading_factor.saturating_sub(7) as f64;
    let q_snr_min = -9.0 - sfs * 2.0;
    let q_snr_max = 6.0;
    let span = q_snr_max - q_snr_min;
    if span <= 0.0 {
        return 0.0;
    }
    let quality = (((f64::from(snr) - q_snr_min) / span) * 100.0).clamp(0.0, 100.0);
    (quality * 10.0).round() / 10.0
}

pub(super) fn publish_phy_telemetry(
    tx: &EventSender,
    config: &RNodeConfig,
    rssi: Option<i16>,
    snr: Option<f32>,
) {
    for event in phy_telemetry(config, rssi, snr, None) {
        let _ = tx.send(event);
    }
}

/// One telemetry event per subinterface.
pub(super) fn phy_telemetry(
    config: &RNodeConfig,
    rssi: Option<i16>,
    snr: Option<f32>,
    radio: Option<RadioStats>,
) -> impl Iterator<Item = Event> + '_ {
    config
        .subinterfaces
        .iter()
        .enumerate()
        .map(move |(i, sub)| {
            let telemetry = InterfaceTelemetry {
                rssi,
                snr,
                signal_quality: snr.map(|snr| signal_quality(sub.spreading_factor, snr)),
                frequency: Some(sub.frequency),
                bandwidth: Some(sub.bandwidth),
                txpower: Some(sub.txpower),
                spreading_factor: Some(sub.spreading_factor),
                coding_rate: Some(sub.coding_rate),
                channel: None,
                modulation: Some("LoRa".to_string()),
                radio,
                ..Default::default()
            };
            Event::InterfaceTelemetry {
                interface_id: InterfaceId(config.base_interface_id.0 + i as u64),
                telemetry: Box::new(telemetry),
            }
        })
}
