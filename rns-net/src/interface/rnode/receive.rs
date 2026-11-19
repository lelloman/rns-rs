//! What the bytes read from an RNode carry, for both I/O engines: decoded
//! frames and reports, turned into driver events.

use super::setup::{self, RadioReports};
use super::*;

/// The receiving side of one connection to an RNode.
pub(super) struct RNodeReceiver {
    decoder: rnode_kiss::RNodeDecoder,
    /// The modem's report for the frame that follows it.
    last_rssi: Option<i16>,
    last_snr: Option<f32>,
    /// What the device reports about its channel and itself.
    radio: RadioStats,
    /// What a single RNode reports about its radio, logged as upstream.
    reports: RadioReports,
    /// The interface as upstream writes it.
    name: String,
}

impl RNodeReceiver {
    /// A receiver for a fresh connection to the device `config` describes.
    pub(super) fn new(config: &RNodeConfig) -> Self {
        Self {
            decoder: rnode_kiss::RNodeDecoder::new(),
            last_rssi: None,
            last_snr: None,
            radio: RadioStats::default(),
            reports: RadioReports::new(config),
            name: setup::display_name(config),
        }
    }

    /// Decode `bytes` read from the device, appending the events they
    /// produce (frames for the subinterfaces, telemetry) to `events`, and
    /// sending the queued frames of flow-controlled subinterfaces when the
    /// device is ready for more.
    pub(super) fn feed(
        &mut self,
        bytes: &[u8],
        config: &RNodeConfig,
        flow_states: &[Arc<Mutex<SubFlowState>>],
        writer: &Arc<Mutex<DeviceWriter>>,
        events: &mut Vec<Event>,
    ) {
        for event in self.decoder.feed(bytes) {
            if config.multi {
                log_multi_radio_report(&event, &config.name);
            } else {
                self.reports.apply(&event, &self.name);
            }
            if update_radio_stats(&event, &mut self.radio, crate::time::now()) {
                events.extend(radio_telemetry(config, &self.radio));
                continue;
            }
            let phy_stat = matches!(
                &event,
                rnode_kiss::RNodeEvent::StatRssi(_) | rnode_kiss::RNodeEvent::StatSnr(_)
            );
            if update_pending_rx_metadata(&event, &mut self.last_rssi, &mut self.last_snr) {
                if phy_stat {
                    events.extend(phy_telemetry(config, self.last_rssi, self.last_snr, None));
                }
                continue;
            }
            match event {
                rnode_kiss::RNodeEvent::DataFrame { index, data } => {
                    let Some(position) = config
                        .subinterfaces
                        .iter()
                        .position(|sub| usize::from(sub.vport) == index)
                    else {
                        continue;
                    };
                    events.push(Event::Frame {
                        interface_id: InterfaceId(config.base_interface_id.0 + position as u64),
                        data: data.into(),
                        rssi: self.last_rssi,
                        snr: self.last_snr,
                    });
                    clear_pending_rx_metadata(&mut self.last_rssi, &mut self.last_snr);
                }
                rnode_kiss::RNodeEvent::Ready => {
                    // Flow control: unlock all subinterfaces that have it.
                    for (fs, sub) in flow_states.iter().zip(&config.subinterfaces) {
                        if sub.flow_control {
                            process_flow_queue(fs, writer, sub.vport, config.multi);
                        }
                    }
                }
                rnode_kiss::RNodeEvent::Error(code) if config.multi => {
                    log::error!("[{}] RNode error: 0x{:02X}", config.name, code);
                }
                _ => {
                    // Status updates logged but not acted on
                }
            }
        }
    }
}
