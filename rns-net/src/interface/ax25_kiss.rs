//! AX.25 UI framing carried over a KISS TNC.

use std::collections::HashMap;
use std::io;

use rns_core::transport::types::InterfaceId;

use super::kiss_iface::{Ax25Address, KissFactory, KissIfaceConfig};
use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};

const HEADER_LEN: usize = 16;
const CONTROL_UI: u8 = 0x03;
const PID_NO_LAYER_3: u8 = 0xF0;

pub fn validate_address(callsign: &str, ssid: u8) -> Result<Ax25Address, String> {
    if !(3..=6).contains(&callsign.len()) || !callsign.is_ascii() {
        return Err("AX.25 callsign must be 3-6 ASCII characters".into());
    }
    if ssid > 15 {
        return Err("AX.25 SSID must be in 0..15".into());
    }
    Ok(Ax25Address {
        callsign: callsign.to_ascii_uppercase(),
        ssid,
    })
}

fn encode_address(address: &Ax25Address, last: bool) -> [u8; 7] {
    // Preserve Python 1.3.8's 0x20 padding byte (including its non-standard
    // unshifted representation) for exact wire compatibility.
    let mut encoded = [0x20; 7];
    for (output, input) in encoded[..6].iter_mut().zip(address.callsign.bytes()) {
        *output = input.to_ascii_uppercase() << 1;
    }
    encoded[6] = 0x60 | (address.ssid << 1) | u8::from(last);
    encoded
}

pub fn encode_ui_frame(source: &Ax25Address, payload: &[u8]) -> Vec<u8> {
    let destination = Ax25Address {
        callsign: "APZRNS".into(),
        ssid: 0,
    };
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&encode_address(&destination, false));
    frame.extend_from_slice(&encode_address(source, true));
    frame.push(CONTROL_UI);
    frame.push(PID_NO_LAYER_3);
    frame.extend_from_slice(payload);
    frame
}

pub fn decode_ui_frame(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < HEADER_LEN
        || frame[14] != CONTROL_UI
        || frame[15] != PID_NO_LAYER_3
        || frame[6] & 1 != 0
        || frame[13] & 1 == 0
    {
        return None;
    }
    let destination: Vec<u8> = frame[..6].iter().map(|byte| byte >> 1).collect();
    if destination.as_slice() != b"APZRNS" || ((frame[6] >> 1) & 0x0f) != 0 {
        return None;
    }
    Some(&frame[HEADER_LEN..])
}

pub struct Ax25KissFactory;

impl InterfaceFactory for Ax25KissFactory {
    fn type_name(&self) -> &str {
        "AX25KISSInterface"
    }

    fn default_ifac_size(&self) -> usize {
        8
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let base = KissFactory.parse_config(name, id, params)?;
        let mut config = *base
            .into_any()
            .downcast::<KissIfaceConfig>()
            .map_err(|_| "wrong KISS config type".to_string())?;
        let callsign = params
            .get("callsign")
            .or_else(|| params.get("source_callsign"))
            .ok_or_else(|| "AX25KISSInterface requires 'callsign'".to_string())?;
        let ssid = params
            .get("ssid")
            .or_else(|| params.get("source_ssid"))
            .map(|value| value.parse::<u8>())
            .transpose()
            .map_err(|_| "invalid AX.25 SSID".to_string())?
            .unwrap_or(0);
        config.ax25_source = Some(validate_address(callsign, ssid)?);
        config.interface_type_name = self.type_name().into();
        Ok(Box::new(config))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        KissFactory.start(config, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_frame_roundtrip_and_header() {
        let source = validate_address("N0CALL", 7).unwrap();
        let frame = encode_ui_frame(&source, b"rns");
        assert_eq!(&frame[..6], &[0x82, 0xa0, 0xb4, 0xa4, 0x9c, 0xa6]);
        assert_eq!(frame[14..16], [CONTROL_UI, PID_NO_LAYER_3]);
        assert_eq!(decode_ui_frame(&frame), Some(b"rns".as_slice()));
    }

    #[test]
    fn address_validation_matches_upstream_bounds() {
        assert!(validate_address("AB", 0).is_err());
        assert!(validate_address("ABCDEFG", 0).is_err());
        assert!(validate_address("N0CALL", 16).is_err());
        assert!(validate_address("N0CALL", 15).is_ok());
    }
}
