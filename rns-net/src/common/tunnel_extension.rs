//! The extension of a tunnel synthesis (upstream b7a93b9b).
//!
//! Since Reticulum 1.6.1 a synthesis carries, after its signature and
//! covered by it, a msgpack map describing the sending transport node:
//! its implementation and version, whether it has transport enabled, and
//! the destination and path request stamp costs of the interface it
//! synthesized on. The keys are the interface discovery field ids. A node
//! that receives one and has not synthesized on that interface answers with
//! a synthesis of its own, so both ends learn about each other.

use rns_core::msgpack::{self, Value};
use rns_core::stamp::StampCost;
use rns_core::transport::tunnel::RemoteTransportInfo;

use super::discovery::{
    sanitize_discovered_name, DST_COST, PR_COST, TRANSPORT, TRANSPORT_IMPL,
    TRANSPORT_IMPLEMENTATION_NAME, TRANSPORT_IMPLEMENTATION_VERSION, TRANSPORT_VERS,
};

/// This node's extension: upstream's `ext_info`, in its key order, with
/// rns-rs's implementation name and version as interface discovery
/// announces them.
pub fn encode(transport_enabled: bool, destination_cost: StampCost, pr_cost: StampCost) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![
        (
            Value::UInt(u64::from(TRANSPORT_IMPL)),
            Value::Str(TRANSPORT_IMPLEMENTATION_NAME.into()),
        ),
        (
            Value::UInt(u64::from(TRANSPORT_VERS)),
            Value::Str(TRANSPORT_IMPLEMENTATION_VERSION.into()),
        ),
        (
            Value::UInt(u64::from(TRANSPORT)),
            Value::Bool(transport_enabled),
        ),
        (
            Value::UInt(u64::from(DST_COST)),
            Value::Float(destination_cost.as_f64()),
        ),
        (
            Value::UInt(u64::from(PR_COST)),
            Value::Float(pr_cost.as_f64()),
        ),
    ]))
}

/// Read a received extension as upstream's `tunnel_synthesize_handler`
/// does. The error is upstream's protocol violation text.
///
/// The map must hold all five fields. The implementation name must be a
/// string that is already in its sanitized form, the version a string
/// that `version_tuple` can read, the costs floats and the transport status
/// a boolean. The costs are quantized to the cost grid. A non-finite cost,
/// which makes upstream's quantization raise, is the parsing exception
/// upstream reports.
pub fn decode(extension: &[u8]) -> Result<RemoteTransportInfo, &'static str> {
    let Ok(value) = msgpack::unpack_exact(extension) else {
        return Err("Undecodable ext_payload in tunnel synthesis packet");
    };
    let Value::Map(entries) = value else {
        return Err("Invalid ext_payload data type in tunnel synthesis packet");
    };
    let field = |key: u8| {
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::UInt(k) if *k == u64::from(key)))
            .map(|(_, v)| v)
    };
    let required = [
        (
            TRANSPORT_IMPL,
            "Missing implementation info in tunnel synthesis packet",
        ),
        (
            TRANSPORT_VERS,
            "Missing version info in tunnel synthesis packet",
        ),
        (
            TRANSPORT,
            "Missing transport status in tunnel synthesis packet",
        ),
        (
            DST_COST,
            "Missing destination cost in tunnel synthesis packet",
        ),
        (
            PR_COST,
            "Missing path request cost in tunnel synthesis packet",
        ),
    ];
    for (key, missing) in required {
        if field(key).is_none() {
            return Err(missing);
        }
    }
    let parsing_exception = "Tunnel synthesis parsing caused exception";
    // `sanitize_name` raises on anything but a string or a falsy value.
    let implementation = match field(TRANSPORT_IMPL) {
        Some(Value::Str(name)) => Some(name.as_str()),
        Some(Value::Nil) | Some(Value::Bool(false)) => None,
        _ => return Err(parsing_exception),
    };
    let version = match field(TRANSPORT_VERS) {
        Some(Value::Str(version)) => super::discovery::parse_version_tuple(version),
        _ => None,
    };
    let Some(version) = version else {
        return Err("Invalid version info in tunnel synthesis packet");
    };
    let implementation = implementation
        .filter(|name| sanitize_discovered_name(name).as_deref() == Some(*name))
        .ok_or("Invalid implementation info in tunnel synthesis packet")?;
    let Some(Value::Float(destination_cost)) = field(DST_COST) else {
        return Err("Invalid destination cost in tunnel synthesis packet");
    };
    let Some(Value::Float(pr_cost)) = field(PR_COST) else {
        return Err("Invalid path request cost in tunnel synthesis packet");
    };
    let Some(Value::Bool(is_transport)) = field(TRANSPORT) else {
        return Err("Invalid transport status in tunnel synthesis packet");
    };
    if !destination_cost.is_finite() || !pr_cost.is_finite() {
        return Err(parsing_exception);
    }
    Ok(RemoteTransportInfo {
        implementation: implementation.to_string(),
        version,
        is_transport: *is_transport,
        destination_cost: StampCost::from_f64(*destination_cost),
        pr_cost: StampCost::from_f64(*pr_cost),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(fields: Vec<(u8, Value)>) -> Vec<u8> {
        msgpack::pack(&Value::Map(
            fields
                .into_iter()
                .map(|(k, v)| (Value::UInt(u64::from(k)), v))
                .collect(),
        ))
    }

    fn upstream_fields() -> Vec<(u8, Value)> {
        vec![
            (TRANSPORT_IMPL, Value::Str("RNS".into())),
            (TRANSPORT_VERS, Value::Str("1.6.1".into())),
            (TRANSPORT, Value::Bool(true)),
            (DST_COST, Value::Float(23.5)),
            (PR_COST, Value::Float(15.8)),
        ]
    }

    #[test]
    fn own_extension_decodes_to_what_was_sent() {
        let encoded = encode(true, StampCost::from_f64(23.5), StampCost::from_f64(15.8));
        let info = decode(&encoded).unwrap();
        assert_eq!(info.implementation, TRANSPORT_IMPLEMENTATION_NAME);
        assert!(!info.version.is_empty());
        assert!(info.is_transport);
        assert_eq!(info.destination_cost, StampCost::from_f64(23.5));
        assert_eq!(info.pr_cost, StampCost::from_f64(15.8));
    }

    #[test]
    fn upstream_extension_is_read_and_quantized() {
        let info = decode(&map(upstream_fields())).unwrap();
        assert_eq!(info.implementation, "RNS");
        assert_eq!(info.version, vec![1, 6, 1]);
        assert!(info.is_transport);
        // 15.8 is not on the 1/256 cost grid; upstream quantizes it.
        assert_eq!(info.pr_cost, StampCost::from_f64(15.8));
        assert_eq!(info.pr_cost.as_f64(), 4045.0 / 256.0);
    }

    #[test]
    fn invalid_extensions_are_protocol_violations() {
        assert_eq!(
            decode(b"\xc1").unwrap_err(),
            "Undecodable ext_payload in tunnel synthesis packet"
        );
        assert_eq!(
            decode(&msgpack::pack(&Value::Array(vec![]))).unwrap_err(),
            "Invalid ext_payload data type in tunnel synthesis packet"
        );
        let without = |key: u8| {
            let fields: Vec<_> = upstream_fields()
                .into_iter()
                .filter(|(k, _)| *k != key)
                .collect();
            decode(&map(fields)).unwrap_err()
        };
        assert_eq!(
            without(TRANSPORT_IMPL),
            "Missing implementation info in tunnel synthesis packet"
        );
        assert_eq!(
            without(PR_COST),
            "Missing path request cost in tunnel synthesis packet"
        );
        let with = |key: u8, value: Value| {
            let fields: Vec<_> = upstream_fields()
                .into_iter()
                .map(|(k, v)| if k == key { (k, value.clone()) } else { (k, v) })
                .collect();
            decode(&map(fields))
        };
        assert_eq!(
            with(TRANSPORT_VERS, Value::Str("unknown".into())).unwrap_err(),
            "Invalid version info in tunnel synthesis packet"
        );
        assert_eq!(
            with(TRANSPORT_IMPL, Value::Str(" RNS".into())).unwrap_err(),
            "Invalid implementation info in tunnel synthesis packet"
        );
        assert_eq!(
            with(TRANSPORT_IMPL, Value::UInt(7)).unwrap_err(),
            "Tunnel synthesis parsing caused exception"
        );
        assert_eq!(
            with(DST_COST, Value::UInt(23)).unwrap_err(),
            "Invalid destination cost in tunnel synthesis packet"
        );
        assert_eq!(
            with(TRANSPORT, Value::UInt(1)).unwrap_err(),
            "Invalid transport status in tunnel synthesis packet"
        );
        assert_eq!(
            with(PR_COST, Value::Float(f64::NAN)).unwrap_err(),
            "Tunnel synthesis parsing caused exception"
        );
        // A version with a suffix reads as far as it is numeric.
        assert_eq!(
            with(TRANSPORT_VERS, Value::Str("1.6.1rc2".into()))
                .unwrap()
                .version,
            vec![1, 6, 1]
        );
    }
}
