//! TCP interface rate, MTU and flush settings.

#[cfg(feature = "iface-tcp")]
use std::collections::HashMap;
#[cfg(feature = "iface-tcp")]
use std::time::Duration;

/// Hardware MTU tier shared by TCP and Backbone interfaces.
#[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
pub(crate) const fn auto_mtu_for_bitrate(bitrate: u64) -> Option<u32> {
    if bitrate >= 1_000_000_000 {
        Some(524_288)
    } else if bitrate >= 750_000_000 {
        Some(262_144)
    } else if bitrate >= 400_000_000 {
        Some(131_072)
    } else if bitrate >= 200_000_000 {
        Some(65_536)
    } else if bitrate >= 100_000_000 {
        Some(32_768)
    } else if bitrate >= 10_000_000 {
        Some(16_384)
    } else if bitrate >= 5_000_000 {
        Some(8_192)
    } else if bitrate >= 2_000_000 {
        Some(4_096)
    } else if bitrate >= 1_000_000 {
        Some(2_048)
    } else if bitrate >= 62_500 {
        Some(1_024)
    } else {
        None
    }
}

/// Bitrate a TCP interface assumes when `bitrate` is not configured:
/// upstream's `TCPClientInterface` / `TCPServerInterface` `BITRATE_GUESS`.
#[cfg(feature = "iface-tcp")]
pub(crate) const TCP_BITRATE_GUESS: u64 = 10_000_000;

/// Bitrate of a TCP interface: the configured one, else [`TCP_BITRATE_GUESS`].
#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_bitrate(bitrate: Option<u64>) -> u64 {
    bitrate.unwrap_or(TCP_BITRATE_GUESS)
}

/// The optional `bitrate` and `fixed_mtu` keys of a TCP interface, with
/// upstream's meaning: `fixed_mtu` sets the hardware MTU and must be at least
/// the base MTU; `bitrate` is the interface bitrate.
#[cfg(feature = "iface-tcp")]
pub(crate) fn parse_tcp_rate_params(
    params: &HashMap<String, String>,
) -> Result<(Option<u64>, Option<u32>), super::InterfaceConfigError> {
    let bitrate = match params.get("bitrate") {
        Some(value) => Some(value.parse::<u64>().map_err(|_| {
            super::InterfaceConfigError::invalid_value(
                "bitrate",
                format!("invalid bitrate {value:?}"),
            )
        })?),
        None => None,
    };
    let fixed_mtu = match params.get("fixed_mtu") {
        Some(value) => {
            let mtu = value.parse::<u32>().map_err(|_| {
                super::InterfaceConfigError::invalid_value(
                    "fixed_mtu",
                    format!("invalid fixed_mtu {value:?}"),
                )
            })?;
            if (mtu as usize) < rns_core::constants::MTU {
                return Err(super::InterfaceConfigError::invalid_value(
                    "fixed_mtu",
                    format!("Configured MTU of {mtu} bytes is too small"),
                ));
            }
            Some(mtu)
        }
        None => None,
    };
    Ok((bitrate, fixed_mtu))
}

/// How long a TCP interface lets a frame wait in the driver's write buffer
/// when `flush_after_us` is not set: 25 µs in the parallel
/// engine, otherwise until the end of the driver's pass.
#[cfg(feature = "iface-tcp")]
pub(crate) const DEFAULT_FLUSH_AFTER: Option<Duration> = if cfg!(feature = "engine-parallel") {
    Some(Duration::from_micros(25))
} else {
    None
};

/// The optional `flush_after_us` key of a TCP interface (an rns-rs
/// extension): microseconds a frame may wait in the driver's write buffer
/// before it is written, instead of waiting for the end of the driver's pass;
/// `off` waits for the end of the pass whatever the build's default.
#[cfg(feature = "iface-tcp")]
pub(crate) fn parse_flush_after(
    params: &HashMap<String, String>,
) -> Result<Option<Duration>, super::InterfaceConfigError> {
    match params.get("flush_after_us") {
        Some(value) if value.eq_ignore_ascii_case("off") => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .map(|us| Some(Duration::from_micros(us)))
            .map_err(|_| {
                super::InterfaceConfigError::invalid_value(
                    "flush_after_us",
                    format!("invalid flush_after_us {value:?}"),
                )
            }),
        None => Ok(DEFAULT_FLUSH_AFTER),
    }
}

/// Hardware MTU of a TCP interface: `fixed_mtu` when configured, else
/// upstream's autoconfiguration tier for its bitrate ([`tcp_bitrate`]).
/// Below the lowest tier upstream sets no hardware MTU, which leaves links
/// at the base MTU.
#[cfg(feature = "iface-tcp")]
pub(crate) fn tcp_hardware_mtu(bitrate: Option<u64>, fixed_mtu: Option<u32>) -> u32 {
    fixed_mtu.unwrap_or_else(|| {
        auto_mtu_for_bitrate(tcp_bitrate(bitrate)).unwrap_or(rns_core::constants::MTU as u32)
    })
}

#[cfg(all(test, feature = "iface-tcp"))]
mod tests {
    use super::*;
    use crate::interface::{tcp, tcp_server, InterfaceFactory};
    use rns_core::transport::types::InterfaceId;

    #[test]
    #[cfg(feature = "iface-tcp")]
    fn tcp_interfaces_take_upstream_bitrate_and_fixed_mtu_keys() {
        let params = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        for (factory, type_name) in [
            (
                &tcp::TcpClientFactory as &dyn InterfaceFactory,
                "TCPClientInterface",
            ),
            (&tcp_server::TcpServerFactory, "TCPServerInterface"),
        ] {
            assert_eq!(factory.type_name(), type_name);
            let rates = |pairs: &[(&str, &str)]| {
                let config = factory
                    .parse_config("bench", InterfaceId(1), &params(pairs))
                    .map_err(|error| error.to_string())?;
                let any = config.into_any();
                Ok::<_, String>(
                    if let Some(c) = any.downcast_ref::<tcp::TcpClientConfig>() {
                        (c.bitrate, c.fixed_mtu)
                    } else {
                        let c = any.downcast_ref::<tcp_server::TcpServerConfig>().unwrap();
                        (c.bitrate, c.fixed_mtu)
                    },
                )
            };
            assert_eq!(rates(&[]), Ok((None, None)));
            assert_eq!(
                rates(&[("bitrate", "1000000000"), ("fixed_mtu", "500")]),
                Ok((Some(1_000_000_000), Some(500)))
            );
            assert_eq!(
                rates(&[("fixed_mtu", "499")]),
                Err("Configured MTU of 499 bytes is too small".to_string())
            );
            assert!(rates(&[("bitrate", "fast")]).is_err());
        }
    }

    #[test]
    #[cfg(feature = "iface-tcp")]
    fn tcp_interfaces_take_the_flush_after_key() {
        let params = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        for factory in [
            &tcp::TcpClientFactory as &dyn InterfaceFactory,
            &tcp_server::TcpServerFactory,
        ] {
            let flush_after = |pairs: &[(&str, &str)]| {
                let config = factory
                    .parse_config("bench", InterfaceId(1), &params(pairs))
                    .map_err(|error| error.to_string())?;
                let any = config.into_any();
                Ok::<_, String>(
                    if let Some(c) = any.downcast_ref::<tcp::TcpClientConfig>() {
                        c.flush_after
                    } else {
                        any.downcast_ref::<tcp_server::TcpServerConfig>()
                            .unwrap()
                            .flush_after
                    },
                )
            };
            assert_eq!(flush_after(&[]), Ok(DEFAULT_FLUSH_AFTER));
            assert_eq!(flush_after(&[("flush_after_us", "off")]), Ok(None));
            assert_eq!(
                flush_after(&[("flush_after_us", "25")]),
                Ok(Some(Duration::from_micros(25)))
            );
            assert!(flush_after(&[("flush_after_us", "soon")]).is_err());
        }
    }

    #[test]
    #[cfg(feature = "iface-tcp")]
    fn tcp_hardware_mtu_follows_fixed_mtu_then_the_bitrate_tier() {
        // Unconfigured: upstream's 10 Mbps guess and its tier.
        assert_eq!(tcp_bitrate(None), 10_000_000);
        assert_eq!(tcp_hardware_mtu(None, None), 16_384);
        assert_eq!(tcp_hardware_mtu(Some(10_000_000), None), 16_384);
        assert_eq!(tcp_hardware_mtu(Some(1_000_000_000), None), 524_288);
        assert_eq!(tcp_hardware_mtu(Some(1_000_000_000), Some(500)), 500);
        assert_eq!(tcp_hardware_mtu(None, Some(1_200)), 1_200);
        // Below the lowest tier upstream sets no hardware MTU.
        assert_eq!(
            tcp_hardware_mtu(Some(9_600), None),
            rns_core::constants::MTU as u32
        );
    }
}
