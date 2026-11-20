//! Reading and checking runtime config values.

use super::*;

impl Driver {
    pub(crate) fn expect_u64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<u64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as u64),
            RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    /// A discovery stamp cost, fractional since upstream 796ef2d4 and at most
    /// `STAMP_COST_CAP`.
    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(crate) fn expect_discovery_stamp_value(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<rns_core::stamp::StampCost, RuntimeConfigError> {
        let cap = rns_core::constants::STAMP_COST_CAP;
        let raw = Self::expect_f64(value, key)?;
        if raw > f64::from(cap) {
            return Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be <= {}", key, cap),
            });
        }
        Ok(rns_core::stamp::StampCost::from_f64(raw))
    }

    pub(crate) fn expect_f64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<f64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Float(v) if v.is_finite() && v >= 0.0 => Ok(v),
            RuntimeConfigValue::Int(v) if v >= 0 => Ok(v as f64),
            RuntimeConfigValue::Float(_) | RuntimeConfigValue::Int(_) => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} must be a finite number >= 0", key),
            }),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value", key),
            }),
        }
    }

    /// Convert a number of seconds into a `Duration`, rejecting values that
    /// cannot be represented or that would overflow when added to `Instant::now()`.
    #[cfg(any(
        feature = "iface-tcp",
        feature = "iface-auto",
        feature = "iface-pipe",
        feature = "iface-backbone",
        feature = "iface-i2p"
    ))]
    pub(crate) fn duration_from_secs(secs: f64, key: &str) -> Result<Duration, RuntimeConfigError> {
        Duration::try_from_secs_f64(secs)
            .ok()
            .filter(|duration| std::time::Instant::now().checked_add(*duration).is_some())
            .ok_or_else(|| RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidValue,
                message: format!("{} is out of range for a duration", key),
            })
    }

    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(crate) fn expect_duration_secs(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Duration, RuntimeConfigError> {
        Self::duration_from_secs(Self::expect_f64(value, key)?, key)
    }

    pub(crate) fn expect_i64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<i64, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Int(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects an integer", key),
            }),
        }
    }

    pub(crate) fn expect_bool(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<bool, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Bool(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a boolean", key),
            }),
        }
    }

    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(crate) fn expect_string(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<String, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::String(v) => Ok(v),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string", key),
            }),
        }
    }

    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(crate) fn expect_optional_f64(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<f64>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::Float(v) => Ok(Some(v)),
            RuntimeConfigValue::Int(v) => Ok(Some(v as f64)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a numeric value or null", key),
            }),
        }
    }

    #[cfg(any(
        feature = "iface-tcp",
        feature = "iface-udp",
        feature = "iface-backbone"
    ))]
    pub(crate) fn expect_optional_string(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<String>, RuntimeConfigError> {
        match value {
            RuntimeConfigValue::Null => Ok(None),
            RuntimeConfigValue::String(v) => Ok(Some(v)),
            _ => Err(RuntimeConfigError {
                code: RuntimeConfigErrorCode::InvalidType,
                message: format!("{} expects a string or null", key),
            }),
        }
    }

    #[cfg(feature = "iface-backbone")]
    #[cfg(feature = "iface-backbone")]
    pub(crate) fn set_optional_duration(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<Duration>, RuntimeConfigError> {
        let secs = Self::expect_f64(value, key)?;
        if secs == 0.0 {
            Ok(None)
        } else {
            Ok(Some(Self::duration_from_secs(secs, key)?))
        }
    }

    #[cfg(any(feature = "iface-tcp", feature = "iface-backbone"))]
    pub(crate) fn set_optional_usize(
        value: RuntimeConfigValue,
        key: &str,
    ) -> Result<Option<usize>, RuntimeConfigError> {
        let raw = Self::expect_u64(value, key)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(raw as usize))
        }
    }
}
