//! The `[stamps]`, filter and `[logging]` sections.

use super::*;

/// An infinite timeout means no deadline in practice.
pub(super) fn stamp_timeout_duration(seconds: f64) -> std::time::Duration {
    std::time::Duration::try_from_secs_f64(seconds).unwrap_or(std::time::Duration::MAX)
}

pub(super) fn build_filter_section(
    kvs: &HashMap<String, String>,
) -> Result<FilterSection, ConfigError> {
    let mut section = FilterSection::default();
    if let Some(v) = kvs.get("required_only") {
        section.required_only = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "required_only".into(),
            value: v.clone(),
        })?;
    }
    let list = |key: &str| -> Vec<String> {
        kvs.get(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    section.ignored_types = list("ignored_types");
    section.allowed_types = list("allowed_types");
    Ok(section)
}

pub(super) fn build_stamps_section(
    kvs: &HashMap<String, String>,
) -> Result<StampsSection, ConfigError> {
    use rns_core::constants::{LINK_COST_CAP, STAMP_COST_CAP, STAMP_TIMEOUT_MIN};

    let mut section = StampsSection::default();
    let flag = |key: &str| -> Result<bool, ConfigError> {
        match kvs.get(key) {
            None => Ok(false),
            Some(v) => parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
                key: key.into(),
                value: v.clone(),
            }),
        }
    };
    let cost = |key: &str, cap: u8| -> Result<Option<StampCost>, ConfigError> {
        let Some(v) = kvs.get(key) else {
            return Ok(None);
        };
        let n = parse_config_float(v).ok_or_else(|| ConfigError::InvalidValue {
            key: key.into(),
            value: v.clone(),
        })?;
        Ok(Some(rns_core::stamp::clamp_cost(n, cap)))
    };
    let timeout = |key: &str| -> Result<Option<f64>, ConfigError> {
        let Some(v) = kvs.get(key) else {
            return Ok(None);
        };
        let n = v
            .trim()
            .parse::<f64>()
            .map_err(|_| ConfigError::InvalidValue {
                key: key.into(),
                value: v.clone(),
            })?;
        // `max(0.020, v)`; Python's `max` also keeps 0.020 for NaN.
        Ok(Some(if n.is_nan() {
            STAMP_TIMEOUT_MIN
        } else {
            n.max(STAMP_TIMEOUT_MIN)
        }))
    };

    // Enable-only booleans (Reticulum.py: `if value == True: ... = True`).
    if flag("enforce_stamps")? {
        section.stamps_enforced = true;
        section.lr_stamps_enforced = true;
    }
    if flag("stamp_destinations")? {
        section.stamp_destinations = true;
    }
    if flag("stamp_prs")? {
        section.stamp_prs = true;
    }
    // a8cc6cb2 replaced `stamp_lrs` with `always_stamp_lrs`; like other
    // unknown options, a leftover `stamp_lrs` is ignored.
    if flag("always_stamp_lrs")? {
        section.always_stamp_lrs = true;
    }
    if let Some(v) = cost("destination_cost", STAMP_COST_CAP)? {
        section.destination_cost = v;
    }
    if let Some(v) = cost("destination_value", STAMP_COST_CAP)? {
        section.destination_value = v;
    }
    if let Some(v) = cost("pr_cost", STAMP_COST_CAP)? {
        section.pr_cost = v;
    }
    if let Some(v) = cost("pr_value", STAMP_COST_CAP)? {
        section.pr_value = v;
    }
    if let Some(v) = cost("lr_cost", LINK_COST_CAP)? {
        section.lr_cost = v;
    }
    if let Some(v) = timeout("lr_stamp_timeout")? {
        section.lr_stamp_timeout = v;
    }
    if let Some(v) = timeout("pr_stamp_timeout")? {
        section.pr_stamp_timeout = v;
    }
    // Read with `as_int` (upstream 16621a78).
    let integer = |key: &str| -> Result<Option<i64>, ConfigError> {
        kvs.get(key)
            .map(|v| {
                v.trim()
                    .parse::<i64>()
                    .map_err(|_| ConfigError::InvalidValue {
                        key: key.into(),
                        value: v.clone(),
                    })
            })
            .transpose()
    };
    if let Some(v) = integer("max_workers")? {
        section.max_workers = Some(v.max(1) as usize);
    }
    if let Some(v) = integer("worker_niceness")? {
        section.worker_niceness = v.clamp(0, 20) as i32;
    }
    Ok(section)
}

pub(super) fn build_logging_section(
    kvs: &HashMap<String, String>,
) -> Result<LoggingSection, ConfigError> {
    let mut section = LoggingSection::default();

    if let Some(v) = kvs.get("loglevel") {
        section.loglevel = v.parse::<u8>().map_err(|_| ConfigError::InvalidValue {
            key: "loglevel".into(),
            value: v.clone(),
        })?;
        if section.loglevel > crate::logging::LOG_EXTREME {
            return Err(ConfigError::InvalidValue {
                key: "loglevel".into(),
                value: v.clone(),
            });
        }
    }
    if let Some(v) = kvs.get("logtimestamps") {
        section.logtimestamps = parse_bool(v).ok_or_else(|| ConfigError::InvalidValue {
            key: "logtimestamps".into(),
            value: v.clone(),
        })?;
    }

    Ok(section)
}
