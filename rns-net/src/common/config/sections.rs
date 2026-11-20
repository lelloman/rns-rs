//! The `[stamps]`, filter and `[logging]` sections.

use super::keys::Keys;
use super::*;

/// An infinite timeout means no deadline in practice.
pub(super) fn stamp_timeout_duration(seconds: f64) -> std::time::Duration {
    std::time::Duration::try_from_secs_f64(seconds).unwrap_or(std::time::Duration::MAX)
}

pub(super) fn build_filter_section(
    kvs: &HashMap<String, String>,
) -> Result<FilterSection, ConfigError> {
    let mut section = FilterSection::default();
    Keys(kvs).set_bool("required_only", &mut section.required_only)?;
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

    let keys = Keys(kvs);
    let mut section = StampsSection::default();
    let flag = |key: &str| Ok::<_, ConfigError>(keys.bool(key)?.unwrap_or(false));
    let cost = |key: &str, cap: u8| {
        Ok::<_, ConfigError>(
            keys.with(key, parse_config_float)?
                .map(|n| rns_core::stamp::clamp_cost(n, cap)),
        )
    };
    // `max(0.020, v)`; Python's `max` also keeps 0.020 for NaN.
    let timeout = |key: &str| {
        Ok::<_, ConfigError>(keys.parse::<f64>(key)?.map(|n| {
            if n.is_nan() {
                STAMP_TIMEOUT_MIN
            } else {
                n.max(STAMP_TIMEOUT_MIN)
            }
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
    let integer = |key: &str| keys.parse::<i64>(key);
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
    let keys = Keys(kvs);
    let mut section = LoggingSection::default();
    if let Some(level) = keys.with("loglevel", |v| {
        v.parse::<u8>()
            .ok()
            .filter(|level| *level <= crate::logging::LOG_EXTREME)
    })? {
        section.loglevel = level;
    }
    keys.set_bool("logtimestamps", &mut section.logtimestamps)?;

    Ok(section)
}
