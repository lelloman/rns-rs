//! Reticulum-compatible numeric logging levels and target filters.

pub use rns_core::logging::PATHING_LOG_TARGET;

pub const LOG_CRITICAL: u8 = 0;
pub const LOG_ERROR: u8 = 1;
pub const LOG_WARNING: u8 = 2;
pub const LOG_NOTICE: u8 = 3;
pub const LOG_INFO: u8 = 4;
pub const LOG_VERBOSE: u8 = 5;
pub const LOG_DEBUG: u8 = 6;
pub const LOG_PATHING: u8 = 7;
pub const LOG_EXTREME: u8 = 8;

/// Runtime level for authenticated link path rebalancing events.
pub const REBALANCE_LOG_LEVEL: log::Level = log::Level::Trace;

/// The two filters needed to represent Reticulum's pathing level with Rust's
/// five-level `log` facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogFilter {
    /// Filter applied to every ordinary logging target.
    pub default: log::LevelFilter,
    /// Filter applied specifically to [`PATHING_LOG_TARGET`].
    pub pathing: log::LevelFilter,
}

/// Translate a Reticulum numeric level into default and pathing filters.
///
/// Values above the supported range are clamped defensively. Configuration
/// parsing rejects them, but callers can also supply levels programmatically.
pub fn numeric_log_filter(log_level: u8) -> LogFilter {
    let log_level = log_level.min(LOG_EXTREME);
    let default = match log_level {
        LOG_CRITICAL | LOG_ERROR => log::LevelFilter::Error,
        LOG_WARNING => log::LevelFilter::Warn,
        LOG_NOTICE | LOG_INFO => log::LevelFilter::Info,
        LOG_VERBOSE | LOG_DEBUG | LOG_PATHING => log::LevelFilter::Debug,
        LOG_EXTREME => log::LevelFilter::Trace,
        _ => unreachable!("numeric log level was clamped"),
    };
    let pathing = if log_level >= LOG_PATHING {
        log::LevelFilter::Trace
    } else {
        default
    };

    LogFilter { default, pathing }
}

/// Apply foreground CLI verbosity and quietness to a configured numeric level.
pub fn adjust_log_level(configured: u8, verbosity: u8, quietness: u8) -> u8 {
    i32::from(configured)
        .saturating_add(i32::from(verbosity))
        .saturating_sub(i32::from(quietness))
        .clamp(i32::from(LOG_CRITICAL), i32::from(LOG_EXTREME)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;

    fn test_logger(filter: LogFilter) -> env_logger::Logger {
        let mut builder = env_logger::Builder::new();
        builder
            .filter_level(filter.default)
            .filter_module(PATHING_LOG_TARGET, filter.pathing);
        builder.build()
    }

    #[test]
    fn numeric_levels_preserve_reticulum_severity_bands() {
        let expected = [
            log::LevelFilter::Error,
            log::LevelFilter::Error,
            log::LevelFilter::Warn,
            log::LevelFilter::Info,
            log::LevelFilter::Info,
            log::LevelFilter::Debug,
            log::LevelFilter::Debug,
            log::LevelFilter::Debug,
            log::LevelFilter::Trace,
        ];

        for (level, default) in expected.into_iter().enumerate() {
            let filter = numeric_log_filter(level as u8);
            assert_eq!(filter.default, default, "numeric level {level}");
        }
    }

    #[test]
    fn pathing_is_hidden_at_debug_and_enabled_at_pathing() {
        let debug = numeric_log_filter(LOG_DEBUG);
        assert_eq!(debug.default, log::LevelFilter::Debug);
        assert_eq!(debug.pathing, log::LevelFilter::Debug);

        let pathing = numeric_log_filter(LOG_PATHING);
        assert_eq!(pathing.default, log::LevelFilter::Debug);
        assert_eq!(pathing.pathing, log::LevelFilter::Trace);
    }

    #[test]
    fn extreme_enables_all_trace_targets() {
        let filter = numeric_log_filter(LOG_EXTREME);
        assert_eq!(filter.default, log::LevelFilter::Trace);
        assert_eq!(filter.pathing, log::LevelFilter::Trace);
    }

    #[test]
    fn level_seven_env_filter_enables_only_pathing_trace() {
        let logger = test_logger(numeric_log_filter(LOG_PATHING));
        let pathing = log::Metadata::builder()
            .level(log::Level::Trace)
            .target(PATHING_LOG_TARGET)
            .build();
        let ordinary_trace = log::Metadata::builder()
            .level(log::Level::Trace)
            .target("rns_net::driver")
            .build();
        let ordinary_debug = log::Metadata::builder()
            .level(log::Level::Debug)
            .target("rns_net::driver")
            .build();

        assert!(logger.enabled(&pathing));
        assert!(!logger.enabled(&ordinary_trace));
        assert!(logger.enabled(&ordinary_debug));
    }

    #[test]
    fn level_six_hides_pathing_trace_and_level_eight_enables_all_trace() {
        let pathing = log::Metadata::builder()
            .level(log::Level::Trace)
            .target(PATHING_LOG_TARGET)
            .build();
        let ordinary_trace = log::Metadata::builder()
            .level(log::Level::Trace)
            .target("rns_core::resource")
            .build();

        let debug = test_logger(numeric_log_filter(LOG_DEBUG));
        assert!(!debug.enabled(&pathing));
        assert!(!debug.enabled(&ordinary_trace));

        let extreme = test_logger(numeric_log_filter(LOG_EXTREME));
        assert!(extreme.enabled(&pathing));
        assert!(extreme.enabled(&ordinary_trace));
    }

    #[test]
    fn link_path_rebalancing_uses_pathing_level() {
        assert_eq!(REBALANCE_LOG_LEVEL, log::Level::Trace);
        let metadata = log::Metadata::builder()
            .level(REBALANCE_LOG_LEVEL)
            .target(PATHING_LOG_TARGET)
            .build();

        let debug = test_logger(numeric_log_filter(LOG_DEBUG));
        assert!(!debug.enabled(&metadata));

        let pathing = test_logger(numeric_log_filter(LOG_PATHING));
        assert!(pathing.enabled(&metadata));
    }

    #[test]
    fn out_of_range_numeric_levels_are_safely_clamped() {
        assert_eq!(numeric_log_filter(u8::MAX), numeric_log_filter(LOG_EXTREME));
    }

    #[test]
    fn cli_adjustment_is_signed_and_clamped_to_supported_range() {
        assert_eq!(adjust_log_level(4, 2, 0), 6);
        assert_eq!(adjust_log_level(4, 0, 2), 2);
        assert_eq!(adjust_log_level(4, 3, 1), 6);
        assert_eq!(adjust_log_level(7, 2, 0), LOG_EXTREME);
        assert_eq!(adjust_log_level(1, 0, 2), LOG_CRITICAL);
        assert_eq!(adjust_log_level(4, u8::MAX, 0), LOG_EXTREME);
        assert_eq!(adjust_log_level(4, 0, u8::MAX), LOG_CRITICAL);
    }
}
