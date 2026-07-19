use std::fs::{self, OpenOptions};
use std::path::Path;

use crate::{Error, Result};

pub const DEFAULT_LOG_LEVEL: u8 = 4;

pub fn init_file_logger(path: &Path, log_level: u8) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let filter = rns_net::logging::numeric_log_filter(log_level);
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(filter.default)
        .filter_module(rns_net::logging::PATHING_LOG_TARGET, filter.pathing)
        .format_timestamp_secs()
        .target(env_logger::Target::Pipe(Box::new(file)));
    builder
        .try_init()
        .map_err(|err| Error::msg(format!("failed to initialize logging: {err}")))
}

pub fn level_filter(log_level: u8) -> log::LevelFilter {
    rns_net::logging::numeric_log_filter(log_level).default
}

pub fn pathing_level_filter(log_level: u8) -> log::LevelFilter {
    rns_net::logging::numeric_log_filter(log_level).pathing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_rngit_log_levels_to_rust_filters() {
        assert_eq!(level_filter(0), log::LevelFilter::Error);
        assert_eq!(level_filter(2), log::LevelFilter::Warn);
        assert_eq!(level_filter(4), log::LevelFilter::Info);
        assert_eq!(level_filter(6), log::LevelFilter::Debug);
        assert_eq!(level_filter(7), log::LevelFilter::Debug);
        assert_eq!(level_filter(8), log::LevelFilter::Trace);
        assert_eq!(level_filter(u8::MAX), log::LevelFilter::Trace);
    }

    #[test]
    fn pathing_filter_is_distinct_at_level_seven() {
        assert_eq!(pathing_level_filter(6), log::LevelFilter::Debug);
        assert_eq!(pathing_level_filter(7), log::LevelFilter::Trace);
        assert_eq!(pathing_level_filter(8), log::LevelFilter::Trace);
    }
}
