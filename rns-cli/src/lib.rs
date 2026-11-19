//! Shared utilities for RNS CLI tools.

extern crate self as rns_cli;

pub mod app;
pub mod argparse;
pub mod args;
pub mod configobj;
pub mod format;
pub mod native_cli;
pub mod placeholder;
pub mod pyfmt;
pub mod pylog;
pub mod readiness;
pub mod remote;
pub mod rncp;
#[path = "bin/rnid/main.rs"]
pub mod rnid_command;
#[path = "bin/rnpath.rs"]
pub mod rnpath_command;
#[path = "bin/rnprobe.rs"]
pub mod rnprobe_command;
pub mod rnsd;
pub mod rnsh;
#[path = "bin/rnstatus.rs"]
pub mod rnstatus_command;
pub mod rnstatus_view;
pub mod rnx;
#[cfg(feature = "sidecars")]
pub mod sentineld;
#[cfg(feature = "sidecars")]
pub mod statsd;
pub mod stdout;
pub mod upstream_parsers;
