//! Shared utilities for RNS CLI tools.

#![warn(missing_docs)]

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
pub mod rnid;
pub mod rnpath;
pub mod rnprobe;
pub mod rnsd;
pub mod rnsh;
pub mod rnstatus;
pub mod rnstatus_view;
pub mod rnx;
#[cfg(feature = "sidecars")]
pub mod sentineld;
pub mod shared_instance;
#[cfg(feature = "sidecars")]
pub mod statsd;
pub mod stdout;
pub(crate) mod sys;
pub mod upstream_parsers;
