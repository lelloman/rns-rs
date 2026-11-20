//! The `rns-ctl` subcommands. Each `run` takes the subcommand's parsed
//! arguments, prints its output and may end the process (argument errors exit
//! with status 2, runtime errors with 1).

/// `rns-ctl backbone`: backbone peer state, blacklist and provider info.
pub mod backbone;
/// `rns-ctl config`: runtime configuration of a running node.
pub mod config;
/// `rns-ctl daemon`: run the node daemon, as `rnsd`.
pub mod daemon;
pub mod hook;
pub mod http;
/// `rns-ctl id`: identity management, as `rnid`.
pub mod id;
/// `rns-ctl path`: path table display and management, as `rnpath`.
pub mod path;
/// `rns-ctl probe`: path reachability probes, as `rnprobe`.
pub mod probe;
/// `rns-ctl status`: interface status, as `rnstatus`.
pub mod status;
