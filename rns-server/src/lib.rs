//! Library behind the `rns-server` binary: a supervisor that runs `rnsd` and,
//! in hook-enabled builds, the `rns-sentineld` and `rns-statsd` sidecars as
//! child processes, with an embedded HTTP control plane from `rns-ctl`.

#![warn(missing_docs)]

/// Command-line parsing for `rns-server`.
pub mod args;
/// Server configuration: command-line flags merged with `rns-server.json`.
pub mod config;
/// Wiring between the supervisor and the `rns-ctl` shared state.
pub mod control_plane;
/// Per-process log files with size-based rotation.
pub mod logs;
mod self_exec;
/// Child process supervision: spawning, readiness probes, restarts and
/// shutdown.
pub mod supervisor;
