//! Logging targets shared by protocol and runtime crates.

/// Target for path discovery, selection, forwarding and tunnel restoration.
///
/// Pathing records use `Trace` so a logger can expose them independently from
/// ordinary `Debug` records at Reticulum's numeric log level 7.
pub const PATHING_LOG_TARGET: &str = "rns::pathing";
