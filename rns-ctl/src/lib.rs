//! `rns-ctl`: an HTTP/WebSocket control plane and command-line tool for a
//! Reticulum node.
//!
//! The `rns-ctl` binary is a thin dispatcher over [`cmd`]. `rns-server`
//! embeds the HTTP control plane through [`cmd::http::prepare_embedded_with_state`]
//! and [`server::run_server_with_listener`], and reports its supervised
//! processes and configuration through [`state`].

/// Request routing and handlers: the JSON `/api/...` endpoints, the web UI
/// shell and the health check.
pub mod api;
pub mod args;
/// Bearer-token checks for HTTP requests and WebSocket upgrades.
pub mod auth;
/// Bridge from the node's event callbacks into [`state`] and WebSocket
/// subscribers.
pub mod bridge;
pub mod cli;
/// The `rns-ctl` subcommands.
pub mod cmd;
/// Settings of the HTTP control plane, from the command line and environment.
pub mod config;
/// Hex and base64 encoding helpers for API payloads.
pub mod encode;
pub mod format;
pub mod hook_path;
/// Minimal HTTP/1.1 request parsing and response writing, with size limits.
pub mod http;
pub mod remote;
/// The HTTP/WebSocket server: accept loop, per-connection handling and
/// connection limits.
pub mod server;
/// SHA-1, used only to answer WebSocket handshakes.
pub mod sha1;
/// State shared by the API handlers, the node callbacks and the supervisor.
pub mod state;
mod stats_api;
/// TLS server configuration from PEM files.
#[cfg(feature = "tls")]
pub mod tls;
/// WebSocket handshake, framing and the event push loop.
pub mod ws;
