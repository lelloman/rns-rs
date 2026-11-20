//! Git hosting over Reticulum.
//!
//! The library behind the `rngit` server, the `git-remote-rns` remote helper
//! that gives git `rns://<destination>/<group>/<repo>` URLs, and the `rngcs`
//! commit signer. A server hosts bare repositories behind a Reticulum
//! destination, enforces per-identity access rules, and can also keep
//! releases and work documents beside each repository and serve them as
//! Nomad Network pages. Each command's entry point is a `main` function taking
//! its arguments.

#![warn(missing_docs)]

/// Access control: who may read, write, create, release and administer repositories.
pub mod acl;
/// The `git-remote-rns` remote helper that lets git fetch from and push to `rns://` URLs.
pub mod client;
/// The `rngit fork` and `rngit mirror` commands.
pub mod clone_cli;
/// The `rngcs` signing program git calls for SSH-format commit and tag signatures made with Reticulum identities.
pub mod commitsigs;
/// Server configuration, read from the `server_config` file in the rngit directory.
pub mod config;
/// The `rngit create` command.
pub mod create_cli;
/// Operations on bare repositories, run through the `git` executable.
pub mod git;
mod highlight;
/// File logging for the server and the client tools.
pub mod logging;
/// Image conversion to WebP for media served on Nomad Network pages.
pub mod media;
/// Nomad Network pages and file downloads for browsing the hosted repositories.
pub mod pages;
/// The `rngit perms` command.
pub mod perms_cli;
/// Request paths, result codes and msgpack request encoding of the repository protocol.
pub mod protocol;
/// Release storage kept beside each repository.
pub mod release;
/// The `rngit release` command.
pub mod release_cli;
/// The `rngit` server: destinations, request handlers and the announce loop.
pub mod server;
mod stats;
/// The `rngit sync` command.
pub mod sync_cli;
/// Small helpers shared by the server and the client tools.
pub mod util;
/// Work documents (issues, notes, proposals) kept beside each repository.
pub mod work;
/// The `rngit work` command.
pub mod work_cli;

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type of this crate.
#[derive(Debug)]
pub enum Error {
    /// A filesystem, process or socket operation failed.
    Io(std::io::Error),
    /// Any other failure, described by the message. Command-line `--help` also
    /// returns the usage text this way.
    Msg(String),
}

impl Error {
    /// Builds an [`Error::Msg`].
    pub fn msg(message: impl Into<String>) -> Self {
        Error::Msg(message.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "{err}"),
            Error::Msg(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for Error {}
