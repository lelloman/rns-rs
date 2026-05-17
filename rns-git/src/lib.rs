pub mod acl;
pub mod client;
pub mod clone_cli;
pub mod config;
pub mod create_cli;
pub mod git;
mod highlight;
pub mod logging;
pub mod pages;
pub mod protocol;
pub mod release;
pub mod release_cli;
pub mod server;
mod stats;
pub mod sync_cli;
pub mod util;
pub mod work;
pub mod work_cli;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Msg(String),
}

impl Error {
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
