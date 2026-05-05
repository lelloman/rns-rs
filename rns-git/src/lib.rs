pub mod acl;
pub mod client;
pub mod config;
pub mod git;
pub mod logging;
pub mod pages;
pub mod protocol;
pub mod server;
pub mod util;

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
