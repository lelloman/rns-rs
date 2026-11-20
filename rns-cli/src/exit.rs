//! Ending a tool with an exit status.
//!
//! A tool returns its status up to `main` instead of calling
//! `std::process::exit` where it decides to stop, so what it holds (a
//! shared instance client, an RPC connection) is dropped and shut down as
//! on a normal return.

use std::process::ExitCode;

/// Stop the tool with this exit status, as upstream's `sys.exit(code)`.
/// Status 0 stops it successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit(pub i32);

/// What a tool's run gives: done, or stopped with an [`Exit`] status.
pub type Status = Result<(), Exit>;

impl Exit {
    /// Status 1, the tools' general failure.
    pub const FAILURE: Exit = Exit(1);
}

impl From<Exit> for ExitCode {
    /// The status as the process exits with it: like `exit(2)`, only its
    /// low eight bits.
    fn from(exit: Exit) -> ExitCode {
        ExitCode::from(exit.0.to_le_bytes()[0])
    }
}

/// The process exit code for a tool's run.
pub fn exit_code(status: Status) -> ExitCode {
    match status {
        Ok(()) => ExitCode::SUCCESS,
        Err(exit) => exit.into(),
    }
}

/// The process exit code for a status a tool computed as a number.
pub fn code(status: i32) -> ExitCode {
    Exit(status).into()
}
