//! Answering queries about the driver, and changing it on request.

mod bookkeeping;
mod interface_stats;
mod listeners;
mod mutate;
mod naming;
mod read;

use super::*;

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
