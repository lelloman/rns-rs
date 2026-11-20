#![allow(
    dead_code,
    reason = "shared with the library; the firmware binary includes this module privately and uses only part of it"
)]

include!(concat!(env!("OUT_DIR"), "/firmware_version.rs"));
