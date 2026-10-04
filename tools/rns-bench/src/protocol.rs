use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

pub const MAX_CONTROL_BYTES: usize = 16384;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Announce,
    Connect {
        destination: [u8; 16],
        signing_key: [u8; 32],
    },
    Transfer {
        id: u64,
    },
    Snapshot,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Ready {
        version: u32,
        destination: [u8; 16],
        signing_key: [u8; 32],
    },
    Connected,
    Linked,
    Received {
        id: u64,
        bytes: usize,
    },
    Completed {
        id: u64,
        elapsed_ns: u64,
    },
    Snapshot {
        metrics: Metrics,
        received: u64,
        completed: u64,
    },
    Stopped,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub user_cpu_seconds: f64,
    pub system_cpu_seconds: f64,
    pub lifetime_peak_rss_bytes: Option<u64>,
    pub current_rss_bytes: Option<u64>,
}

pub fn metrics() -> Result<Metrics> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // getrusage initializes the structure on success; RUSAGE_SELF includes threads.
    ensure!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0,
        "getrusage failed"
    );
    let usage = unsafe { usage.assume_init() };
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    #[cfg(target_os = "linux")]
    let current = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb * 1024)
        });
    #[cfg(not(target_os = "linux"))]
    let current = None;
    Ok(Metrics {
        user_cpu_seconds: seconds(usage.ru_utime),
        system_cpu_seconds: seconds(usage.ru_stime),
        lifetime_peak_rss_bytes: if cfg!(target_os = "linux") {
            Some(usage.ru_maxrss as u64 * 1024)
        } else {
            None
        },
        current_rss_bytes: current,
    })
}

pub fn write_json<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

pub fn read_line(reader: &mut impl BufRead) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            ensure!(bytes.is_empty(), "truncated control message");
            return Ok(None);
        }
        let n = available
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available.len(), |i| i + 1);
        ensure!(
            bytes.len() + n <= MAX_CONTROL_BYTES,
            "control message exceeds limit"
        );
        bytes.extend_from_slice(&available[..n]);
        reader.consume(n);
        if bytes.last() == Some(&b'\n') {
            return Ok(Some(String::from_utf8(bytes)?));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_and_complete_control_records() {
        assert!(read_line(&mut &b"{}"[..]).is_err());
        assert!(read_line(&mut &vec![b'x'; MAX_CONTROL_BYTES + 1][..]).is_err());
        assert_eq!(read_line(&mut &b"{}\n"[..]).unwrap(), Some("{}\n".into()));
    }
}
