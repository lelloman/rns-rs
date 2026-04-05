//! Pipe interface: subprocess stdin/stdout with HDLC framing.
//!
//! Matches Python `PipeInterface.py`. Spawns a subprocess, communicates
//! via piped stdin/stdout using HDLC framing for packet boundaries.
//! Auto-respawns subprocess on failure.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rns_core::transport::types::{InterfaceId, InterfaceInfo};

use super::{InterfaceConfigData, InterfaceFactory, StartContext, StartResult};
use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;

/// Configuration for a pipe interface.
#[derive(Debug, Clone)]
pub struct PipeConfig {
    pub name: String,
    pub command: String,
    pub respawn_delay: Duration,
    pub interface_id: InterfaceId,
    pub runtime: Arc<Mutex<PipeRuntime>>,
}

#[derive(Debug, Clone)]
pub struct PipeRuntime {
    pub respawn_delay: Duration,
}

impl PipeRuntime {
    pub fn from_config(config: &PipeConfig) -> Self {
        Self {
            respawn_delay: config.respawn_delay,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipeRuntimeConfigHandle {
    pub interface_name: String,
    pub runtime: Arc<Mutex<PipeRuntime>>,
    pub startup: PipeRuntime,
}

impl Default for PipeConfig {
    fn default() -> Self {
        let mut config = PipeConfig {
            name: String::new(),
            command: String::new(),
            respawn_delay: Duration::from_secs(5),
            interface_id: InterfaceId(0),
            runtime: Arc::new(Mutex::new(PipeRuntime {
                respawn_delay: Duration::from_secs(5),
            })),
        };
        let startup = PipeRuntime::from_config(&config);
        config.runtime = Arc::new(Mutex::new(startup));
        config
    }
}

/// Writer that sends HDLC-framed data to a subprocess stdin.
struct PipeWriter {
    stdin: std::process::ChildStdin,
}

impl Writer for PipeWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stdin.write_all(&hdlc::frame(data))
    }
}

/// Start the pipe interface. Spawns subprocess, returns writer.
pub fn start(config: PipeConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let id = config.interface_id;
    {
        let startup = PipeRuntime::from_config(&config);
        *config.runtime.lock().unwrap() = startup;
    }

    let mut child = spawn_child(&config.command)?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no stdout from child"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no stdin from child"))?;

    log::info!(
        "[{}] pipe interface started: {}",
        config.name,
        config.command
    );

    // Signal interface up
    let _ = tx.send(Event::InterfaceUp(id, None, None));

    // Spawn reader thread
    thread::Builder::new()
        .name(format!("pipe-reader-{}", id.0))
        .spawn(move || {
            reader_loop(stdout, child, id, config, tx);
        })?;

    Ok(Box::new(PipeWriter { stdin }))
}

fn spawn_child(command: &str) -> io::Result<std::process::Child> {
    Command::new("sh")
        .args(["-c", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// Reader loop: reads from subprocess stdout, HDLC-decodes, dispatches events.
/// On subprocess exit, attempts respawn.
fn reader_loop(
    mut stdout: std::process::ChildStdout,
    mut child: std::process::Child,
    id: InterfaceId,
    config: PipeConfig,
    tx: EventSender,
) {
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stdout.read(&mut buf) {
            Ok(0) => {
                // EOF — subprocess exited
                let _ = child.wait();
                log::warn!("[{}] subprocess terminated", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match respawn(&config, &tx) {
                    Some((new_stdout, new_child)) => {
                        stdout = new_stdout;
                        child = new_child;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
            Ok(n) => {
                for frame in decoder.feed(&buf[..n]) {
                    if tx
                        .send(Event::Frame {
                            interface_id: id,
                            data: frame,
                        })
                        .is_err()
                    {
                        // Driver shut down
                        let _ = child.kill();
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] pipe read error: {}", config.name, e);
                let _ = child.kill();
                let _ = child.wait();
                let _ = tx.send(Event::InterfaceDown(id));
                match respawn(&config, &tx) {
                    Some((new_stdout, new_child)) => {
                        stdout = new_stdout;
                        child = new_child;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => return,
                }
            }
        }
    }
}

/// Attempt to respawn the subprocess after a delay.
fn respawn(
    config: &PipeConfig,
    tx: &EventSender,
) -> Option<(std::process::ChildStdout, std::process::Child)> {
    loop {
        thread::sleep(config.runtime.lock().unwrap().respawn_delay);
        log::info!(
            "[{}] attempting to respawn subprocess: {}",
            config.name,
            config.command
        );

        match spawn_child(&config.command) {
            Ok(mut child) => {
                let stdout = match child.stdout.take() {
                    Some(s) => s,
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        continue;
                    }
                };
                let stdin = match child.stdin.take() {
                    Some(s) => s,
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        continue;
                    }
                };

                let new_writer: Box<dyn Writer> = Box::new(PipeWriter { stdin });
                if tx
                    .send(Event::InterfaceUp(
                        config.interface_id,
                        Some(new_writer),
                        None,
                    ))
                    .is_err()
                {
                    return None; // Driver shut down
                }
                log::info!("[{}] subprocess respawned", config.name);
                return Some((stdout, child));
            }
            Err(e) => {
                log::warn!("[{}] respawn failed: {}", config.name, e);
            }
        }
    }
}

/// Factory for [`PipeInterface`] instances.
pub struct PipeFactory;

impl InterfaceFactory for PipeFactory {
    fn type_name(&self) -> &str {
        "PipeInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        let command = params
            .get("command")
            .ok_or_else(|| "PipeInterface requires 'command'".to_string())?
            .clone();

        let respawn_delay = match params.get("respawn_delay") {
            Some(v) => {
                let ms: u64 = v
                    .parse()
                    .map_err(|_| format!("invalid respawn_delay: {}", v))?;
                Duration::from_millis(ms)
            }
            None => Duration::from_secs(5),
        };

        Ok(Box::new(PipeConfig {
            name: name.to_string(),
            command,
            respawn_delay,
            interface_id: id,
            runtime: Arc::new(Mutex::new(PipeRuntime { respawn_delay })),
        }))
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> io::Result<StartResult> {
        let pipe_config = *config
            .into_any()
            .downcast::<PipeConfig>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong config type"))?;

        let id = pipe_config.interface_id;
        let info = InterfaceInfo {
            id,
            name: pipe_config.name.clone(),
            mode: ctx.mode,
            out_capable: true,
            in_capable: true,
            bitrate: Some(1_000_000),
            announce_rate_target: None,
            announce_rate_grace: 0,
            announce_rate_penalty: 0.0,
            announce_cap: rns_core::constants::ANNOUNCE_CAP,
            is_local_client: false,
            wants_tunnel: false,
            tunnel_id: None,
            mtu: rns_core::constants::MTU as u32,
            ingress_control: false,
            ia_freq: 0.0,
            started: crate::time::now(),
        };

        let writer = start(pipe_config, ctx.tx)?;

        Ok(StartResult::Simple {
            id,
            info,
            writer,
            interface_type_name: "PipeInterface".to_string(),
        })
    }
}

pub(crate) fn pipe_runtime_handle_from_config(config: &PipeConfig) -> PipeRuntimeConfigHandle {
    PipeRuntimeConfigHandle {
        interface_name: config.name.clone(),
        runtime: Arc::clone(&config.runtime),
        startup: PipeRuntime::from_config(config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_start_and_receive() {
        // Use `cat` as a loopback subprocess
        let (tx, rx) = crate::event::channel();
        let config = PipeConfig {
            name: "test-pipe".into(),
            command: "cat".into(),
            respawn_delay: Duration::from_secs(1),
            interface_id: InterfaceId(100),
            runtime: Arc::new(Mutex::new(PipeRuntime {
                respawn_delay: Duration::from_secs(1),
            })),
        };

        let mut writer = start(config, tx).unwrap();

        // Drain InterfaceUp
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            event,
            Event::InterfaceUp(InterfaceId(100), None, None)
        ));

        // Send a packet (>= 19 bytes for HDLC minimum)
        let payload: Vec<u8> = (0..32).collect();
        writer.send_frame(&payload).unwrap();

        // Should receive Frame event (cat echos back the HDLC frame)
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(100));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn pipe_writer_sends() {
        // Verify the writer wraps data in HDLC
        let (tx, rx) = crate::event::channel();
        let config = PipeConfig {
            name: "test-pipe-writer".into(),
            command: "cat".into(),
            respawn_delay: Duration::from_secs(1),
            interface_id: InterfaceId(101),
            runtime: Arc::new(Mutex::new(PipeRuntime {
                respawn_delay: Duration::from_secs(1),
            })),
        };

        let mut writer = start(config, tx).unwrap();
        let _ = rx.recv_timeout(Duration::from_secs(2)).unwrap(); // drain InterfaceUp

        // Write data and verify we get it back as HDLC frame
        let payload: Vec<u8> = (10..42).collect();
        writer.send_frame(&payload).unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => {
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn pipe_subprocess_exit() {
        // Use a command that exits immediately
        let (tx, rx) = crate::event::channel();
        let config = PipeConfig {
            name: "test-pipe-exit".into(),
            command: "true".into(),                 // exits immediately with 0
            respawn_delay: Duration::from_secs(60), // long delay so we catch InterfaceDown
            interface_id: InterfaceId(102),
            runtime: Arc::new(Mutex::new(PipeRuntime {
                respawn_delay: Duration::from_secs(60),
            })),
        };

        let _writer = start(config, tx).unwrap();

        // Should get InterfaceUp then InterfaceDown
        let mut got_down = false;
        for _ in 0..5 {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(Event::InterfaceDown(InterfaceId(102))) => {
                    got_down = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(
            got_down,
            "should receive InterfaceDown after subprocess exits"
        );
    }

    #[test]
    fn pipe_config_defaults() {
        let config = PipeConfig::default();
        assert_eq!(config.respawn_delay, Duration::from_secs(5));
        assert_eq!(config.interface_id, InterfaceId(0));
        assert!(config.command.is_empty());
    }

    #[test]
    fn pipe_invalid_command() {
        let (tx, _rx) = crate::event::channel();
        let config = PipeConfig {
            name: "test-pipe-bad".into(),
            command: "/nonexistent_rns_test_binary_that_does_not_exist_xyz".into(),
            respawn_delay: Duration::from_secs(60),
            interface_id: InterfaceId(103),
            runtime: Arc::new(Mutex::new(PipeRuntime {
                respawn_delay: Duration::from_secs(60),
            })),
        };

        // sh -c <nonexistent> will start sh successfully but the child exits immediately
        // For a truly invalid binary we need to check that the process fails
        // Actually, sh -c "<nonexistent>" will still spawn sh successfully
        // Let's test with a different approach: verify it doesn't panic
        let result = start(config, tx);
        // sh will spawn successfully even if the inner command fails
        // The real test is that it doesn't panic
        assert!(result.is_ok());
    }
}
