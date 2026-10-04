//! Optional userspace TCP byte pacing. No host network configuration is changed.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub forwarded_bytes: u64,
    pub chunks: u64,
    pub max_pacing_lateness_ns: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub sender_to_receiver: Counters,
    pub receiver_to_sender: Counters,
}
#[derive(Default)]
struct State {
    counters: Snapshot,
    error: Option<String>,
}

/// At most 10 ms of bytes per chunk, bounded independently of socket buffering.
fn chunk_size(rate_bps: u64) -> usize {
    (rate_bps / 800).clamp(1, 4096) as usize
}
fn serialization_time(bytes: usize, rate_bps: u64) -> Duration {
    Duration::from_nanos((bytes as u64 * 8_000_000_000).div_ceil(rate_bps))
}

pub struct Relay {
    port: u16,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
    worker: Option<JoinHandle<()>>,
}
impl Relay {
    pub fn start(receiver_port: u16, rate_bps: u64) -> Result<Self> {
        ensure!(
            (64_000..=1_000_000_000).contains(&rate_bps),
            "rate must be 64000..1000000000 bit/s per direction"
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(State::default()));
        let worker_stop = stop.clone();
        let worker_state = state.clone();
        let worker = thread::spawn(move || {
            let result = (|| -> Result<()> {
                let sender = loop {
                    if worker_stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => return Err(e.into()),
                    }
                };
                let receiver = TcpStream::connect_timeout(
                    &format!("127.0.0.1:{receiver_port}").parse()?,
                    Duration::from_secs(2),
                )?;
                for socket in [&sender, &receiver] {
                    socket.set_nodelay(true)?;
                    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
                    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
                }
                let sender_back = sender.try_clone()?;
                let receiver_back = receiver.try_clone()?;
                thread::scope(|scope| {
                    let back = scope.spawn(|| {
                        pump(
                            receiver_back,
                            sender_back,
                            rate_bps,
                            false,
                            &worker_stop,
                            &worker_state,
                        )
                    });
                    let forward = pump(
                        sender,
                        receiver,
                        rate_bps,
                        true,
                        &worker_stop,
                        &worker_state,
                    );
                    worker_stop.store(true, Ordering::Relaxed);
                    let backward = back
                        .join()
                        .map_err(|_| anyhow::anyhow!("relay thread panicked"))?;
                    forward.and(backward)
                })
            })();
            if let Err(e) = result {
                worker_state.lock().unwrap().error = Some(format!("{e:#}"));
            }
        });
        Ok(Self {
            port,
            stop,
            state,
            worker: Some(worker),
        })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        let state = self.state.lock().unwrap();
        ensure!(
            state.error.is_none(),
            "rate relay failed: {}",
            state.error.as_deref().unwrap_or("")
        );
        ensure!(
            !self.stop.load(Ordering::Relaxed),
            "rate relay closed before measurement completed"
        );
        Ok(state.counters.clone())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Calibration {
    pub rate_bps_per_direction: u64,
    pub bytes_per_direction: usize,
    pub sender_to_receiver_seconds: f64,
    pub receiver_to_sender_seconds: f64,
    pub minimum_rate_fraction: f64,
    pub counters: Snapshot,
}

/// A separate raw-stream check, excluding protocol work and endpoint CPU metrics.
/// This diagnoses a pacer that cannot approach its requested cap on this host.
pub fn calibrate(rate_bps: u64) -> Result<Calibration> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let relay = Relay::start(listener.local_addr()?.port(), rate_bps)?;
    let mut sender = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", relay.port()).parse()?,
        Duration::from_secs(2),
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(
                    Instant::now() < deadline,
                    "calibration connection timed out"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    };
    for socket in [&sender, &receiver] {
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    }
    let bytes = (rate_bps / 32).clamp(2000, 1024 * 1024) as usize;
    let payload: Vec<u8> = (0..bytes).map(|n| (n % 251) as u8).collect();
    let transfer = |writer: &mut TcpStream, reader: &mut TcpStream| -> Result<f64> {
        let mut received = vec![0; bytes];
        let start = Instant::now();
        thread::scope(|scope| -> Result<()> {
            let task = scope.spawn(|| writer.write_all(&payload));
            let read = reader.read_exact(&mut received);
            task.join()
                .map_err(|_| anyhow::anyhow!("calibration writer panicked"))??;
            read?;
            Ok(())
        })?;
        let elapsed = start.elapsed();
        ensure!(received == payload, "calibration payload corrupted");
        ensure!(
            elapsed >= serialization_time(bytes, rate_bps),
            "relay exceeded configured rate"
        );
        Ok(elapsed.as_secs_f64())
    };
    let forward = transfer(&mut sender, &mut receiver)?;
    let backward = transfer(&mut receiver, &mut sender)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let counters = loop {
        let counters = relay.snapshot()?;
        if counters.sender_to_receiver.forwarded_bytes == bytes as u64
            && counters.receiver_to_sender.forwarded_bytes == bytes as u64
        {
            break counters;
        }
        ensure!(
            Instant::now() < deadline,
            "calibration counters did not settle"
        );
        thread::sleep(Duration::from_millis(1));
    };
    Ok(Calibration {
        rate_bps_per_direction: rate_bps,
        bytes_per_direction: bytes,
        sender_to_receiver_seconds: forward,
        receiver_to_sender_seconds: backward,
        minimum_rate_fraction: bytes as f64 * 8.0 / forward.max(backward) / rate_bps as f64,
        counters,
    })
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn pump(
    mut input: TcpStream,
    mut output: TcpStream,
    rate_bps: u64,
    forward: bool,
    stop: &AtomicBool,
    state: &Mutex<State>,
) -> Result<()> {
    let mut buffer = vec![0; chunk_size(rate_bps)];
    while !stop.load(Ordering::Relaxed) {
        let size = match input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e).context("relay read"),
        };
        // Pay for this chunk before forwarding. No accumulated idle credit or
        // catch-up burst after a scheduler stall; late pacing reduces capacity.
        let deadline = Instant::now() + serialization_time(size, rate_bps);
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
        let lateness = deadline.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        output.write_all(&buffer[..size]).context("relay write")?;
        let mut state = state.lock().unwrap();
        let counters = if forward {
            &mut state.counters.sender_to_receiver
        } else {
            &mut state.counters.receiver_to_sender
        };
        counters.forwarded_bytes += size as u64;
        counters.chunks += 1;
        counters.max_pacing_lateness_ns = counters.max_pacing_lateness_ns.max(lateness);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pacing_budget_has_no_free_bytes() {
        for rate in [64_000, 1_000_000, 8_000_000, 1_000_000_000] {
            let chunk = chunk_size(rate);
            assert!(chunk <= 4096);
            let cost = serialization_time(chunk, rate);
            assert!(cost <= Duration::from_millis(10));
            assert!(cost.as_nanos() * rate as u128 >= chunk as u128 * 8_000_000_000);
        }
    }
    #[test]
    #[ignore = "requires loopback sockets"]
    fn relay_preserves_bytes_caps_rate_and_stops_without_client() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = Relay::start(listener.local_addr().unwrap().port(), 64_000).unwrap();
        let mut sender = TcpStream::connect(("127.0.0.1", relay.port())).unwrap();
        let (mut receiver, _) = listener.accept().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        sender
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let bytes = vec![0x5a; 1600];
        let start = Instant::now();
        sender.write_all(&bytes).unwrap();
        let mut got = vec![0; bytes.len()];
        receiver.read_exact(&mut got).unwrap();
        assert_eq!(got, bytes);
        assert!(start.elapsed() >= serialization_time(bytes.len(), 64_000));
        receiver.write_all(&bytes).unwrap();
        sender.read_exact(&mut got).unwrap();
        assert_eq!(got, bytes);
        // Counter update can follow the receiving thread by a scheduling tick.
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let count = relay.snapshot().unwrap();
            if count.receiver_to_sender.forwarded_bytes == 1600 {
                assert_eq!(count.sender_to_receiver.forwarded_bytes, 1600);
                break;
            }
            assert!(Instant::now() < until);
            thread::yield_now();
        }
        drop(relay);
        let idle = Relay::start(listener.local_addr().unwrap().port(), 64_000).unwrap();
        drop(idle);
        let active = Relay::start(listener.local_addr().unwrap().port(), 64_000).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", active.port())).unwrap();
        let (_upstream, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // Both pump threads may be blocked reading. Cleanup must close the
        // accepted sockets without waiting for the peer to send or disconnect.
        drop(active);
        assert_eq!(client.read(&mut [0; 1]).unwrap(), 0);
    }
}
