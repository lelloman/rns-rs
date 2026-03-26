use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    DropNewest,
    DropOldest,
}

#[derive(Debug, Clone)]
pub struct ProviderBridgeConfig {
    pub enabled: bool,
    pub socket_path: PathBuf,
    pub queue_max_events: usize,
    pub queue_max_bytes: usize,
    pub overflow_policy: OverflowPolicy,
    pub node_instance: String,
}

impl Default for ProviderBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: PathBuf::from("/tmp/rns-provider.sock"),
            queue_max_events: 8192,
            queue_max_bytes: 4 * 1024 * 1024,
            overflow_policy: OverflowPolicy::DropNewest,
            node_instance: "default".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderEnvelope {
    pub version: u16,
    pub seq: u64,
    pub message: ProviderMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProviderMessage {
    Event(HookProviderEventEnvelope),
    DroppedEvents { count: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookProviderEventEnvelope {
    pub ts_unix_ms: u64,
    pub node_instance: String,
    pub hook_name: String,
    pub attach_point: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct QueuedEnvelope {
    encoded: Vec<u8>,
}

#[derive(Debug)]
struct BridgeState {
    queue: VecDeque<QueuedEnvelope>,
    queued_bytes: usize,
    dropped_count: u64,
    next_seq: u64,
    connected: bool,
    shutdown: bool,
    queue_max_events: usize,
    queue_max_bytes: usize,
}

struct BridgeShared {
    config: ProviderBridgeConfig,
    state: Mutex<BridgeState>,
    condvar: Condvar,
}

pub struct ProviderBridge {
    shared: Arc<BridgeShared>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ProviderBridge {
    pub fn start(config: ProviderBridgeConfig) -> io::Result<Self> {
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        remove_stale_socket(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path)?;
        listener.set_nonblocking(true)?;

        let queue_max_events = config.queue_max_events;
        let queue_max_bytes = config.queue_max_bytes;
        let shared = Arc::new(BridgeShared {
            config,
            state: Mutex::new(BridgeState {
                queue: VecDeque::new(),
                queued_bytes: 0,
                dropped_count: 0,
                next_seq: 1,
                connected: false,
                shutdown: false,
                queue_max_events,
                queue_max_bytes,
            }),
            condvar: Condvar::new(),
        });

        let thread_shared = shared.clone();
        let thread = thread::Builder::new()
            .name("provider-bridge".into())
            .spawn(move || provider_bridge_loop(listener, thread_shared))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    pub fn emit_event(
        &self,
        attach_point: &str,
        hook_name: String,
        payload_type: String,
        payload: Vec<u8>,
    ) {
        let mut state = self.shared.state.lock().unwrap();
        let envelope = ProviderEnvelope {
            version: 1,
            seq: take_seq(&mut state),
            message: ProviderMessage::Event(HookProviderEventEnvelope {
                ts_unix_ms: current_unix_ms(),
                node_instance: self.shared.config.node_instance.clone(),
                hook_name,
                attach_point: attach_point.to_string(),
                payload_type,
                payload,
            }),
        };
        enqueue_serialized(&self.shared, &mut state, envelope);
    }

    pub fn queue_max_events(&self) -> usize {
        self.shared.state.lock().unwrap().queue_max_events
    }

    pub fn set_queue_max_events(&self, value: usize) {
        self.shared.state.lock().unwrap().queue_max_events = value;
    }

    pub fn queue_max_bytes(&self) -> usize {
        self.shared.state.lock().unwrap().queue_max_bytes
    }

    pub fn set_queue_max_bytes(&self, value: usize) {
        self.shared.state.lock().unwrap().queue_max_bytes = value;
    }
}

impl Drop for ProviderBridge {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock().unwrap();
            state.shutdown = true;
            self.shared.condvar.notify_all();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.shared.config.socket_path);
    }
}

fn provider_bridge_loop(listener: UnixListener, shared: Arc<BridgeShared>) {
    let mut consumers: Vec<UnixStream> = Vec::new();

    loop {
        {
            let state = shared.state.lock().unwrap();
            if state.shutdown {
                break;
            }
        }

        // Accept all pending connections.
        loop {
            match listener.accept() {
                Ok((accepted, _)) => {
                    let _ = accepted.set_write_timeout(Some(Duration::from_secs(1)));
                    log::info!(
                        "provider bridge consumer connected (total: {})",
                        consumers.len() + 1
                    );
                    consumers.push(accepted);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    log::warn!("provider bridge accept error: {}", err);
                    break;
                }
            }
        }

        // Update connected state.
        if let Ok(mut state) = shared.state.lock() {
            let was_connected = state.connected;
            state.connected = !consumers.is_empty();
            if state.connected && !was_connected {
                shared.condvar.notify_all();
            }
        }

        if !consumers.is_empty() {
            match next_encoded_frame(&shared) {
                Some(frame) => {
                    let mut failed = Vec::new();
                    for (i, consumer) in consumers.iter_mut().enumerate() {
                        if let Err(err) = write_frame(consumer, &frame) {
                            log::debug!("provider bridge consumer {} write error: {}", i, err);
                            failed.push(i);
                        }
                    }
                    // Remove failed consumers in reverse order to preserve indices.
                    for &i in failed.iter().rev() {
                        log::info!(
                            "provider bridge consumer disconnected (remaining: {})",
                            consumers.len() - 1
                        );
                        consumers.swap_remove(i);
                    }
                    if !failed.is_empty() && consumers.is_empty() {
                        // All consumers gone — account for the failed frame.
                        account_failed_frame(&shared, frame);
                    }
                    continue;
                }
                None => {}
            }
        }

        let state = shared.state.lock().unwrap();
        if state.shutdown {
            break;
        }
        let _ = shared
            .condvar
            .wait_timeout(state, Duration::from_millis(100))
            .unwrap();
    }
}

fn next_encoded_frame(shared: &Arc<BridgeShared>) -> Option<Vec<u8>> {
    let mut state = shared.state.lock().unwrap();
    if state.dropped_count > 0 {
        let dropped = ProviderEnvelope {
            version: 1,
            seq: take_seq(&mut state),
            message: ProviderMessage::DroppedEvents {
                count: state.dropped_count,
            },
        };
        match bincode::serialize(&dropped) {
            Ok(encoded) => {
                state.dropped_count = 0;
                return Some(encoded);
            }
            Err(err) => {
                log::warn!("provider bridge failed to serialize dropped event: {}", err);
            }
        }
    }

    let queued = state.queue.pop_front()?;
    state.queued_bytes = state.queued_bytes.saturating_sub(queued.encoded.len());
    Some(queued.encoded)
}

fn account_failed_frame(shared: &Arc<BridgeShared>, encoded: Vec<u8>) {
    if let Ok(envelope) = bincode::deserialize::<ProviderEnvelope>(&encoded) {
        let mut state = shared.state.lock().unwrap();
        match envelope.message {
            ProviderMessage::DroppedEvents { count } => {
                state.dropped_count = state.dropped_count.saturating_add(count);
            }
            ProviderMessage::Event(_) => {
                state.dropped_count = state.dropped_count.saturating_add(1);
            }
        }
    }
}

fn enqueue_serialized(
    shared: &Arc<BridgeShared>,
    state: &mut BridgeState,
    envelope: ProviderEnvelope,
) {
    let encoded = match bincode::serialize(&envelope) {
        Ok(encoded) => encoded,
        Err(err) => {
            log::warn!("provider bridge failed to serialize event: {}", err);
            state.dropped_count = state.dropped_count.saturating_add(1);
            return;
        }
    };

    if encoded.len() > state.queue_max_bytes {
        state.dropped_count = state.dropped_count.saturating_add(1);
        return;
    }

    while !can_fit(state, encoded.len()) {
        match shared.config.overflow_policy {
            OverflowPolicy::DropNewest => {
                state.dropped_count = state.dropped_count.saturating_add(1);
                return;
            }
            OverflowPolicy::DropOldest => {
                if let Some(old) = state.queue.pop_front() {
                    state.queued_bytes = state.queued_bytes.saturating_sub(old.encoded.len());
                    state.dropped_count = state.dropped_count.saturating_add(1);
                } else {
                    state.dropped_count = state.dropped_count.saturating_add(1);
                    return;
                }
            }
        }
    }

    state.queued_bytes += encoded.len();
    state.queue.push_back(QueuedEnvelope { encoded });
    shared.condvar.notify_one();
}

fn can_fit(state: &BridgeState, len: usize) -> bool {
    state.queue.len() < state.queue_max_events
        && state.queued_bytes.saturating_add(len) <= state.queue_max_bytes
}

fn take_seq(state: &mut BridgeState) -> u64 {
    let seq = state.next_seq;
    state.next_seq += 1;
    seq
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "provider frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_frame(stream: &mut UnixStream) -> ProviderEnvelope {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).unwrap();
        bincode::deserialize(&buf).unwrap()
    }

    fn wait_for_consumer(bridge: &ProviderBridge) {
        let mut state = bridge.shared.state.lock().unwrap();
        while !state.connected {
            state = bridge.shared.condvar.wait(state).unwrap();
        }
    }

    #[test]
    fn bridge_delivers_events_and_dropped_notice() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = ProviderBridge::start(ProviderBridgeConfig {
            enabled: true,
            socket_path: socket_path.clone(),
            queue_max_events: 1,
            queue_max_bytes: 4096,
            overflow_policy: OverflowPolicy::DropNewest,
            node_instance: "node-a".into(),
        })
        .unwrap();

        bridge.emit_event(
            "PreIngress",
            "hook-a".into(),
            "packet".into(),
            vec![1, 2, 3],
        );
        bridge.emit_event(
            "PreIngress",
            "hook-a".into(),
            "packet".into(),
            vec![4, 5, 6],
        );

        let mut stream = UnixStream::connect(socket_path).unwrap();
        wait_for_consumer(&bridge);
        let dropped = read_frame(&mut stream);
        assert_eq!(dropped.message, ProviderMessage::DroppedEvents { count: 1 });

        let event = read_frame(&mut stream);
        match event.message {
            ProviderMessage::Event(evt) => {
                assert_eq!(evt.node_instance, "node-a");
                assert_eq!(evt.hook_name, "hook-a");
                assert_eq!(evt.attach_point, "PreIngress");
                assert_eq!(evt.payload_type, "packet");
                assert_eq!(evt.payload, vec![1, 2, 3]);
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[test]
    fn bridge_fans_out_to_multiple_consumers() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = ProviderBridge::start(ProviderBridgeConfig {
            enabled: true,
            socket_path: socket_path.clone(),
            queue_max_events: 64,
            queue_max_bytes: 65536,
            overflow_policy: OverflowPolicy::DropNewest,
            node_instance: "node-b".into(),
        })
        .unwrap();

        let mut stream_a = UnixStream::connect(&socket_path).unwrap();
        wait_for_consumer(&bridge);
        let mut stream_b = UnixStream::connect(&socket_path).unwrap();
        // Give the bridge thread time to accept the second connection.
        std::thread::sleep(Duration::from_millis(200));

        bridge.emit_event(
            "PreIngress",
            "hook-x".into(),
            "packet".into(),
            vec![10, 20],
        );

        let env_a = read_frame(&mut stream_a);
        let env_b = read_frame(&mut stream_b);
        match (&env_a.message, &env_b.message) {
            (ProviderMessage::Event(a), ProviderMessage::Event(b)) => {
                assert_eq!(a.payload, vec![10, 20]);
                assert_eq!(b.payload, vec![10, 20]);
            }
            other => panic!("unexpected messages: {:?}", other),
        }
    }
}
