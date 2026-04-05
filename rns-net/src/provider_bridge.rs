use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::common::event::{ProviderBridgeConsumerStats, ProviderBridgeStats};

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

#[derive(Debug, Clone)]
struct QueuedEnvelope {
    encoded: Vec<u8>,
}

struct ConsumerEntry {
    shared: Arc<ConsumerShared>,
    thread: Option<thread::JoinHandle<()>>,
}

struct BridgeState {
    next_seq: u64,
    next_consumer_id: u64,
    connected: bool,
    shutdown: bool,
    queue_max_events: usize,
    queue_max_bytes: usize,
    consumers: Vec<ConsumerEntry>,
    backlog: VecDeque<QueuedEnvelope>,
    backlog_bytes: usize,
    backlog_dropped_count: u64,
    backlog_dropped_total: u64,
    total_disconnect_count: u64,
}

struct BridgeShared {
    config: ProviderBridgeConfig,
    state: Mutex<BridgeState>,
    condvar: Condvar,
}

#[derive(Debug)]
struct ConsumerState {
    queue: VecDeque<QueuedEnvelope>,
    queued_bytes: usize,
    dropped_count: u64,
    dropped_total: u64,
    queue_max_events: usize,
    queue_max_bytes: usize,
    connected: bool,
    shutdown: bool,
}

struct ConsumerShared {
    id: u64,
    state: Mutex<ConsumerState>,
    condvar: Condvar,
}

impl ConsumerShared {
    fn new(id: u64, queue_max_events: usize, queue_max_bytes: usize) -> Self {
        Self {
            id,
            state: Mutex::new(ConsumerState {
                queue: VecDeque::new(),
                queued_bytes: 0,
                dropped_count: 0,
                dropped_total: 0,
                queue_max_events,
                queue_max_bytes,
                connected: true,
                shutdown: false,
            }),
            condvar: Condvar::new(),
        }
    }
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
                next_seq: 1,
                next_consumer_id: 1,
                connected: false,
                shutdown: false,
                queue_max_events,
                queue_max_bytes,
                consumers: Vec::new(),
                backlog: VecDeque::new(),
                backlog_bytes: 0,
                backlog_dropped_count: 0,
                backlog_dropped_total: 0,
                total_disconnect_count: 0,
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
        let (encoded, consumers) = {
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
            let encoded = match bincode::serialize(&envelope) {
                Ok(encoded) => encoded,
                Err(err) => {
                    log::warn!("provider bridge failed to serialize event: {}", err);
                    return;
                }
            };

            if state.consumers.is_empty() {
                enqueue_backlog(&self.shared.config, &mut state, encoded);
                return;
            }

            let consumers = state
                .consumers
                .iter()
                .map(|consumer| consumer.shared.clone())
                .collect::<Vec<_>>();
            (encoded, consumers)
        };

        for consumer in consumers {
            enqueue_consumer_frame(&self.shared.config, &consumer, encoded.clone());
        }
    }

    pub fn queue_max_events(&self) -> usize {
        self.shared.state.lock().unwrap().queue_max_events
    }

    pub fn set_queue_max_events(&self, value: usize) {
        let consumers = {
            let mut state = self.shared.state.lock().unwrap();
            state.queue_max_events = value;
            state
                .consumers
                .iter()
                .map(|consumer| consumer.shared.clone())
                .collect::<Vec<_>>()
        };
        for consumer in consumers {
            consumer.state.lock().unwrap().queue_max_events = value;
        }
    }

    pub fn queue_max_bytes(&self) -> usize {
        self.shared.state.lock().unwrap().queue_max_bytes
    }

    pub fn set_queue_max_bytes(&self, value: usize) {
        let consumers = {
            let mut state = self.shared.state.lock().unwrap();
            state.queue_max_bytes = value;
            state
                .consumers
                .iter()
                .map(|consumer| consumer.shared.clone())
                .collect::<Vec<_>>()
        };
        for consumer in consumers {
            consumer.state.lock().unwrap().queue_max_bytes = value;
        }
    }

    pub fn stats(&self) -> ProviderBridgeStats {
        let (
            connected,
            consumer_count,
            queue_max_events,
            queue_max_bytes,
            backlog_len,
            backlog_bytes,
            backlog_dropped_pending,
            backlog_dropped_total,
            total_disconnect_count,
            consumers,
        ) = {
            let state = self.shared.state.lock().unwrap();
            (
                state.connected,
                state.consumers.len(),
                state.queue_max_events,
                state.queue_max_bytes,
                state.backlog.len(),
                state.backlog_bytes,
                state.backlog_dropped_count,
                state.backlog_dropped_total,
                state.total_disconnect_count,
                state
                    .consumers
                    .iter()
                    .map(|consumer| consumer.shared.clone())
                    .collect::<Vec<_>>(),
            )
        };

        let consumers = consumers
            .into_iter()
            .map(|consumer| {
                let state = consumer.state.lock().unwrap();
                ProviderBridgeConsumerStats {
                    id: consumer.id,
                    connected: state.connected,
                    queue_len: state.queue.len(),
                    queued_bytes: state.queued_bytes,
                    dropped_pending: state.dropped_count,
                    dropped_total: state.dropped_total,
                    queue_max_events: state.queue_max_events,
                    queue_max_bytes: state.queue_max_bytes,
                }
            })
            .collect();

        ProviderBridgeStats {
            connected,
            consumer_count,
            queue_max_events,
            queue_max_bytes,
            backlog_len,
            backlog_bytes,
            backlog_dropped_pending,
            backlog_dropped_total,
            total_disconnect_count,
            consumers,
        }
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

        let handles = {
            let mut state = self.shared.state.lock().unwrap();
            let mut handles = Vec::new();
            for consumer in &mut state.consumers {
                {
                    let mut consumer_state = consumer.shared.state.lock().unwrap();
                    consumer_state.shutdown = true;
                    consumer.shared.condvar.notify_all();
                }
                if let Some(handle) = consumer.thread.take() {
                    handles.push(handle);
                }
            }
            state.consumers.clear();
            state.connected = false;
            handles
        };

        for handle in handles {
            let _ = handle.join();
        }

        let _ = fs::remove_file(&self.shared.config.socket_path);
    }
}

fn provider_bridge_loop(listener: UnixListener, shared: Arc<BridgeShared>) {
    loop {
        {
            let state = shared.state.lock().unwrap();
            if state.shutdown {
                break;
            }
        }

        loop {
            match listener.accept() {
                Ok((accepted, _)) => {
                    if let Err(err) = accepted.set_write_timeout(Some(Duration::from_secs(1))) {
                        log::debug!("provider bridge consumer timeout setup failed: {}", err);
                    }

                    let (consumer_shared, backlog_seed) = {
                        let mut state = shared.state.lock().unwrap();
                        let consumer_id = state.next_consumer_id;
                        state.next_consumer_id += 1;

                        let consumer_shared = Arc::new(ConsumerShared::new(
                            consumer_id,
                            state.queue_max_events,
                            state.queue_max_bytes,
                        ));

                        let backlog_seed = if state.consumers.is_empty() {
                            Some((
                                state.backlog_dropped_count,
                                state.backlog.iter().cloned().collect::<Vec<_>>(),
                            ))
                        } else {
                            None
                        };

                        if backlog_seed.is_some() {
                            state.backlog.clear();
                            state.backlog_bytes = 0;
                            state.backlog_dropped_count = 0;
                        }

                        (consumer_shared, backlog_seed)
                    };

                    if let Some((dropped_count, queued)) = backlog_seed {
                        let mut consumer_state = consumer_shared.state.lock().unwrap();
                        consumer_state.dropped_count = dropped_count;
                        for frame in queued {
                            consumer_state.queued_bytes += frame.encoded.len();
                            consumer_state.queue.push_back(frame);
                        }
                    }

                    match spawn_consumer_thread(shared.clone(), consumer_shared.clone(), accepted) {
                        Ok(thread) => {
                            let total = {
                                let mut state = shared.state.lock().unwrap();
                                state.consumers.push(ConsumerEntry {
                                    shared: consumer_shared,
                                    thread: Some(thread),
                                });
                                let was_connected = state.connected;
                                state.connected = !state.consumers.is_empty();
                                if state.connected && !was_connected {
                                    shared.condvar.notify_all();
                                }
                                state.consumers.len()
                            };
                            log::info!("provider bridge consumer connected (total: {})", total);
                        }
                        Err(err) => {
                            log::warn!("provider bridge failed to spawn consumer thread: {}", err);
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    log::warn!("provider bridge accept error: {}", err);
                    break;
                }
            }
        }

        prune_disconnected_consumers(&shared);

        let state = shared.state.lock().unwrap();
        if state.shutdown {
            break;
        }
        let _ = shared
            .condvar
            .wait_timeout(state, Duration::from_millis(100))
            .unwrap();
    }

    prune_disconnected_consumers(&shared);
}

fn spawn_consumer_thread(
    bridge_shared: Arc<BridgeShared>,
    consumer_shared: Arc<ConsumerShared>,
    mut stream: UnixStream,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("provider-consumer-{}", consumer_shared.id))
        .spawn(move || loop {
            match next_consumer_frame(&bridge_shared, &consumer_shared) {
                Some(frame) => {
                    if let Err(err) = write_frame(&mut stream, &frame) {
                        log::info!(
                            "provider bridge consumer {} disconnected: {}",
                            consumer_shared.id,
                            err
                        );
                        let mut state = consumer_shared.state.lock().unwrap();
                        state.connected = false;
                        state.shutdown = true;
                        drop(state);
                        let mut bridge_state = bridge_shared.state.lock().unwrap();
                        bridge_state.total_disconnect_count =
                            bridge_state.total_disconnect_count.saturating_add(1);
                        bridge_shared.condvar.notify_all();
                        break;
                    }
                }
                None => {
                    let state = consumer_shared.state.lock().unwrap();
                    if state.shutdown {
                        break;
                    }
                    let _ = consumer_shared
                        .condvar
                        .wait_timeout(state, Duration::from_millis(100))
                        .unwrap();
                }
            }
        })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

fn next_consumer_frame(
    bridge_shared: &Arc<BridgeShared>,
    consumer_shared: &Arc<ConsumerShared>,
) -> Option<Vec<u8>> {
    let dropped_count = {
        let mut state = consumer_shared.state.lock().unwrap();
        if state.dropped_count > 0 {
            let count = state.dropped_count;
            state.dropped_count = 0;
            Some(count)
        } else {
            None
        }
    };

    if let Some(count) = dropped_count {
        let mut bridge_state = bridge_shared.state.lock().unwrap();
        let envelope = ProviderEnvelope {
            version: 1,
            seq: take_seq(&mut bridge_state),
            message: ProviderMessage::DroppedEvents { count },
        };
        return match bincode::serialize(&envelope) {
            Ok(encoded) => Some(encoded),
            Err(err) => {
                log::warn!("provider bridge failed to serialize dropped event: {}", err);
                None
            }
        };
    }

    let mut state = consumer_shared.state.lock().unwrap();
    let queued = state.queue.pop_front()?;
    state.queued_bytes = state.queued_bytes.saturating_sub(queued.encoded.len());
    Some(queued.encoded)
}

fn prune_disconnected_consumers(shared: &Arc<BridgeShared>) {
    let removed = {
        let mut state = shared.state.lock().unwrap();
        let mut idx = 0;
        let mut removed = Vec::new();

        while idx < state.consumers.len() {
            let is_connected = state.consumers[idx].shared.state.lock().unwrap().connected;
            if is_connected {
                idx += 1;
                continue;
            }
            removed.push(state.consumers.swap_remove(idx));
        }

        state.connected = !state.consumers.is_empty();
        removed
    };

    for mut consumer in removed {
        if let Some(handle) = consumer.thread.take() {
            let _ = handle.join();
        }
        log::info!(
            "provider bridge consumer disconnected (remaining: {})",
            shared.state.lock().unwrap().consumers.len()
        );
    }
}

fn enqueue_backlog(config: &ProviderBridgeConfig, state: &mut BridgeState, encoded: Vec<u8>) {
    enqueue_into_queue(
        config.overflow_policy,
        &mut state.backlog,
        &mut state.backlog_bytes,
        &mut state.backlog_dropped_count,
        &mut state.backlog_dropped_total,
        state.queue_max_events,
        state.queue_max_bytes,
        encoded,
    );
}

fn enqueue_consumer_frame(
    config: &ProviderBridgeConfig,
    consumer_shared: &Arc<ConsumerShared>,
    encoded: Vec<u8>,
) {
    let mut state = consumer_shared.state.lock().unwrap();
    if !state.connected || state.shutdown {
        return;
    }
    enqueue_consumer_state(config.overflow_policy, &mut state, encoded);
    consumer_shared.condvar.notify_one();
}

fn enqueue_consumer_state(
    overflow_policy: OverflowPolicy,
    state: &mut ConsumerState,
    encoded: Vec<u8>,
) {
    let queue_max_events = state.queue_max_events;
    let queue_max_bytes = state.queue_max_bytes;
    if encoded.len() > queue_max_bytes {
        state.dropped_count = state.dropped_count.saturating_add(1);
        state.dropped_total = state.dropped_total.saturating_add(1);
        return;
    }

    while state.queue.len() >= queue_max_events
        || state.queued_bytes.saturating_add(encoded.len()) > queue_max_bytes
    {
        match overflow_policy {
            OverflowPolicy::DropNewest => {
                state.dropped_count = state.dropped_count.saturating_add(1);
                state.dropped_total = state.dropped_total.saturating_add(1);
                return;
            }
            OverflowPolicy::DropOldest => {
                if let Some(old) = state.queue.pop_front() {
                    state.queued_bytes = state.queued_bytes.saturating_sub(old.encoded.len());
                    state.dropped_count = state.dropped_count.saturating_add(1);
                    state.dropped_total = state.dropped_total.saturating_add(1);
                } else {
                    state.dropped_count = state.dropped_count.saturating_add(1);
                    state.dropped_total = state.dropped_total.saturating_add(1);
                    return;
                }
            }
        }
    }

    state.queued_bytes += encoded.len();
    state.queue.push_back(QueuedEnvelope { encoded });
}

fn enqueue_into_queue(
    overflow_policy: OverflowPolicy,
    queue: &mut VecDeque<QueuedEnvelope>,
    queued_bytes: &mut usize,
    dropped_count: &mut u64,
    dropped_total: &mut u64,
    queue_max_events: usize,
    queue_max_bytes: usize,
    encoded: Vec<u8>,
) {
    if encoded.len() > queue_max_bytes {
        *dropped_count = dropped_count.saturating_add(1);
        *dropped_total = dropped_total.saturating_add(1);
        return;
    }

    while queue.len() >= queue_max_events
        || queued_bytes.saturating_add(encoded.len()) > queue_max_bytes
    {
        match overflow_policy {
            OverflowPolicy::DropNewest => {
                *dropped_count = dropped_count.saturating_add(1);
                *dropped_total = dropped_total.saturating_add(1);
                return;
            }
            OverflowPolicy::DropOldest => {
                if let Some(old) = queue.pop_front() {
                    *queued_bytes = queued_bytes.saturating_sub(old.encoded.len());
                    *dropped_count = dropped_count.saturating_add(1);
                    *dropped_total = dropped_total.saturating_add(1);
                } else {
                    *dropped_count = dropped_count.saturating_add(1);
                    *dropped_total = dropped_total.saturating_add(1);
                    return;
                }
            }
        }
    }

    *queued_bytes += encoded.len();
    queue.push_back(QueuedEnvelope { encoded });
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
        std::thread::sleep(Duration::from_millis(200));

        bridge.emit_event("PreIngress", "hook-x".into(), "packet".into(), vec![10, 20]);

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

    #[test]
    fn consumer_disconnect_does_not_block_other_consumers() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = ProviderBridge::start(ProviderBridgeConfig {
            enabled: true,
            socket_path: socket_path.clone(),
            queue_max_events: 64,
            queue_max_bytes: 65536,
            overflow_policy: OverflowPolicy::DropNewest,
            node_instance: "node-c".into(),
        })
        .unwrap();

        let mut stream_a = UnixStream::connect(&socket_path).unwrap();
        wait_for_consumer(&bridge);
        let stream_b = UnixStream::connect(&socket_path).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        drop(stream_b);

        bridge.emit_event(
            "PreIngress",
            "hook-y".into(),
            "packet".into(),
            vec![7, 8, 9],
        );

        let env_a = read_frame(&mut stream_a);
        match env_a.message {
            ProviderMessage::Event(evt) => assert_eq!(evt.payload, vec![7, 8, 9]),
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[test]
    fn stats_expose_queue_depth_drop_totals_and_disconnects() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("provider.sock");
        let bridge = ProviderBridge::start(ProviderBridgeConfig {
            enabled: true,
            socket_path: socket_path.clone(),
            queue_max_events: 1,
            queue_max_bytes: 4096,
            overflow_policy: OverflowPolicy::DropNewest,
            node_instance: "node-d".into(),
        })
        .unwrap();

        bridge.emit_event("PreIngress", "hook-z".into(), "packet".into(), vec![1]);
        bridge.emit_event("PreIngress", "hook-z".into(), "packet".into(), vec![2]);

        let stats = bridge.stats();
        assert_eq!(stats.consumer_count, 0);
        assert_eq!(stats.total_disconnect_count, 0);
        assert_eq!(stats.backlog_len, 1);
        assert!(stats.backlog_dropped_total >= 1);
        assert!(stats.backlog_dropped_pending >= 1);

        let mut stream_a = UnixStream::connect(&socket_path).unwrap();
        wait_for_consumer(&bridge);
        let stream_b = UnixStream::connect(&socket_path).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let stats = bridge.stats();
        assert_eq!(stats.consumer_count, 2);
        assert_eq!(stats.total_disconnect_count, 0);
        assert!(stats.consumers.iter().all(|c| c.queue_len <= 1));
        assert!(
            stats
                .consumers
                .iter()
                .all(|c| c.dropped_pending <= c.dropped_total),
            "pending drops should never exceed total drops: {:?}",
            stats.consumers
        );

        drop(stream_b);
        bridge.emit_event("PreIngress", "hook-z".into(), "packet".into(), vec![3]);
        let _ = read_frame(&mut stream_a);
        std::thread::sleep(Duration::from_millis(200));

        let stats = bridge.stats();
        assert!(stats.total_disconnect_count >= 1);
    }
}
