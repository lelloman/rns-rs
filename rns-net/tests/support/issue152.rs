//! Regression: actual TCP, encryption, routing and receiver callbacks,
//! with a controlled pause at the sender's concrete writer (no injected drops).
use super::*;
use rns_net::interface::{
    registry::InterfaceRegistry, tcp::TcpClientFactory, InterfaceConfigData, InterfaceFactory,
    StartContext, StartResult, Writer,
};
use std::sync::atomic::{AtomicBool, Ordering};

type SendCompletion<'a> = futures::future::LocalBoxFuture<'a, Result<(), rns_net::LinkSendError>>;

struct PausedTcpFactory {
    armed: Arc<AtomicBool>,
    entered: mpsc::Sender<()>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

struct PausedWriter {
    inner: Box<dyn Writer>,
    armed: Arc<AtomicBool>,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Writer for PausedWriter {
    fn send_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.send(()).unwrap();
            // Also unblocks on sender drop if the test panics.
            let _ = self.release.recv_timeout(Duration::from_secs(30));
        }
        // Model a slow interface even after release, so the queued burst does
        // not overflow unrelated downstream ingress/relay queues in the control.
        std::thread::sleep(Duration::from_millis(2));
        self.inner.send_frame(data)
    }
}

impl InterfaceFactory for PausedTcpFactory {
    fn type_name(&self) -> &str {
        "TCPClientInterface"
    }

    fn parse_config(
        &self,
        name: &str,
        id: InterfaceId,
        params: &std::collections::HashMap<String, String>,
    ) -> Result<Box<dyn InterfaceConfigData>, String> {
        TcpClientFactory.parse_config(name, id, params)
    }

    fn start(
        &self,
        config: Box<dyn InterfaceConfigData>,
        ctx: StartContext,
    ) -> std::io::Result<StartResult> {
        match TcpClientFactory.start(config, ctx)? {
            StartResult::Simple {
                id,
                info,
                writer,
                interface_type_name,
            } => Ok(StartResult::Simple {
                id,
                info,
                interface_type_name,
                writer: Box::new(PausedWriter {
                    inner: writer,
                    armed: self.armed.clone(),
                    entered: self.entered.clone(),
                    release: self.release.lock().unwrap().take().unwrap(),
                }),
            }),
            _ => panic!("TCP client factory did not return a simple interface"),
        }
    }
}

#[test]
fn link_burst_survives_writer_backpressure() {
    run_burst(false);
}

#[test]
fn async_link_burst_survives_writer_backpressure() {
    run_burst(true);
}

fn run_burst(async_api: bool) {
    use futures::FutureExt;
    let queue_capacity = rns_net::interface::DEFAULT_ASYNC_WRITER_QUEUE_CAPACITY;
    const PACKETS: u32 = 4096;
    const PAYLOAD_SIZE: usize = 256;
    const CONTEXT: u8 = 0;
    let port = find_free_port();
    let bob_id = Identity::new(&mut OsRng);
    let bob_dest = Destination::single_in(APP_NAME, &["issue152"], IdentityHash(*bob_id.hash()));
    let (bob_tx, bob_rx) = mpsc::channel();
    let bob = RnsNode::start(
        NodeConfig {
            // Isolate sender egress saturation from receiver ingress limits.
            driver_event_queue_capacity: 8192,
            identity: Some(Identity::from_private_key(
                &bob_id.get_private_key().unwrap(),
            )),
            interfaces: vec![InterfaceConfig {
                name: "Bob TCP".into(),
                type_name: "TCPServerInterface".into(),
                config_data: Box::new(TcpServerConfig {
                    name: "Bob TCP".into(),
                    listen_ip: "127.0.0.1".into(),
                    listen_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: Default::default(),
                ifac: None,
                discovery: None,
            }],
            ..Default::default()
        },
        Box::new(TestCallbacks::new(bob_tx)),
    )
    .unwrap();
    bob.register_destination_with_proof(&bob_dest, Some(bob_id.get_private_key().unwrap()))
        .unwrap();
    let (prv, public) = extract_sig_keys(&bob_id);
    bob.register_link_destination(bob_dest.hash.0, prv, public, 0)
        .unwrap();
    bob.query(QueryRequest::InterfaceStats).unwrap();

    let armed = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut registry = InterfaceRegistry::with_builtins();
    registry.register(Box::new(PausedTcpFactory {
        armed: armed.clone(),
        entered: entered_tx,
        release: Mutex::new(Some(release_rx)),
    }));
    let (alice_tx, alice_rx) = mpsc::channel();
    let alice = RnsNode::start(
        NodeConfig {
            interface_writer_queue_capacity: queue_capacity,
            driver_event_queue_capacity: 8192,
            identity: Some(Identity::new(&mut OsRng)),
            registry: Some(registry),
            interfaces: vec![InterfaceConfig {
                name: "Alice paused TCP".into(),
                type_name: "TCPClientInterface".into(),
                config_data: Box::new(TcpClientConfig {
                    name: "Alice paused TCP".into(),
                    target_port: port,
                    interface_id: InterfaceId(1),
                    ..Default::default()
                }),
                mode: MODE_FULL,
                gravity: 0,
                recursive_prs: false,
                announces_from_internal: true,
                announces_to_internal: None,
                ingress_control: Default::default(),
                ifac: None,
                discovery: None,
            }],
            ..Default::default()
        },
        Box::new(TestCallbacks::new(alice_tx)),
    )
    .unwrap();
    std::thread::sleep(SETTLE);
    announce_with_retry(&bob, &bob_dest, &bob_id, None, &alice_rx).unwrap();
    let link = alice.create_link(bob_dest.hash.0, public).unwrap();
    wait_for_link_established(&alice_rx, TIMEOUT).unwrap();
    wait_for_link_established(&bob_rx, TIMEOUT).unwrap();

    // A paced control establishes that this Link and payload size work.
    for sequence in 0..8u32 {
        let mut payload = vec![0x55; PAYLOAD_SIZE];
        payload[..4].copy_from_slice(&sequence.to_be_bytes());
        futures::executor::block_on(alice.send_on_link(link, payload.clone(), CONTEXT)).unwrap();
        let (received_link, context, received) = wait_for_link_data(&bob_rx, TIMEOUT).unwrap();
        assert_eq!((received_link, context, received), (link, CONTEXT, payload));
    }

    armed.store(true, Ordering::SeqCst);
    let mut receipts: Vec<SendCompletion<'_>> = Vec::new();
    for sequence in 0..PACKETS {
        let mut payload = vec![0xAA; PAYLOAD_SIZE];
        payload[..4].copy_from_slice(&sequence.to_be_bytes());
        let mut receipt: SendCompletion<'_> = if async_api {
            Box::pin(alice.send_on_link(link, payload, CONTEXT))
        } else {
            Box::pin(alice.try_send_on_link(link, payload, CONTEXT).unwrap())
        };
        assert!(receipt.as_mut().now_or_never().is_none());
        receipts.push(receipt);
        if sequence == 0 {
            entered_rx
                .recv_timeout(TIMEOUT)
                .expect("writer did not pause");
        }
    }
    // FIFO control-event barrier: all SendOnLink events have been dispatched.
    alice.query(QueryRequest::InterfaceStats).unwrap();
    // Admission must never be confused with transmission completion.
    for receipt in &mut receipts {
        assert!(
            (&mut *receipt).now_or_never().is_none(),
            "receipt completed while writer was paused"
        );
    }
    release_tx.send(()).unwrap();
    // Let the retry timer expire before sending the end marker.
    std::thread::sleep(Duration::from_secs(1));
    let marker = b"issue152-end".to_vec();
    let marker_receipt = alice
        .try_send_on_link(link, marker.clone(), CONTEXT)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut sequences = Vec::new();
    let mut marker_received = false;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Some((received_link, context, payload)) = wait_for_link_data(&bob_rx, remaining) else {
            break;
        };
        assert_eq!((received_link, context), (link, CONTEXT));
        if payload == marker {
            marker_received = true;
            break;
        }
        assert_eq!(payload.len(), PAYLOAD_SIZE);
        assert!(payload[4..].iter().all(|byte| *byte == 0xAA));
        sequences.push(u32::from_be_bytes(payload[..4].try_into().unwrap()));
    }
    eprintln!("issue152: queue capacity={queue_capacity}, {PACKETS} sends returned Ok, {} burst packets received, end marker received={marker_received}", sequences.len());
    for receipt in receipts {
        futures::executor::block_on(receipt).unwrap();
    }
    marker_receipt.wait().unwrap();
    alice.shutdown();
    bob.shutdown();
    assert!(
        marker_received,
        "Link did not recover after releasing writer"
    );
    assert_eq!(
        sequences.len(),
        PACKETS as usize,
        "successful sends disappeared before TCP transmission"
    );
    assert_eq!(sequences, (0..PACKETS).collect::<Vec<_>>());
}
