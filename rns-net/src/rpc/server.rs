//! The RPC server: its listeners and the exchange on each connection.

use super::*;

/// RPC server that listens for incoming connections and handles queries.
pub struct RpcServer {
    shutdown: Arc<AtomicBool>,
    wake: ListenerWake,
    thread: Option<thread::JoinHandle<()>>,
}

impl RpcServer {
    /// Start the RPC server on the given address.
    pub fn start(addr: &RpcAddr, auth_key: [u8; 32], event_tx: EventSender) -> io::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();

        let listener = match addr {
            RpcAddr::Tcp(host, port) => {
                let l = TcpListener::bind((host.as_str(), *port))?;
                // Non-blocking: the thread waits in its poller, then accepts.
                l.set_nonblocking(true)?;
                l
            }
            RpcAddr::Local { port, .. } => {
                let l = TcpListener::bind(("127.0.0.1", *port))?;
                // Non-blocking: the thread waits in its poller, then accepts.
                l.set_nonblocking(true)?;
                l
            }
        };
        let (listener, wake) = Listener::new(listener)?;

        let thread = thread::Builder::new()
            .name("rpc-server".into())
            .spawn(move || {
                rpc_server_loop(listener, auth_key, event_tx, shutdown2);
            })
            .map_err(io::Error::other)?;

        Ok(RpcServer {
            shutdown,
            wake,
            thread: Some(thread),
        })
    }

    /// Listen on the abstract socket used by Python Reticulum on Linux.
    #[cfg(target_os = "linux")]
    pub fn start_abstract_unix(
        instance_name: &str,
        auth_key: [u8; 32],
        event_tx: EventSender,
    ) -> io::Result<Self> {
        let listener = bind_abstract_unix(instance_name)?;
        listener.set_nonblocking(true)?;
        let (listener, wake) = Listener::new(listener)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();
        let thread = thread::Builder::new()
            .name("rpc-unix-server".into())
            .spawn(move || rpc_server_loop_unix(listener, auth_key, event_tx, shutdown2))
            .map_err(io::Error::other)?;
        Ok(Self {
            shutdown,
            wake,
            thread: Some(thread),
        })
    }

    /// Stop the RPC server.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.wake.wake();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Bind the abstract socket used by Python Reticulum on Linux.
#[cfg(target_os = "linux")]
pub(crate) fn bind_abstract_unix(instance_name: &str) -> io::Result<UnixListener> {
    let addr = SocketAddr::from_abstract_name(format!("rns/{instance_name}/rpc"))?;
    UnixListener::bind_addr(&addr)
}

#[cfg(target_os = "linux")]
pub(super) fn rpc_server_loop_unix(
    mut listener: Listener<UnixListener>,
    auth_key: [u8; 32],
    event_tx: EventSender,
    shutdown: Arc<AtomicBool>,
) {
    let mut workers = Vec::new();
    loop {
        reap_finished_rpc_workers(&mut workers);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match listener.get().accept() {
            Ok((stream, _)) => {
                if workers.len() >= MAX_CONCURRENT_RPC_CONNECTIONS {
                    log::warn!("rejecting Unix RPC connection: {MAX_CONCURRENT_RPC_CONNECTIONS} handlers already active");
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                let worker_event_tx = event_tx.clone();
                match thread::Builder::new()
                    .name("rpc-unix-client".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &auth_key, &worker_event_tx) {
                            log::debug!("Unix RPC connection error: {e}");
                        }
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(e) => log::error!("failed to start Unix RPC connection handler: {e}"),
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = listener.wait() {
                    log::error!("Unix RPC wait error: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
            Err(e) => {
                log::error!("Unix RPC accept error: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) fn rpc_server_loop(
    mut listener: Listener<TcpListener>,
    auth_key: [u8; 32],
    event_tx: EventSender,
    shutdown: Arc<AtomicBool>,
) {
    let mut workers = Vec::new();

    loop {
        reap_finished_rpc_workers(&mut workers);

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.get().accept() {
            Ok((stream, addr)) => {
                if workers.len() >= MAX_CONCURRENT_RPC_CONNECTIONS {
                    log::warn!(
                        "rejecting RPC connection from {addr}: {MAX_CONCURRENT_RPC_CONNECTIONS} handlers already active"
                    );
                    continue;
                }

                // Set blocking for this connection
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));

                let worker_event_tx = event_tx.clone();
                match thread::Builder::new()
                    .name("rpc-client".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &auth_key, &worker_event_tx) {
                            log::debug!("RPC connection error: {e}");
                        }
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(e) => log::error!("failed to start RPC connection handler: {e}"),
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(e) = listener.wait() {
                    log::error!("RPC wait error: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
            Err(e) => {
                log::error!("RPC accept error: {}", e);
                thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    for worker in workers {
        let _ = worker.join();
    }
}

pub(super) fn reap_finished_rpc_workers(workers: &mut Vec<thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

pub(super) fn handle_connection<S: Read + Write>(
    mut stream: S,
    auth_key: &[u8; 32],
    event_tx: &EventSender,
) -> io::Result<()> {
    // Authentication: send challenge, verify response
    server_auth(&mut stream, auth_key)?;
    // multiprocessing.connection authenticates both peers before requests.
    answer_challenge(&mut stream, auth_key)?;

    // Read request.
    let request_bytes = recv_bytes(&mut stream)?;
    let response_bytes = answer_request(&request_bytes, &mut event_tx.clone())?;
    send_bytes(&mut stream, &response_bytes)?;

    Ok(())
}

/// Decode a request, have `driver` answer it, and encode the answer in the
/// request's own codec.
pub(crate) fn answer_request(
    request_bytes: &[u8],
    driver: &mut dyn RpcDriver,
) -> io::Result<Vec<u8>> {
    let (request, codec) = decode_rpc_payload(request_bytes)?;
    let response = handle_rpc_request(&request, driver)?;
    Ok(encode_rpc_payload(&response, codec))
}
