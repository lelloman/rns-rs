use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::api::{check_request_auth, handle_request, NodeHandle};
use crate::auth::check_ws_auth;
use crate::http::{
    parse_request_head, read_body, request_body_length, write_response, HttpResponse,
};
use crate::state::{
    lock_ws_broadcast, ControlPlaneConfigHandle, SharedState, WsBroadcast, WsEvent,
};
use crate::ws;

/// Maximum number of connections served at once, WebSocket sessions included.
///
/// Each connection runs on its own thread. The control plane serves a local
/// UI, CLI and a handful of automation clients, so 64 leaves ample room while
/// keeping the thread count bounded. Connections accepted beyond this get a
/// `503` and are closed without spawning a thread.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Write timeout for the short `503` sent from the accept loop.
const REFUSAL_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Holds one connection slot and releases it when dropped.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()
            .map(|_| ConnectionSlot(active.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A connection stream that is either plain TCP or TLS-wrapped.
pub(crate) enum ConnStream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(rustls::StreamOwned<rustls::ServerConnection, TcpStream>),
}

impl ConnStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            ConnStream::Plain(s) => s.set_read_timeout(dur),
            #[cfg(feature = "tls")]
            ConnStream::Tls(s) => s.sock.set_read_timeout(dur),
        }
    }
}

impl Read for ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ConnStream::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            ConnStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ConnStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ConnStream::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            ConnStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ConnStream::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            ConnStream::Tls(s) => s.flush(),
        }
    }
}

/// All context needed by connection handlers.
pub struct ServerContext {
    pub node: NodeHandle,
    pub state: SharedState,
    pub ws_broadcast: WsBroadcast,
    pub config: ControlPlaneConfigHandle,
    #[cfg(feature = "tls")]
    pub tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
}

/// Run the HTTP/WS server. Blocks on the accept loop.
pub fn run_server(addr: SocketAddr, ctx: std::sync::Arc<ServerContext>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    run_server_with_listener(listener, ctx)
}

/// Run the HTTP/WS server using a pre-bound listener. Blocks on the accept loop.
pub fn run_server_with_listener(
    listener: TcpListener,
    ctx: std::sync::Arc<ServerContext>,
) -> io::Result<()> {
    let addr = listener.local_addr()?;

    #[cfg(feature = "tls")]
    let scheme = if ctx.tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    #[cfg(not(feature = "tls"))]
    let scheme = "http";

    log::info!("Listening on {}://{}", scheme, addr);

    let active = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        match stream {
            Ok(tcp_stream) => {
                let Some(slot) = ConnectionSlot::acquire(&active, MAX_CONCURRENT_CONNECTIONS)
                else {
                    log::debug!(
                        "refusing connection: {} connections already active",
                        MAX_CONCURRENT_CONNECTIONS
                    );
                    refuse_connection(tcp_stream, &ctx);
                    continue;
                };
                let ctx = ctx.clone();
                std::thread::Builder::new()
                    .name("rns-ctl-conn".into())
                    .spawn(move || {
                        let _slot = slot;
                        let conn = match wrap_stream(tcp_stream, &ctx) {
                            Ok(c) => c,
                            Err(e) => {
                                log::debug!("TLS handshake error: {}", e);
                                return;
                            }
                        };
                        if let Err(e) = handle_connection(conn, &ctx) {
                            log::debug!("Connection error: {}", e);
                        }
                    })
                    .ok();
            }
            Err(e) => {
                log::warn!("Accept error: {}", e);
            }
        }
    }

    Ok(())
}

/// Answer a connection over the cap with a short `503` and close it.
/// TLS listeners close the connection without a response, since a plain-text
/// reply is not readable by a TLS client.
fn refuse_connection(mut tcp_stream: TcpStream, ctx: &ServerContext) {
    #[cfg(feature = "tls")]
    {
        if ctx.tls_config.is_some() {
            return;
        }
    }
    let _ = ctx;
    let _ = tcp_stream.set_write_timeout(Some(REFUSAL_WRITE_TIMEOUT));
    let _ = write_response(
        &mut tcp_stream,
        &HttpResponse::service_unavailable("Too many connections"),
    );
    let _ = tcp_stream.shutdown(std::net::Shutdown::Both);
}

/// Wrap a TCP stream in TLS if configured, otherwise return plain.
fn wrap_stream(tcp_stream: TcpStream, ctx: &ServerContext) -> io::Result<ConnStream> {
    #[cfg(feature = "tls")]
    {
        if let Some(ref tls_config) = ctx.tls_config {
            let server_conn = rustls::ServerConnection::new(tls_config.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {}", e)))?;
            return Ok(ConnStream::Tls(rustls::StreamOwned::new(
                server_conn,
                tcp_stream,
            )));
        }
    }
    let _ = ctx; // suppress unused warning when tls feature is off
    Ok(ConnStream::Plain(tcp_stream))
}

fn handle_connection(mut stream: ConnStream, ctx: &ServerContext) -> io::Result<()> {
    // Set a read timeout so we don't block forever on malformed requests
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Parse the head first; the body is read only after the request is
    // authenticated and its declared length is within bounds.
    let mut reader = BufReader::new(&mut stream);
    let mut req = parse_request_head(&mut reader)?;

    if ws::is_upgrade(&req) {
        drop(reader);
        return handle_ws_connection(stream, &req, ctx);
    }

    if let Err(response) = check_request_auth(&req, &ctx.config) {
        return write_response(reader.get_mut(), &response);
    }
    let len = match request_body_length(&req) {
        Ok(len) => len,
        Err(response) => return write_response(reader.get_mut(), &response),
    };
    req.body = read_body(&mut reader, len)?;
    drop(reader);

    let response = handle_request(&req, &ctx.node, &ctx.state, &ctx.config);
    write_response(&mut stream, &response)
}

fn handle_ws_connection(
    mut stream: ConnStream,
    req: &crate::http::HttpRequest,
    ctx: &ServerContext,
) -> io::Result<()> {
    // Auth check on the upgrade request
    if let Err(resp) = check_ws_auth(&req.query, &ctx.config) {
        return write_response(&mut stream, &resp);
    }

    // Complete handshake
    ws::do_handshake(&mut stream, req)?;

    // Set a short read timeout for the non-blocking event loop
    stream.set_read_timeout(Some(Duration::from_millis(50)))?;

    // Create broadcast channel for this client
    let (event_tx, event_rx) = mpsc::channel::<WsEvent>();

    // Register in broadcast list
    {
        let mut senders = lock_ws_broadcast(&ctx.ws_broadcast);
        senders.push(event_tx);
    }

    // Subscribed topics for this client (no Arc/Mutex needed — single thread)
    let mut topics = HashSet::<String>::new();
    let mut ws_buf = ws::WsBuf::new();

    loop {
        // Try to read a frame from the client
        match ws_buf.try_read_frame(&mut stream) {
            Ok(Some(frame)) => match frame.opcode {
                ws::OPCODE_TEXT => {
                    if let Ok(text) = std::str::from_utf8(&frame.payload) {
                        handle_ws_text(text, &mut topics, &mut stream);
                    }
                }
                ws::OPCODE_PING => {
                    let _ = ws::write_pong_frame(&mut stream, &frame.payload);
                }
                ws::OPCODE_CLOSE => {
                    let _ = ws::write_close_frame(&mut stream);
                    break;
                }
                _ => {}
            },
            Ok(None) => {
                // No complete frame yet — fall through to drain events
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                log::debug!("WS read error: {}", e);
                break;
            }
        }

        // Drain event channel, send matching events to client
        while let Ok(event) = event_rx.try_recv() {
            if topics.contains(event.topic) {
                let json = event.to_json();
                if ws::write_text_frame(&mut stream, &json).is_err() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn handle_ws_text(text: &str, topics: &mut HashSet<String>, stream: &mut ConnStream) {
    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) {
        match msg["type"].as_str() {
            Some("subscribe") => {
                if let Some(arr) = msg["topics"].as_array() {
                    for t in arr {
                        if let Some(s) = t.as_str() {
                            topics.insert(s.to_string());
                        }
                    }
                }
            }
            Some("unsubscribe") => {
                if let Some(arr) = msg["topics"].as_array() {
                    for t in arr {
                        if let Some(s) = t.as_str() {
                            topics.remove(s);
                        }
                    }
                }
            }
            Some("ping") => {
                let _ =
                    ws::write_text_frame(stream, &serde_json::json!({"type": "pong"}).to_string());
            }
            _ => {}
        }
    }
}
