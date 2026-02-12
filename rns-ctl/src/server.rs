use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use crate::api::{handle_request, NodeHandle};
use crate::auth::check_ws_auth;
use crate::config::CtlConfig;
use crate::http::{parse_request, write_response};
use crate::state::{SharedState, WsBroadcast, WsEvent};
use crate::ws;

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
    pub config: CtlConfig,
    #[cfg(feature = "tls")]
    pub tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
}

/// Run the HTTP/WS server. Blocks on the accept loop.
pub fn run_server(addr: SocketAddr, ctx: std::sync::Arc<ServerContext>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;

    #[cfg(feature = "tls")]
    let scheme = if ctx.tls_config.is_some() { "https" } else { "http" };
    #[cfg(not(feature = "tls"))]
    let scheme = "http";

    log::info!("Listening on {}://{}", scheme, addr);

    for stream in listener.incoming() {
        match stream {
            Ok(tcp_stream) => {
                let ctx = ctx.clone();
                std::thread::Builder::new()
                    .name("rns-ctl-conn".into())
                    .spawn(move || {
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

/// Wrap a TCP stream in TLS if configured, otherwise return plain.
fn wrap_stream(tcp_stream: TcpStream, ctx: &ServerContext) -> io::Result<ConnStream> {
    #[cfg(feature = "tls")]
    {
        if let Some(ref tls_config) = ctx.tls_config {
            let server_conn = rustls::ServerConnection::new(tls_config.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TLS error: {}", e)))?;
            return Ok(ConnStream::Tls(rustls::StreamOwned::new(server_conn, tcp_stream)));
        }
    }
    let _ = ctx; // suppress unused warning when tls feature is off
    Ok(ConnStream::Plain(tcp_stream))
}

fn handle_connection(mut stream: ConnStream, ctx: &ServerContext) -> io::Result<()> {
    // Set a read timeout so we don't block forever on malformed requests
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let req = parse_request(&mut stream)?;

    if ws::is_upgrade(&req) {
        handle_ws_connection(stream, &req, ctx)
    } else {
        let response = handle_request(&req, &ctx.node, &ctx.state, &ctx.config);
        write_response(&mut stream, &response)
    }
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
        let mut senders = ctx.ws_broadcast.lock().unwrap();
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
                let _ = ws::write_text_frame(
                    stream,
                    &serde_json::json!({"type": "pong"}).to_string(),
                );
            }
            _ => {}
        }
    }
}
