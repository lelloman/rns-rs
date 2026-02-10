use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use crate::api::{handle_request, NodeHandle};
use crate::auth::check_ws_auth;
use crate::config::CtlConfig;
use crate::http::{parse_request, write_response};
use crate::state::{SharedState, WsBroadcast, WsEvent};
use crate::ws;

/// All context needed by connection handlers.
pub struct ServerContext {
    pub node: NodeHandle,
    pub state: SharedState,
    pub ws_broadcast: WsBroadcast,
    pub config: CtlConfig,
}

/// Run the HTTP/WS server. Blocks on the accept loop.
pub fn run_server(addr: SocketAddr, ctx: std::sync::Arc<ServerContext>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    log::info!("Listening on http://{}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let ctx = ctx.clone();
                thread::Builder::new()
                    .name("rns-ctl-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &ctx) {
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

fn handle_connection(mut stream: TcpStream, ctx: &ServerContext) -> io::Result<()> {
    // Set a read timeout so we don't block forever on malformed requests
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;

    let req = parse_request(&mut stream)?;

    if ws::is_upgrade(&req) {
        handle_ws_connection(stream, &req, ctx)
    } else {
        let response = handle_request(&req, &ctx.node, &ctx.state, &ctx.config);
        write_response(&mut stream, &response)
    }
}

fn handle_ws_connection(
    mut stream: TcpStream,
    req: &crate::http::HttpRequest,
    ctx: &ServerContext,
) -> io::Result<()> {
    // Auth check on the upgrade request
    if let Err(resp) = check_ws_auth(&req.query, &ctx.config) {
        return write_response(&mut stream, &resp);
    }

    // Complete handshake
    ws::do_handshake(&mut stream, req)?;

    // Remove the read timeout for the long-lived WS connection
    stream.set_read_timeout(None)?;

    // Create broadcast channel for this client
    let (event_tx, event_rx) = mpsc::channel::<WsEvent>();

    // Register in broadcast list
    {
        let mut senders = ctx.ws_broadcast.lock().unwrap();
        senders.push(event_tx);
    }

    // Subscribed topics for this client
    let topics = std::sync::Arc::new(std::sync::Mutex::new(HashSet::<String>::new()));
    let topics_writer = topics.clone();

    // Writer thread: sends events to client
    let mut write_stream = stream.try_clone()?;
    let writer_handle = thread::Builder::new()
        .name("rns-ctl-ws-writer".into())
        .spawn(move || {
            while let Ok(event) = event_rx.recv() {
                let subs = topics_writer.lock().unwrap();
                if !subs.contains(event.topic) {
                    continue;
                }
                drop(subs);
                let json = event.to_json();
                if ws::write_text_frame(&mut write_stream, &json).is_err() {
                    break;
                }
            }
        })?;

    // Reader loop: handle subscribe/unsubscribe/ping from client
    // Use separate clones: one for run_ws_loop's pong replies, one for text-level pong
    let mut read_stream = stream.try_clone()?;
    let mut ctrl_stream = stream.try_clone()?;
    let pong_stream = std::sync::Mutex::new(stream);

    ws::run_ws_loop(&mut read_stream, &mut ctrl_stream, |text| {
        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) {
            match msg["type"].as_str() {
                Some("subscribe") => {
                    if let Some(arr) = msg["topics"].as_array() {
                        let mut subs = topics.lock().unwrap();
                        for t in arr {
                            if let Some(s) = t.as_str() {
                                subs.insert(s.to_string());
                            }
                        }
                    }
                }
                Some("unsubscribe") => {
                    if let Some(arr) = msg["topics"].as_array() {
                        let mut subs = topics.lock().unwrap();
                        for t in arr {
                            if let Some(s) = t.as_str() {
                                subs.remove(s);
                            }
                        }
                    }
                }
                Some("ping") => {
                    if let Ok(mut s) = pong_stream.lock() {
                        let _ = ws::write_text_frame(
                            &mut *s,
                            &serde_json::json!({"type": "pong"}).to_string(),
                        );
                    }
                }
                _ => {}
            }
        }
    })?;

    // Clean up: writer thread will exit when event_rx is dropped
    drop(writer_handle);
    Ok(())
}
