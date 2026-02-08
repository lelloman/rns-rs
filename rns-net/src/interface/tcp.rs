//! TCP client interface with HDLC framing.
//!
//! Matches Python `TCPClientInterface` from `TCPInterface.py`.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

use rns_core::transport::types::InterfaceId;

use crate::event::{Event, EventSender};
use crate::hdlc;
use crate::interface::Writer;

/// Configuration for a TCP client interface.
#[derive(Debug, Clone)]
pub struct TcpClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub interface_id: InterfaceId,
    pub reconnect_wait: Duration,
    pub max_reconnect_tries: Option<u32>,
    pub connect_timeout: Duration,
}

impl Default for TcpClientConfig {
    fn default() -> Self {
        TcpClientConfig {
            name: String::new(),
            target_host: "127.0.0.1".into(),
            target_port: 4242,
            interface_id: InterfaceId(0),
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: None,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

/// Writer that sends HDLC-framed data over a TCP stream.
struct TcpWriter {
    stream: TcpStream,
}

impl Writer for TcpWriter {
    fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(&hdlc::frame(data))
    }
}

/// Set TCP keepalive and timeout socket options (Linux).
fn set_socket_options(stream: &TcpStream) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    unsafe {
        // TCP_NODELAY = 1
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        // SO_KEEPALIVE = 1
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }

        // Linux-specific keepalive tuning and user timeout
        #[cfg(target_os = "linux")]
        {
            // TCP_KEEPIDLE = 5
            let idle: libc::c_int = 5;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &idle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_KEEPINTVL = 2
            let intvl: libc::c_int = 2;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &intvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_KEEPCNT = 12
            let cnt: libc::c_int = 12;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                &cnt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // TCP_USER_TIMEOUT = 24000 ms
            let timeout: libc::c_int = 24_000;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Try to connect to the target host:port with timeout.
fn try_connect(config: &TcpClientConfig) -> io::Result<TcpStream> {
    let addr_str = format!("{}:{}", config.target_host, config.target_port);
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved"))?;

    let stream = TcpStream::connect_timeout(&addr, config.connect_timeout)?;
    set_socket_options(&stream)?;
    Ok(stream)
}

/// Connect and start the reader thread. Returns the writer for the driver.
pub fn start(config: TcpClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let stream = try_connect(&config)?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None));

    // Spawn reader thread
    let reader_config = config;
    let reader_tx = tx;
    thread::Builder::new()
        .name(format!("tcp-reader-{}", id.0))
        .spawn(move || {
            reader_loop(reader_stream, reader_config, reader_tx);
        })?;

    Ok(Box::new(TcpWriter { stream: writer_stream }))
}

/// Reader thread: reads from socket, HDLC-decodes, sends frames to driver.
/// On disconnect, attempts reconnection.
fn reader_loop(mut stream: TcpStream, config: TcpClientConfig, tx: EventSender) {
    let id = config.interface_id;
    let mut decoder = hdlc::Decoder::new();
    let mut buf = [0u8; 4096];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                // Connection closed by peer
                log::warn!("[{}] connection closed", config.name);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
            }
            Ok(n) => {
                for frame in decoder.feed(&buf[..n]) {
                    if tx.send(Event::Frame { interface_id: id, data: frame }).is_err() {
                        // Driver shut down
                        return;
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] read error: {}", config.name, e);
                let _ = tx.send(Event::InterfaceDown(id));
                match reconnect(&config, &tx) {
                    Some(new_stream) => {
                        stream = new_stream;
                        decoder = hdlc::Decoder::new();
                        continue;
                    }
                    None => {
                        log::error!("[{}] reconnection failed, giving up", config.name);
                        return;
                    }
                }
            }
        }
    }
}

/// Attempt to reconnect with retry logic. Returns the new reader stream on success.
/// Sends the new writer to the driver via InterfaceUp event.
fn reconnect(config: &TcpClientConfig, tx: &EventSender) -> Option<TcpStream> {
    let mut attempts = 0u32;
    loop {
        thread::sleep(config.reconnect_wait);
        attempts += 1;

        if let Some(max) = config.max_reconnect_tries {
            if attempts > max {
                let _ = tx.send(Event::InterfaceDown(config.interface_id));
                return None;
            }
        }

        log::info!(
            "[{}] reconnect attempt {} ...",
            config.name,
            attempts
        );

        match try_connect(config) {
            Ok(new_stream) => {
                // Clone the stream: one for the reader, one for the writer
                let writer_stream = match new_stream.try_clone() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("[{}] failed to clone stream: {}", config.name, e);
                        continue;
                    }
                };
                log::info!("[{}] reconnected", config.name);
                // Send new writer to the driver so it can replace the stale one
                let new_writer: Box<dyn Writer> = Box::new(TcpWriter { stream: writer_stream });
                let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(new_writer)));
                return Some(new_stream);
            }
            Err(e) => {
                log::warn!("[{}] reconnect failed: {}", config.name, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    fn find_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn make_config(port: u16) -> TcpClientConfig {
        TcpClientConfig {
            name: format!("test-tcp-{}", port),
            target_host: "127.0.0.1".into(),
            target_port: port,
            interface_id: InterfaceId(1),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(2),
            connect_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn connect_to_listener() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        // Accept the connection
        let _server_stream = listener.accept().unwrap();

        // Should receive InterfaceUp event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _)));
    }

    #[test]
    fn receive_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain the InterfaceUp event
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send an HDLC frame from server (>= 19 bytes payload)
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        server_stream.write_all(&framed).unwrap();

        // Should receive Frame event
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { interface_id, data } => {
                assert_eq!(interface_id, InterfaceId(1));
                assert_eq!(data, payload);
            }
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn send_frame() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, _rx) = mpsc::channel();

        let config = make_config(port);
        let mut writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send a frame via writer
        let payload: Vec<u8> = (0..24).collect();
        writer.send_frame(&payload).unwrap();

        // Read from server side
        let mut buf = [0u8; 256];
        let n = server_stream.read(&mut buf).unwrap();
        let expected = hdlc::frame(&payload);
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn multiple_frames() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send multiple frames
        let payloads: Vec<Vec<u8>> = (0..3).map(|i| (0..24).map(|j| j + i * 50).collect()).collect();
        for p in &payloads {
            server_stream.write_all(&hdlc::frame(p)).unwrap();
        }

        // Should receive all frames
        for expected in &payloads {
            let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            match event {
                Event::Frame { data, .. } => assert_eq!(&data, expected),
                other => panic!("expected Frame, got {:?}", other),
            }
        }
    }

    #[test]
    fn split_across_reads() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        let (mut server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        // Send frame in two parts
        let payload: Vec<u8> = (0..32).collect();
        let framed = hdlc::frame(&payload);
        let mid = framed.len() / 2;

        server_stream.write_all(&framed[..mid]).unwrap();
        server_stream.flush().unwrap();
        thread::sleep(Duration::from_millis(50));
        server_stream.write_all(&framed[mid..]).unwrap();
        server_stream.flush().unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Frame { data, .. } => assert_eq!(data, payload),
            other => panic!("expected Frame, got {:?}", other),
        }
    }

    #[test]
    fn reconnect_on_close() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        listener.set_nonblocking(false).unwrap();
        let (tx, rx) = mpsc::channel();

        let config = make_config(port);
        let _writer = start(config, tx).unwrap();

        // Accept first connection and immediately close it
        let (server_stream, _) = listener.accept().unwrap();

        // Drain InterfaceUp
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        drop(server_stream);

        // Should get InterfaceDown
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceDown(InterfaceId(1))));

        // Accept the reconnection
        let _server_stream2 = listener.accept().unwrap();

        // Should get InterfaceUp again
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _)));
    }

    #[test]
    fn socket_options() {
        let port = find_free_port();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();

        let stream = try_connect(&make_config(port)).unwrap();
        let _server = listener.accept().unwrap();

        // Verify TCP_NODELAY is set
        let fd = stream.as_raw_fd();
        let mut val: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            );
        }
        assert_eq!(val, 1, "TCP_NODELAY should be 1");
    }

    #[test]
    fn connect_timeout() {
        // Use a non-routable address to trigger timeout
        let config = TcpClientConfig {
            name: "timeout-test".into(),
            target_host: "192.0.2.1".into(), // TEST-NET, non-routable
            target_port: 12345,
            interface_id: InterfaceId(99),
            reconnect_wait: Duration::from_millis(100),
            max_reconnect_tries: Some(0),
            connect_timeout: Duration::from_millis(500),
        };

        let start_time = std::time::Instant::now();
        let result = try_connect(&config);
        let elapsed = start_time.elapsed();

        assert!(result.is_err());
        // Should timeout roughly around 500ms, definitely under 5s
        assert!(elapsed < Duration::from_secs(5));
    }
}
