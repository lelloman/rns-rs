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
    /// Linux network interface to bind the socket to (e.g. "usb0").
    pub device: Option<String>,
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
            device: None,
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

    #[cfg(target_os = "linux")]
    let stream = if let Some(ref device) = config.device {
        connect_with_device(&addr, device, config.connect_timeout)?
    } else {
        TcpStream::connect_timeout(&addr, config.connect_timeout)?
    };
    #[cfg(not(target_os = "linux"))]
    let stream = TcpStream::connect_timeout(&addr, config.connect_timeout)?;
    set_socket_options(&stream)?;
    Ok(stream)
}

/// Create a TCP socket, bind it to a network device, then connect with timeout.
#[cfg(target_os = "linux")]
fn connect_with_device(
    addr: &std::net::SocketAddr,
    device: &str,
    timeout: Duration,
) -> io::Result<TcpStream> {
    use std::os::unix::io::{FromRawFd, RawFd};

    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd: RawFd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Ensure the fd is closed on error paths
    let stream = unsafe { TcpStream::from_raw_fd(fd) };

    super::bind_to_device(stream.as_raw_fd(), device)?;

    // Set non-blocking for connect-with-timeout
    stream.set_nonblocking(true)?;

    let (sockaddr, socklen) = socket_addr_to_raw(addr);
    let ret = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            &sockaddr as *const libc::sockaddr_storage as *const libc::sockaddr,
            socklen,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
    }

    // Poll for connect completion
    let mut pollfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis() as libc::c_int;
    let poll_ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };

    if poll_ret == 0 {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
    }
    if poll_ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Check SO_ERROR
    let mut err_val: libc::c_int = 0;
    let mut err_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err_val as *mut _ as *mut libc::c_void,
            &mut err_len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if err_val != 0 {
        return Err(io::Error::from_raw_os_error(err_val));
    }

    // Set back to blocking
    stream.set_nonblocking(false)?;

    Ok(stream)
}

/// Convert a `SocketAddr` to a raw `sockaddr_storage` for `libc::connect`.
#[cfg(target_os = "linux")]
fn socket_addr_to_raw(addr: &std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        std::net::SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// Connect and start the reader thread. Returns the writer for the driver.
pub fn start(config: TcpClientConfig, tx: EventSender) -> io::Result<Box<dyn Writer>> {
    let stream = try_connect(&config)?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;

    let id = config.interface_id;
    // Initial connect: writer is None because it's returned directly to the caller
    let _ = tx.send(Event::InterfaceUp(id, None, None));

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
                let _ = tx.send(Event::InterfaceUp(config.interface_id, Some(new_writer), None));
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
            device: None,
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
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _, _)));
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
        assert!(matches!(event, Event::InterfaceUp(InterfaceId(1), _, _)));
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
            device: None,
        };

        let start_time = std::time::Instant::now();
        let result = try_connect(&config);
        let elapsed = start_time.elapsed();

        assert!(result.is_err());
        // Should timeout roughly around 500ms, definitely under 5s
        assert!(elapsed < Duration::from_secs(5));
    }
}
