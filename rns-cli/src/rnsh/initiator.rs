//! The initiator: connecting to a listener and relaying a command.

#![allow(unsafe_code, reason = "OS calls through libc and signal handlers")]

use super::*;

pub(super) fn initiate(opts: CliOptions) -> Result<i32, RnshError> {
    let dest_hash = parse_hash_16(
        opts.destination
            .as_deref()
            .ok_or_else(|| RnshError::Protocol("missing destination".into()))?,
    )
    .ok_or_else(|| RnshError::Protocol("destination must be 32 hexadecimal characters".into()))?;
    let timeout = Duration::from_secs_f64(opts.timeout.unwrap_or(15.0));
    let (event_tx, event_rx) = mpsc::channel();
    let home = home_dir();
    let rnsh_config = resolve_rnsh_config_dir(opts.rnsh_config.as_deref(), &home)?;
    let rns_config = resolve_rns_config_dir(opts.rns_config.as_deref(), &home);
    // Upstream's initiator logs only to `logfile.initiator`.
    crate::pylog::set_logfile(Some(rnsh_log_path(&rnsh_config, false)));
    crate::pylog::install_utility_logging(
        rns_config.to_str(),
        Some(rnsh_log_level(opts.verbose, opts.quiet)),
        0,
        false,
    );
    let node = RnsNode::connect_shared_from_config(
        Some(&rns_config),
        Box::new(RnshCallbacks {
            tx: event_tx.clone(),
        }),
    )?;
    node.wants_destination_type(APP_NAME);
    let identity = prepare_identity(
        &rnsh_config,
        &rns_config,
        opts.identity.as_deref(),
        None,
        &home,
    )?;

    if !node.has_path(&DestHash(dest_hash))? {
        log::info!(target: crate::pylog::INFO_TARGET, "Requesting path to {}", prettyhexrep(&dest_hash));
    }
    wait_for_path(&node, dest_hash, &event_rx, timeout)?;
    let recalled = node
        .recall_identity(&DestHash(dest_hash))?
        .ok_or_else(|| RnshError::Protocol("destination identity was not recalled".into()))?;
    let mut sig_pub = [0u8; 32];
    sig_pub.copy_from_slice(&recalled.public_key[32..64]);

    log::info!(target: crate::pylog::INFO_TARGET, "Establishing link with {}", prettyhexrep(&dest_hash));
    let link_id = node.create_link(dest_hash, sig_pub)?;
    wait_for_link(&event_rx, link_id, timeout)?;
    log::info!(target: crate::pylog::INFO_TARGET, "Link established with {}", prettyhexrep(&dest_hash));
    if !opts.no_id {
        node.identify_on_link(
            link_id,
            identity
                .get_private_key()
                .ok_or_else(|| RnshError::Protocol("identity has no private key".into()))?,
        )?;
    }

    send_message(&node, link_id, &version_message())?;
    let (remote_version, protocol_version) = wait_for_version(&event_rx, timeout)?;
    log::info!(target: crate::pylog::INFO_TARGET, "Connected server version info: sw {remote_version}, proto {protocol_version}");

    let stdin_is_tty = io::stdin().is_terminal();
    let stdout_is_tty = io::stdout().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    let size = current_winsize(0);
    let execute = ExecuteCommand {
        cmdline: opts.command.clone(),
        pipe_stdin: !stdin_is_tty,
        pipe_stdout: !stdout_is_tty,
        pipe_stderr: !stderr_is_tty,
        term: std::env::var("TERM").ok(),
        rows: size.rows,
        cols: size.cols,
        hpix: size.hpix,
        vpix: size.vpix,
    };
    send_message(&node, link_id, &RnshMessage::ExecuteCommand(execute))?;

    let tty = stdin_is_tty.then(|| {
        let restorer = TtyRestorer::new(0);
        restorer.raw();
        // SAFETY: `sigwinch_handler` is an `extern "C" fn(c_int)` and only stores an atomic flag,
        // which is async-signal-safe.
        unsafe {
            libc::signal(libc::SIGWINCH, sigwinch_handler as *const () as usize);
        }
        restorer
    });
    let _keep_tty = tty;
    spawn_stdin_reader(event_tx);

    loop {
        if SIGWINCH_SEEN.swap(false, Ordering::SeqCst) {
            let _ = send_message(&node, link_id, &RnshMessage::WindowSize(current_winsize(0)));
        }
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ChannelMessage {
                msgtype, payload, ..
            }) => match RnshMessage::unpack(msgtype, &payload)? {
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDOUT => {
                    io::stdout().write_all(&data.data)?;
                    io::stdout().flush()?;
                }
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDERR => {
                    io::stderr().write_all(&data.data)?;
                    io::stderr().flush()?;
                }
                RnshMessage::CommandExited(code) => return Ok(code),
                RnshMessage::Error { msg, fatal } => {
                    eprintln!("remote error: {msg}");
                    if fatal {
                        return Ok(200);
                    }
                }
                _ => {}
            },
            Ok(RnshEvent::LocalStdin(data)) => {
                send_stream_chunks(&node, link_id, STREAM_STDIN, &data, false)?;
            }
            Ok(RnshEvent::LocalStdinEof) => {
                send_stream_chunks(&node, link_id, STREAM_STDIN, &[], true)?;
            }
            Ok(RnshEvent::LinkClosed(_)) => return Ok(0),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
        }
    }
}

pub(super) fn send_message(
    transport: &dyn RnshTransport,
    link_id: [u8; 16],
    message: &RnshMessage,
) -> Result<(), RnshError> {
    transport.send_rnsh_message(link_id, message)
}

pub(super) fn send_stream_chunks(
    transport: &dyn RnshTransport,
    link_id: [u8; 16],
    stream_id: u16,
    data: &[u8],
    eof: bool,
) -> Result<(), RnshError> {
    for chunk in data.chunks(STREAM_CHUNK_MAX) {
        let msg = RnshMessage::StreamData(StreamDataMessage::new(
            stream_id,
            chunk.to_vec(),
            false,
            false,
        ));
        send_message(transport, link_id, &msg)?;
    }
    if eof {
        let msg =
            RnshMessage::StreamData(StreamDataMessage::new(stream_id, Vec::new(), true, false));
        send_message(transport, link_id, &msg)?;
    }
    Ok(())
}

pub(super) fn version_message() -> RnshMessage {
    RnshMessage::VersionInfo {
        sw_version: VERSION.into(),
        protocol_version: PROTOCOL_VERSION,
    }
}

pub(super) fn wait_for_path(
    node: &RnsNode,
    dest_hash: [u8; 16],
    event_rx: &mpsc::Receiver<RnshEvent>,
    timeout: Duration,
) -> Result<(), RnshError> {
    let started = Instant::now();
    if !node.has_path(&DestHash(dest_hash))? {
        node.request_path(&DestHash(dest_hash))?;
    }
    while started.elapsed() < timeout {
        if node.has_path(&DestHash(dest_hash))? {
            return Ok(());
        }
        if let Ok(RnshEvent::Announce(announced)) =
            event_rx.recv_timeout(Duration::from_millis(250))
        {
            if announced.dest_hash.0 == dest_hash {
                return Ok(());
            }
        }
    }
    Err(RnshError::Protocol("path not found".into()))
}

pub(super) fn wait_for_link(
    event_rx: &mpsc::Receiver<RnshEvent>,
    expected_link: [u8; 16],
    timeout: Duration,
) -> Result<(), RnshError> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::LinkEstablished {
                link_id,
                is_initiator: true,
                ..
            }) if link_id == expected_link => return Ok(()),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(RnshError::Protocol("link establishment timed out".into()))
}

pub(super) fn wait_for_version(
    event_rx: &mpsc::Receiver<RnshEvent>,
    timeout: Duration,
) -> Result<(String, u64), RnshError> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ChannelMessage {
                msgtype, payload, ..
            }) => match RnshMessage::unpack(msgtype, &payload)? {
                RnshMessage::VersionInfo {
                    sw_version,
                    protocol_version,
                } if protocol_version == PROTOCOL_VERSION => {
                    return Ok((sw_version, protocol_version));
                }
                RnshMessage::Error { msg, .. } => return Err(RnshError::Protocol(msg)),
                _ => {}
            },
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Err(RnshError::Protocol(
        "protocol version exchange timed out".into(),
    ))
}

pub(super) fn spawn_stdin_reader(event_tx: mpsc::Sender<RnshEvent>) {
    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(RnshEvent::LocalStdinEof);
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(RnshEvent::LocalStdin(buf[..n].to_vec()));
                }
                Err(_) => {
                    let _ = event_tx.send(RnshEvent::LocalStdinEof);
                    break;
                }
            }
        }
    });
}
