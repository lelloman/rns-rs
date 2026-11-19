//! The listener: accepting links and running commands for them.

#![allow(unsafe_code, reason = "OS calls through libc and signal handlers")]

use super::*;

#[derive(Clone)]
pub(super) struct ListenerConfig {
    pub(super) default_command: Vec<String>,
    pub(super) allow_all: bool,
    pub(super) allowed: HashSet<[u8; 16]>,
    pub(super) allow_remote_command: bool,
    pub(super) remote_command_as_args: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListenerState {
    WaitIdent,
    WaitVersion,
    WaitCommand,
    Running,
    Closed,
}

// Service queued output in batches so a slow session cannot monopolize the
// listener loop. Reader threads stop at the per-process budget until accepted
// messages release capacity.
pub(super) const OUTPUT_SEND_BATCH: usize = 16;

#[derive(Default)]
pub(super) struct PendingOutput {
    pub(super) messages: VecDeque<PendingMessage>,
}

pub(super) struct PendingMessage {
    pub(super) message: RnshMessage,
    pub(super) reservation: Option<(Arc<OutputBudget>, usize)>,
}

impl PendingMessage {
    pub(super) fn control(message: RnshMessage) -> Self {
        Self {
            message,
            reservation: None,
        }
    }
}

impl Drop for PendingMessage {
    fn drop(&mut self) {
        if let Some((budget, bytes)) = self.reservation.take() {
            budget.release(bytes);
        }
    }
}

impl PendingOutput {
    pub(super) fn stream(&mut self, stream_id: u16, data: &[u8], eof: bool) {
        self.stream_inner(stream_id, data, eof, None);
    }

    pub(super) fn reserved_stream(
        &mut self,
        stream_id: u16,
        data: &[u8],
        budget: Arc<OutputBudget>,
    ) {
        self.stream_inner(stream_id, data, false, Some(budget));
    }

    pub(super) fn stream_inner(
        &mut self,
        stream_id: u16,
        data: &[u8],
        eof: bool,
        budget: Option<Arc<OutputBudget>>,
    ) {
        for chunk in data.chunks(STREAM_CHUNK_MAX) {
            self.messages.push_back(PendingMessage {
                message: RnshMessage::StreamData(StreamDataMessage::new(
                    stream_id,
                    chunk.to_vec(),
                    false,
                    false,
                )),
                reservation: budget.as_ref().map(|budget| (budget.clone(), chunk.len())),
            });
        }
        if eof {
            self.messages
                .push_back(PendingMessage::control(RnshMessage::StreamData(
                    StreamDataMessage::new(stream_id, Vec::new(), true, false),
                )));
        }
    }

    pub(super) fn push_control(&mut self, message: RnshMessage) {
        self.messages.push_back(PendingMessage::control(message));
    }

    pub(super) fn flush(
        &mut self,
        transport: &dyn RnshTransport,
        link_id: [u8; 16],
    ) -> Result<(), RnshError> {
        for _ in 0..OUTPUT_SEND_BATCH {
            let Some(pending) = self.messages.front() else {
                break;
            };
            match send_message(transport, link_id, &pending.message) {
                Ok(()) => {
                    self.messages.pop_front();
                }
                Err(RnshError::Channel(ChannelSendError::NotReady)) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub(super) struct ListenerSession {
    pub(super) link_id: [u8; 16],
    pub(super) state: ListenerState,
    pub(super) remote_identity: Option<IdentityHash>,
    pub(super) config: ListenerConfig,
    pub(super) process: Option<ChildProcess>,
    pub(super) pending_output: PendingOutput,
    pub(super) process_exited: bool,
}

impl ListenerSession {
    pub(super) fn new(link_id: [u8; 16], config: ListenerConfig) -> Self {
        let state = if config.allow_all {
            ListenerState::WaitVersion
        } else {
            ListenerState::WaitIdent
        };
        ListenerSession {
            link_id,
            state,
            remote_identity: None,
            config,
            process: None,
            pending_output: PendingOutput::default(),
            process_exited: false,
        }
    }

    pub(super) fn remote_identified(
        &mut self,
        transport: &dyn RnshTransport,
        identity_hash: IdentityHash,
    ) {
        if self.state == ListenerState::Closed {
            return;
        }
        log::info!(
            target: crate::pylog::INFO_TARGET,
            "Initiator identified {} on link Outlet on {}",
            prettyhexrep(&identity_hash.0),
            prettyhexrep(&self.link_id)
        );
        if !matches!(
            self.state,
            ListenerState::WaitIdent | ListenerState::WaitVersion
        ) {
            self.protocol_error(transport, "unexpected remote identification");
            return;
        }
        if !self.config.allow_all && !self.config.allowed.contains(&identity_hash.0) {
            log::info!(target: crate::pylog::NOTICE_TARGET, "Identity {} not allowed", prettyhexrep(&identity_hash.0));
            let _ = send_message(
                transport,
                self.link_id,
                &RnshMessage::Error {
                    msg: "Identity is not allowed.".into(),
                    fatal: true,
                },
            );
            let _ = transport.teardown_rnsh_link(self.link_id);
            self.state = ListenerState::Closed;
            return;
        }
        log::info!(target: crate::pylog::NOTICE_TARGET, "Identity {} authenticated", prettyhexrep(&identity_hash.0));
        self.remote_identity = Some(identity_hash);
        if self.state == ListenerState::WaitIdent {
            self.state = ListenerState::WaitVersion;
        }
    }

    pub(super) fn handle_message(
        &mut self,
        transport: &dyn RnshTransport,
        event_tx: &mpsc::Sender<RnshEvent>,
        msgtype: u16,
        payload: Vec<u8>,
    ) {
        if matches!(self.state, ListenerState::WaitIdent | ListenerState::Closed) {
            return;
        }
        let message = match RnshMessage::unpack(msgtype, &payload) {
            Ok(message) => message,
            Err(err) => {
                self.protocol_error(transport, &err.to_string());
                return;
            }
        };
        match self.state {
            ListenerState::WaitVersion => match message {
                RnshMessage::VersionInfo {
                    protocol_version, ..
                } if protocol_version == PROTOCOL_VERSION => {
                    let _ = send_message(transport, self.link_id, &version_message());
                    self.state = ListenerState::WaitCommand;
                }
                RnshMessage::VersionInfo { .. } => {
                    self.protocol_error(transport, "Incompatible protocol");
                }
                _ => self.protocol_error(transport, "expected version info"),
            },
            ListenerState::WaitCommand => match message {
                RnshMessage::ExecuteCommand(command) => {
                    if let Err(err) = self.start_command(transport, event_tx, command) {
                        self.protocol_error(transport, &format!("Unable to start process: {err}"));
                    } else {
                        self.state = ListenerState::Running;
                    }
                }
                _ => self.protocol_error(transport, "expected execute command"),
            },
            ListenerState::Running => match message {
                RnshMessage::WindowSize(size) => {
                    if let Some(process) = &self.process {
                        process.set_winsize(&size);
                    }
                }
                RnshMessage::StreamData(data) if data.stream_id == STREAM_STDIN => {
                    if let Some(process) = &mut self.process {
                        if !data.data.is_empty() {
                            process.write_stdin(&data.data);
                        }
                        if data.eof {
                            process.close_stdin();
                        }
                    }
                }
                RnshMessage::Noop => {
                    let _ = send_message(transport, self.link_id, &RnshMessage::Noop);
                }
                _ => self.protocol_error(transport, "unexpected message while running"),
            },
            ListenerState::WaitIdent | ListenerState::Closed => {}
        }
    }

    pub(super) fn start_command(
        &mut self,
        transport: &dyn RnshTransport,
        event_tx: &mpsc::Sender<RnshEvent>,
        command: ExecuteCommand,
    ) -> Result<(), RnshError> {
        let authenticated = self.config.allow_all || self.remote_identity.is_some();
        if self.state != ListenerState::WaitCommand || !authenticated {
            return Err(RnshError::Protocol(
                "session is not authenticated and ready for a command".into(),
            ));
        }
        if !self.config.allow_remote_command && !command.cmdline.is_empty() {
            let _ = send_message(
                transport,
                self.link_id,
                &RnshMessage::Error {
                    msg: "Remote command line not allowed by listener".into(),
                    fatal: true,
                },
            );
            return Err(RnshError::Protocol(
                "remote command line not allowed by listener".into(),
            ));
        }

        let mut argv = self.config.default_command.clone();
        if self.config.remote_command_as_args && !command.cmdline.is_empty() {
            argv.extend(command.cmdline.clone());
        } else if !command.cmdline.is_empty() {
            argv = command.cmdline.clone();
        }

        let remote_identity = self
            .remote_identity
            .as_ref()
            .map(|ih| prettyhexrep(&ih.0))
            .unwrap_or_default();
        // Python's str() of the identity and of the command line list.
        log::info!(
            "Remote {} executing: [{}]",
            if remote_identity.is_empty() {
                "None"
            } else {
                remote_identity.as_str()
            },
            argv.iter()
                .map(|arg| crate::argparse::repr(arg))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let env = [
            (
                "TERM",
                command
                    .term
                    .clone()
                    .or_else(|| std::env::var("TERM").ok())
                    .unwrap_or_else(|| "xterm".into()),
            ),
            ("RNS_REMOTE_IDENTITY", remote_identity),
        ];
        let process = ChildProcess::spawn(self.link_id, &argv, &env, &command, event_tx.clone())?;
        process.set_winsize(&WindowSize {
            rows: command.rows,
            cols: command.cols,
            hpix: command.hpix,
            vpix: command.vpix,
        });
        self.process = Some(process);
        Ok(())
    }

    pub(super) fn protocol_error(&mut self, transport: &dyn RnshTransport, message: &str) {
        let _ = send_message(
            transport,
            self.link_id,
            &RnshMessage::Error {
                msg: message.into(),
                fatal: true,
            },
        );
        let _ = transport.teardown_rnsh_link(self.link_id);
        if let Some(process) = &mut self.process {
            process.terminate();
        }
        self.pending_output = PendingOutput::default();
        self.state = ListenerState::Closed;
    }
}

pub(super) fn close_listener_session(
    transport: &dyn RnshTransport,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    link_id: [u8; 16],
) {
    if let Some(mut session) = sessions.remove(&link_id) {
        if let Some(process) = &mut session.process {
            process.terminate();
        }
    }
    let _ = transport.teardown_rnsh_link(link_id);
}

pub(super) fn flush_listener_session(
    transport: &dyn RnshTransport,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    link_id: [u8; 16],
) {
    let Some(session) = sessions.get_mut(&link_id) else {
        return;
    };
    if session.state != ListenerState::Running {
        return;
    }
    if let Err(error) = session.pending_output.flush(transport, link_id) {
        // Upstream checks the channel before it sends, and has no such
        // line.
        log::debug!(
            "Closing rnsh session {} after output send failed: {error}",
            prettyhexrep(&link_id)
        );
        close_listener_session(transport, sessions, link_id);
    } else if session.process_exited && session.pending_output.messages.is_empty() {
        // CommandExited was accepted after all output and EOF. The channel still
        // owns in-flight frames; the initiator closes the link after receiving it.
        sessions.remove(&link_id);
    }
}

pub(super) fn flush_listener_output(
    transport: &dyn RnshTransport,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
) {
    let links: Vec<_> = sessions.keys().copied().collect();
    for link_id in links {
        flush_listener_session(transport, sessions, link_id);
    }
}

// Events can outlive a link. Keep unsent output on its session, and retry only
// NotReady. Fatal errors remain session-local.
pub(super) fn handle_listener_process_event(
    transport: &dyn RnshTransport,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    event: RnshEvent,
) {
    let link_id = match event {
        RnshEvent::ProcessOutput {
            link_id,
            stream_id,
            data,
            budget,
        } => {
            let Some(session) = sessions.get_mut(&link_id) else {
                budget.release(data.len());
                return;
            };
            if session.state != ListenerState::Running || session.process_exited {
                budget.release(data.len());
                return;
            }
            session
                .pending_output
                .reserved_stream(stream_id, &data, budget);
            link_id
        }
        RnshEvent::ProcessExited { link_id, code } => {
            let Some(session) = sessions.get_mut(&link_id) else {
                return;
            };
            // The waiter already reaped this PID. Never signal it on a later
            // send failure or disconnect while the remaining output drains.
            session.process.take();
            if session.state != ListenerState::Running || session.process_exited {
                return;
            }
            session.process_exited = true;
            session.pending_output.stream(STREAM_STDOUT, &[], true);
            session
                .pending_output
                .push_control(RnshMessage::CommandExited(code));
            link_id
        }
        RnshEvent::LinkClosed(link_id) => {
            if let Some(mut session) = sessions.remove(&link_id) {
                if let Some(process) = &mut session.process {
                    process.terminate();
                }
            }
            return;
        }
        _ => return,
    };
    flush_listener_session(transport, sessions, link_id);
}

pub(super) fn listen(opts: CliOptions) -> Result<(), RnshError> {
    let (event_tx, event_rx) = mpsc::channel();
    let home = home_dir();
    let rnsh_config = resolve_rnsh_config_dir(opts.rnsh_config.as_deref(), &home)?;
    let rns_config = resolve_rns_config_dir(opts.rns_config.as_deref(), &home);
    // Upstream's listen: it logs to stdout until it listens, then to the
    // log file in the rnsh config directory.
    let service = opts.service.as_deref().unwrap_or(DEFAULT_SERVICE_NAME);
    crate::pylog::log(
        &format!("Using service name {service}"),
        crate::pylog::LOG_INFO,
    );
    let logfile = rnsh_log_path(&rnsh_config, true);
    crate::pylog::log(
        &format!("Logging to {}", logfile.display()),
        crate::pylog::LOG_NOTICE,
    );
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

    let identity = prepare_identity(
        &rnsh_config,
        &rns_config,
        opts.identity.as_deref(),
        Some(service),
        &home,
    )?;
    let identity_hash = IdentityHash(*identity.hash());
    let dest = Destination::single_in(APP_NAME, &[], identity_hash);
    let (sig_prv, sig_pub) = extract_sig_keys(&identity)?;
    node.register_destination_with_proof(
        &dest,
        Some(
            identity.get_private_key().ok_or_else(|| {
                RnshError::Protocol("listener identity has no private key".into())
            })?,
        ),
    )?;
    node.register_link_destination(dest.hash.0, sig_prv, sig_pub, 0)?;

    crate::pylog::log(
        &format!(
            "rnsh listening for commands on {}",
            prettyhexrep(&dest.hash.0)
        ),
        crate::pylog::LOG_NOTICE,
    );
    crate::pylog::set_logfile(Some(logfile));

    let default_command = if opts.command.is_empty() {
        let shell = login_shell();
        crate::pylog::log(
            &format!(
                "Using {} for default command.",
                shell.as_deref().unwrap_or("None")
            ),
            crate::pylog::LOG_INFO,
        );
        vec![shell
            .filter(|shell| !shell.is_empty())
            .unwrap_or_else(|| "/bin/sh".into())]
    } else {
        crate::pylog::log(
            &format!("Using command {}", shlex_join(&opts.command)),
            crate::pylog::LOG_INFO,
        );
        opts.command.clone()
    };

    let allowed = load_allowed_identities(&opts, &rnsh_config)?;
    if allowed.is_empty() && !opts.no_auth {
        log::warn!(
            "Warning: No allowed identities configured, rnsh will not accept any connections!"
        );
    }
    let config = ListenerConfig {
        default_command,
        allow_all: opts.no_auth,
        allowed,
        allow_remote_command: !opts.no_remote_command,
        remote_command_as_args: opts.remote_command_as_args,
    };

    let mut sessions: HashMap<[u8; 16], ListenerSession> = HashMap::new();
    let mut last_announce = Instant::now() - Duration::from_secs(24 * 60 * 60);
    let mut announced_once = false;

    loop {
        if let Some(period) = opts.announce_period {
            let due = period == 0 && !announced_once
                || period > 0 && last_announce.elapsed() >= Duration::from_secs(period);
            if due {
                node.announce_queued(&dest, &identity, None)?;
                last_announce = Instant::now();
                announced_once = true;
            }
        }

        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::LinkEstablished {
                link_id,
                is_initiator: false,
                ..
            }) => {
                sessions.entry(link_id).or_insert_with(|| {
                    // Upstream's ListenerSession, created for each link.
                    log::info!(
                        target: crate::pylog::INFO_TARGET,
                        "Session started for Outlet on {}",
                        prettyhexrep(&link_id)
                    );
                    ListenerSession::new(link_id, config.clone())
                });
            }
            Ok(RnshEvent::RemoteIdentified {
                link_id,
                identity_hash,
            }) => {
                if let Some(session) = sessions.get_mut(&link_id) {
                    session.remote_identified(&node, identity_hash);
                }
            }
            Ok(RnshEvent::ChannelMessage {
                link_id,
                msgtype,
                payload,
            }) => {
                if let Some(session) = sessions.get_mut(&link_id) {
                    session.handle_message(&node, &event_tx, msgtype, payload);
                }
            }
            Ok(
                event @ (RnshEvent::ProcessOutput { .. }
                | RnshEvent::ProcessExited { .. }
                | RnshEvent::LinkClosed(_)),
            ) => {
                handle_listener_process_event(&node, &mut sessions, event);
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        flush_listener_output(&node, &mut sessions);
    }
    Ok(())
}

/// The login shell of the user running rnsh (`pwd.getpwuid(os.getuid())
/// .pw_shell`).
pub(super) fn login_shell() -> Option<String> {
    // SAFETY: getpwuid returns a pointer into static storage, read at once.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() || (*entry).pw_shell.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr((*entry).pw_shell)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Python's `shlex.join`.
pub(super) fn shlex_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            let safe = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
            if safe {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
