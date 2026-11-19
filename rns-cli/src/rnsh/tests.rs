use super::*;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const TEST_LINK: [u8; 16] = [0x42; 16];
static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_dir(label: &str) -> PathBuf {
    let id = TEST_DIR_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let path = std::env::temp_dir().join(format!("rns-rnsh-{label}-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[derive(Default)]
struct FakeTransport {
    sent: Mutex<Vec<SentFrame>>,
    teardowns: Mutex<Vec<[u8; 16]>>,
    fail_send: Mutex<Option<([u8; 16], u16)>>,
    window: Mutex<Option<([u8; 16], rns_core::channel::Channel)>>,
}

type SentFrame = ([u8; 16], u16, Vec<u8>);

impl FakeTransport {
    fn sent_messages(&self) -> Vec<([u8; 16], RnshMessage)> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(link_id, msgtype, payload)| {
                (
                    *link_id,
                    RnshMessage::unpack(*msgtype, payload)
                        .expect("fake transport stored decodable message"),
                )
            })
            .collect()
    }
}

impl RnshTransport for FakeTransport {
    fn send_rnsh_message(&self, link_id: [u8; 16], message: &RnshMessage) -> Result<(), RnshError> {
        if *self.fail_send.lock().unwrap() == Some((link_id, message.msgtype())) {
            return Err(RnshError::Send);
        }
        if let Some((limited_link, channel)) = self.window.lock().unwrap().as_mut() {
            if *limited_link == link_id {
                channel
                    .send(
                        message.msgtype(),
                        &message.pack(),
                        0.0,
                        rns_core::constants::LINK_MDU,
                    )
                    .map_err(|error| RnshError::from(ChannelSendError::from(error.to_string())))?;
            }
        }
        self.sent
            .lock()
            .unwrap()
            .push((link_id, message.msgtype(), message.pack()));
        Ok(())
    }

    fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError> {
        self.teardowns.lock().unwrap().push(link_id);
        Ok(())
    }
}

fn test_config() -> ListenerConfig {
    ListenerConfig {
        default_command: vec!["/bin/cat".into()],
        allow_all: true,
        allowed: HashSet::new(),
        allow_remote_command: true,
        remote_command_as_args: false,
    }
}

fn exec_msg(cmdline: Vec<&str>) -> RnshMessage {
    RnshMessage::ExecuteCommand(ExecuteCommand {
        cmdline: cmdline.into_iter().map(str::to_string).collect(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: Some("xterm".into()),
        rows: Some(24),
        cols: Some(80),
        hpix: None,
        vpix: None,
    })
}

fn running_session(link_id: [u8; 16]) -> ListenerSession {
    let mut session = ListenerSession::new(link_id, test_config());
    session.state = ListenerState::Running;
    session
}

fn output_event(link_id: [u8; 16]) -> RnshEvent {
    output_event_with_data(link_id, STREAM_STDOUT, b"hello".to_vec())
}

fn output_event_with_data(link_id: [u8; 16], stream_id: u16, data: Vec<u8>) -> RnshEvent {
    let budget = Arc::new(OutputBudget::new());
    assert!(budget.reserve(data.len()));
    RnshEvent::ProcessOutput {
        link_id,
        stream_id,
        data,
        budget,
    }
}

#[test]
fn listener_ignores_queued_process_events_after_link_closed() {
    let fake = FakeTransport::default();
    let other = [0x43; 16];
    let mut sessions = HashMap::from([
        (TEST_LINK, running_session(TEST_LINK)),
        (other, running_session(other)),
    ]);
    handle_listener_process_event(&fake, &mut sessions, RnshEvent::LinkClosed(TEST_LINK));
    handle_listener_process_event(&fake, &mut sessions, output_event(TEST_LINK));
    handle_listener_process_event(
        &fake,
        &mut sessions,
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 0,
        },
    );
    assert!(fake.sent_messages().is_empty());
    assert!(fake.teardowns.lock().unwrap().is_empty());
    assert!(!sessions.contains_key(&TEST_LINK));
    handle_listener_process_event(&fake, &mut sessions, output_event(other));
    assert_eq!(fake.sent_messages()[0].0, other);
    assert_eq!(sessions[&other].state, ListenerState::Running);
}

#[test]
fn listener_isolates_process_send_errors_and_accepts_next_session() {
    for event in [
        output_event(TEST_LINK),
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 0,
        },
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 0,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let (case, event) = event;
        let fake = FakeTransport::default();
        let failure_type = if case == 2 {
            MSG_COMMAND_EXITED
        } else {
            MSG_STREAM_DATA
        };
        *fake.fail_send.lock().unwrap() = Some((TEST_LINK, failure_type));
        let other = [0x43; 16];
        let mut sessions = HashMap::from([
            (TEST_LINK, running_session(TEST_LINK)),
            (other, running_session(other)),
        ]);
        handle_listener_process_event(&fake, &mut sessions, event);
        assert!(!sessions.contains_key(&TEST_LINK));
        assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
        let sent_before = fake.sent_messages().len();
        handle_listener_process_event(&fake, &mut sessions, output_event(TEST_LINK));
        handle_listener_process_event(
            &fake,
            &mut sessions,
            RnshEvent::ProcessExited {
                link_id: TEST_LINK,
                code: 0,
            },
        );
        assert_eq!(fake.sent_messages().len(), sent_before);
        handle_listener_process_event(&fake, &mut sessions, output_event(other));
        assert_eq!(fake.sent_messages().last().unwrap().0, other);
        assert_eq!(sessions[&other].state, ListenerState::Running);

        let new_link = [0x44; 16];
        let mut next = ListenerSession::new(new_link, test_config());
        let (tx, _rx) = mpsc::channel();
        let version = version_message();
        next.handle_message(&fake, &tx, version.msgtype(), version.pack());
        assert_eq!(next.state, ListenerState::WaitCommand);
        assert_eq!(fake.sent_messages().last().unwrap().0, new_link);
    }
}

#[test]
fn listener_process_exit_sends_eof_and_status_before_removal() {
    let fake = FakeTransport::default();
    let mut sessions = HashMap::from([(TEST_LINK, running_session(TEST_LINK))]);
    handle_listener_process_event(&fake, &mut sessions, output_event(TEST_LINK));
    handle_listener_process_event(
        &fake,
        &mut sessions,
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 17,
        },
    );
    let messages = fake.sent_messages();
    assert_eq!(messages.len(), 3);
    assert!(
        matches!(&messages[0].1, RnshMessage::StreamData(data) if data.data == b"hello" && !data.eof)
    );
    assert!(
        matches!(&messages[1].1, RnshMessage::StreamData(data) if data.data.is_empty() && data.eof)
    );
    assert!(matches!(&messages[2].1, RnshMessage::CommandExited(17)));
    assert!(sessions.is_empty());
    assert!(fake.teardowns.lock().unwrap().is_empty());
}

#[test]
fn channel_send_error_preserves_backpressure() {
    assert_eq!(
        ChannelSendError::from(rns_core::channel::ChannelError::NotReady.to_string()),
        ChannelSendError::NotReady
    );
    assert_eq!(
        ChannelSendError::from("unknown link".to_string()),
        ChannelSendError::Rejected("unknown link".to_string())
    );
    assert!(matches!(
        ChannelSendError::from(rns_core::channel::ChannelError::MessageTooBig.to_string()),
        ChannelSendError::Rejected(_)
    ));
}

#[test]
fn listener_drains_real_channel_window_without_losing_output_or_exit() {
    let fake = FakeTransport::default();
    *fake.window.lock().unwrap() = Some((TEST_LINK, rns_core::channel::Channel::new(2.0)));
    let other = [0x43; 16];
    let mut sessions = HashMap::from([
        (TEST_LINK, running_session(TEST_LINK)),
        (other, running_session(other)),
    ]);
    let data: Vec<_> = (0..STREAM_CHUNK_MAX * 3 + 7)
        .map(|i| (i % 251) as u8)
        .collect();
    handle_listener_process_event(
        &fake,
        &mut sessions,
        output_event_with_data(TEST_LINK, STREAM_STDOUT, data.clone()),
    );
    handle_listener_process_event(
        &fake,
        &mut sessions,
        output_event_with_data(TEST_LINK, STREAM_STDERR, b"stderr tail".to_vec()),
    );
    handle_listener_process_event(
        &fake,
        &mut sessions,
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 17,
        },
    );
    assert_eq!(fake.sent_messages().len(), 1);
    assert!(sessions[&TEST_LINK].process_exited);
    assert!(!sessions[&TEST_LINK].pending_output.messages.is_empty());
    for _ in 0..3 {
        flush_listener_output(&fake, &mut sessions);
    }
    assert_eq!(
        fake.sent_messages().len(),
        1,
        "NotReady must not duplicate accepted frames"
    );
    handle_listener_process_event(&fake, &mut sessions, output_event(other));
    assert_eq!(fake.sent_messages().last().unwrap().0, other);
    for sequence in 0..7 {
        fake.window
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .1
            .packet_delivered(sequence);
        // Drive retries with idle ticks, without new child events.
        flush_listener_output(&fake, &mut sessions);
    }
    assert!(!sessions.contains_key(&TEST_LINK));
    assert_eq!(sessions[&other].state, ListenerState::Running);
    assert!(fake.teardowns.lock().unwrap().is_empty());
    let messages: Vec<_> = fake
        .sent_messages()
        .into_iter()
        .filter(|(link, _)| *link == TEST_LINK)
        .map(|(_, msg)| msg)
        .collect();
    assert_eq!(messages.len(), 7);
    let output: Vec<_> = messages[..4]
        .iter()
        .flat_map(|msg| match msg {
            RnshMessage::StreamData(stream) => {
                assert_eq!(stream.stream_id, STREAM_STDOUT);
                assert!(!stream.eof);
                stream.data.clone()
            }
            _ => panic!("expected stdout"),
        })
        .collect();
    assert_eq!(output, data);
    assert!(
        matches!(&messages[4], RnshMessage::StreamData(stream) if stream.stream_id == STREAM_STDERR && stream.data == b"stderr tail")
    );
    assert!(
        matches!(&messages[5], RnshMessage::StreamData(stream) if stream.eof && stream.data.is_empty())
    );
    assert!(matches!(&messages[6], RnshMessage::CommandExited(17)));
}

#[test]
fn listener_discards_blocked_output_on_link_close() {
    let fake = FakeTransport::default();
    *fake.window.lock().unwrap() = Some((TEST_LINK, rns_core::channel::Channel::new(2.0)));
    let mut sessions = HashMap::from([(TEST_LINK, running_session(TEST_LINK))]);
    let data = vec![1; STREAM_CHUNK_MAX * 2];
    let budget = Arc::new(OutputBudget::new());
    assert!(budget.reserve(data.len()));
    handle_listener_process_event(
        &fake,
        &mut sessions,
        RnshEvent::ProcessOutput {
            link_id: TEST_LINK,
            stream_id: STREAM_STDOUT,
            data,
            budget: budget.clone(),
        },
    );
    assert!(!sessions[&TEST_LINK].pending_output.messages.is_empty());
    assert!(budget.buffered() > 0);
    handle_listener_process_event(&fake, &mut sessions, RnshEvent::LinkClosed(TEST_LINK));
    handle_listener_process_event(
        &fake,
        &mut sessions,
        RnshEvent::ProcessExited {
            link_id: TEST_LINK,
            code: 0,
        },
    );
    flush_listener_output(&fake, &mut sessions);
    assert!(sessions.is_empty());
    assert_eq!(fake.sent_messages().len(), 1);
    assert_eq!(budget.buffered(), 0);
}

#[test]
fn process_output_budget_blocks_and_resumes_producers() {
    let budget = Arc::new(OutputBudget::new());
    assert!(budget.reserve(PROCESS_OUTPUT_BUFFER_MAX));
    let waiting_budget = budget.clone();
    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let reserved = waiting_budget.reserve(1);
        let _ = tx.send(reserved);
    });

    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    budget.release(1);
    assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
    budget.close();
    waiter.join().unwrap();
}

#[test]
fn process_output_budget_bounds_reader_events_and_allows_completion() {
    const EXTRA_OUTPUT: usize = 8192;

    let (tx, rx) = mpsc::channel();
    let command = ExecuteCommand {
        cmdline: Vec::new(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: None,
        rows: None,
        cols: None,
        hpix: None,
        vpix: None,
    };
    let process = ChildProcess::spawn(
        TEST_LINK,
        &[
            "/bin/sh".into(),
            "-c".into(),
            format!(
                "head -c {} /dev/zero",
                PROCESS_OUTPUT_BUFFER_MAX + EXTRA_OUTPUT
            ),
        ],
        &[],
        &command,
        tx,
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while process.output_budget.buffered() < PROCESS_OUTPUT_BUFFER_MAX && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(process.output_budget.buffered(), PROCESS_OUTPUT_BUFFER_MAX);

    let mut received = 0;
    let mut exit = None;
    while exit.is_none() && Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ProcessOutput { data, budget, .. }) => {
                received += data.len();
                budget.release(data.len());
                assert!(process.output_budget.buffered() <= PROCESS_OUTPUT_BUFFER_MAX);
            }
            Ok(RnshEvent::ProcessExited { code, .. }) => exit = Some(code),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert_eq!(received, PROCESS_OUTPUT_BUFFER_MAX + EXTRA_OUTPUT);
    assert_eq!(exit, Some(0));
}

/// Run `argv` with piped streams; its stdout and exit code.
fn run_piped(argv: &[&str], env: &[(&str, String)]) -> (Vec<u8>, i32) {
    let (tx, rx) = mpsc::channel();
    let command = ExecuteCommand {
        cmdline: Vec::new(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: None,
        rows: None,
        cols: None,
        hpix: None,
        vpix: None,
    };
    let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
    let mut process = ChildProcess::spawn(TEST_LINK, &argv, env, &command, tx).unwrap();
    process.close_stdin();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stdout = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ProcessOutput {
                stream_id,
                data,
                budget,
                ..
            }) => {
                budget.release(data.len());
                if stream_id == STREAM_STDOUT {
                    stdout.extend_from_slice(&data);
                }
            }
            Ok(RnshEvent::ProcessExited { code, .. }) => return (stdout, code),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!("{argv:?} did not exit");
}

#[test]
fn exited_child_is_reaped_before_its_exit_is_reported_and_not_signalled() {
    let (tx, rx) = mpsc::channel();
    let command = ExecuteCommand {
        cmdline: Vec::new(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: None,
        rows: None,
        cols: None,
        hpix: None,
        vpix: None,
    };
    let argv = ["sh".to_string(), "-c".to_string(), "exit 5".to_string()];
    let mut process = ChildProcess::spawn(TEST_LINK, &argv, &[], &command, tx).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let code = loop {
        assert!(Instant::now() < deadline, "no exit reported");
        if let Ok(RnshEvent::ProcessExited { code, .. }) =
            rx.recv_timeout(Duration::from_millis(100))
        {
            break code;
        }
    };
    assert_eq!(code, 5);
    assert!(*process.reaped.lock().unwrap());
    // The pid is gone: terminating must not signal whatever reuses it.
    process.terminate();
    drop(process);
}

#[test]
fn readers_keep_their_descriptors_after_the_process_is_dropped() {
    let (tx, rx) = mpsc::channel();
    let command = ExecuteCommand {
        cmdline: Vec::new(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: None,
        rows: None,
        cols: None,
        hpix: None,
        vpix: None,
    };
    let argv = ["sh".to_string(), "-c".to_string(), "sleep 0.2".to_string()];
    let process = ChildProcess::spawn(TEST_LINK, &argv, &[], &command, tx).unwrap();
    let stdout = Arc::downgrade(process.stdout_fd.as_ref().unwrap());
    drop(process);
    // A reader still holds the pipe, so it is not closed under it.
    assert!(stdout.upgrade().is_some());
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(RnshEvent::ProcessExited { .. }) = rx.recv_timeout(Duration::from_millis(100)) {
            break;
        }
    }
    // Readers are joined before the exit is reported: the pipe is closed now.
    assert!(stdout.upgrade().is_none());
}

#[test]
fn spawned_programs_are_found_and_get_the_environment() {
    let env = [
        ("RNS_REMOTE_IDENTITY", "<abcd>".to_string()),
        ("HOME", "/nowhere".to_string()),
    ];
    let (out, code) = run_piped(
        &[
            "sh",
            "-c",
            "printf '%s %s' \"$RNS_REMOTE_IDENTITY\" \"$HOME\"; exit 3",
        ],
        &env,
    );
    assert_eq!(out, b"<abcd> /nowhere");
    assert_eq!(code, 3);

    assert_eq!(run_piped(&["rns-no-such-program"], &[]).1, 255);
    assert_eq!(run_piped(&["/nonexistent/program"], &[]).1, 255);

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("no-header");
    std::fs::write(&script, "printf script\nexit 7\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let (out, code) = run_piped(&[script.to_str().unwrap()], &[]);
    assert_eq!((out.as_slice(), code), (b"script".as_slice(), 7));
}

#[test]
fn pending_output_limits_work_per_flush() {
    let mut pending = PendingOutput::default();
    pending.stream(
        STREAM_STDOUT,
        &vec![0; STREAM_CHUNK_MAX * (OUTPUT_SEND_BATCH + 1)],
        false,
    );
    let fake = FakeTransport::default();
    pending.flush(&fake, TEST_LINK).unwrap();
    assert_eq!(fake.sent_messages().len(), OUTPUT_SEND_BATCH);
    assert_eq!(pending.messages.len(), 1);
}

#[test]
fn msgpack_version_matches_upstream_shape() {
    let msg = RnshMessage::VersionInfo {
        sw_version: "1.2.0".into(),
        protocol_version: 1,
    };
    let packed = msg.pack();
    assert_eq!(packed, b"\x92\xa51.2.0\x01");
    assert_eq!(RnshMessage::unpack(MSG_VERSION_INFO, &packed).unwrap(), msg);
}

#[test]
fn execute_command_roundtrips() {
    let msg = RnshMessage::ExecuteCommand(ExecuteCommand {
        cmdline: vec!["/bin/sh".into(), "-lc".into(), "echo hi".into()],
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: false,
        term: Some("xterm-256color".into()),
        rows: Some(24),
        cols: Some(80),
        hpix: None,
        vpix: None,
    });
    let packed = msg.pack();
    assert_eq!(
        RnshMessage::unpack(MSG_EXECUTE_COMMAND, &packed).unwrap(),
        msg
    );
}

#[test]
fn stream_data_uses_upstream_header_bits() {
    let msg = RnshMessage::StreamData(StreamDataMessage::new(2, b"err".to_vec(), true, false));
    let packed = msg.pack();
    assert_eq!(&packed[..2], &0x8002u16.to_be_bytes());
    assert_eq!(RnshMessage::unpack(MSG_STREAM_DATA, &packed).unwrap(), msg);
}

#[test]
fn cli_splits_command_after_double_dash() {
    let args = CliOptions::parse(
        vec![
            "-l".into(),
            "-s".into(),
            "ops".into(),
            "--".into(),
            "/bin/sh".into(),
            "-l".into(),
        ],
        80,
    )
    .unwrap();
    assert!(args.listen);
    assert_eq!(args.service.as_deref(), Some("ops"));
    assert_eq!(args.command, vec!["/bin/sh", "-l"]);
}

#[test]
fn cli_separates_rnsh_and_reticulum_config_directories() {
    let short = CliOptions::parse(
        vec![
            "-c".into(),
            "/tmp/rnsh-app".into(),
            "--rnsconfig".into(),
            "/tmp/reticulum".into(),
        ],
        80,
    )
    .unwrap();
    assert_eq!(short.rnsh_config.as_deref(), Some("/tmp/rnsh-app"));
    assert_eq!(short.rns_config.as_deref(), Some("/tmp/reticulum"));

    let long = CliOptions::parse(
        vec![
            "--config".into(),
            "/tmp/rnsh-long".into(),
            "--rnsconfig".into(),
            "/tmp/rns-long".into(),
        ],
        80,
    )
    .unwrap();
    assert_eq!(long.rnsh_config.as_deref(), Some("/tmp/rnsh-long"));
    assert_eq!(long.rns_config.as_deref(), Some("/tmp/rns-long"));

    let equals = CliOptions::parse(
        vec![
            "--config=/tmp/rnsh-equals".into(),
            "--rnsconfig=/tmp/rns-equals".into(),
        ],
        80,
    )
    .unwrap();
    assert_eq!(equals.rnsh_config.as_deref(), Some("/tmp/rnsh-equals"));
    assert_eq!(equals.rns_config.as_deref(), Some("/tmp/rns-equals"));
}

#[test]
fn cli_parses_upstream_invocations_as_argparse_does() {
    let parse = |argv: &[&str]| {
        CliOptions::parse(argv.iter().map(|s| s.to_string()).collect(), 80)
            .unwrap_or_else(|e| panic!("{argv:?}: {e:?}"))
    };
    let o = parse(&["-l", "-a", "aa", "-abb", "-n", "-b", "60", "-vv"]);
    assert!(o.listen && o.no_auth);
    assert_eq!(o.allowed, vec!["aa", "bb"]);
    assert_eq!((o.announce_period, o.verbose), (Some(60), 2));
    assert_eq!(o.service.as_deref(), Some(DEFAULT_SERVICE_NAME));
    let o = parse(&["-lACs", "ops", "-b0", "--", "/bin/bash", "--login"]);
    assert!(o.listen && o.remote_command_as_args && o.no_remote_command);
    assert_eq!(
        (o.service.as_deref(), o.announce_period),
        (Some("ops"), Some(0))
    );
    assert_eq!(o.command, vec!["/bin/bash", "--login"]);
    let o = parse(&["dest", "-Nm", "-w=2.5", "-i", "id", "-q"]);
    assert_eq!(o.destination.as_deref(), Some("dest"));
    assert!(o.no_id && o.mirror_exit);
    assert_eq!(
        (o.timeout, o.identity.as_deref(), o.quiet),
        (Some(2.5), Some("id"), 1)
    );
    let o = parse(&[
        "--listen",
        "--serv",
        "ops",
        "--allowed=aa",
        "--no-a",
        "--rnsc",
        "/r",
    ]);
    assert!(o.listen && o.no_auth);
    assert_eq!(o.service.as_deref(), Some("ops"));
    assert_eq!(o.allowed, vec!["aa"]);
    assert_eq!(o.rns_config.as_deref(), Some("/r"));
    let o = parse(&[
        "--no-i",
        "--mirror",
        "--timeout",
        "5",
        "--ident",
        "id",
        "dest",
    ]);
    assert!(o.no_id && o.mirror_exit);
    assert_eq!((o.timeout, o.identity.as_deref()), (Some(5.0), Some("id")));
    assert_eq!(parse(&["-cdir"]).rnsh_config.as_deref(), Some("dir"));
    assert!(parse(&["-p", "--print"]).print_identity);
    assert!(parse(&["--version"]).version);
    assert_eq!(parse(&["-b", "-5"]).announce_period, Some(0));
    let exit = |argv: &[&str]| {
        CliOptions::parse(argv.iter().map(|s| s.to_string()).collect(), 80).unwrap_err()
    };
    let help = exit(&["-h"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.starts_with("usage: rnsh [-h]"));
    // `--no` is ambiguous: --no-auth, --no-remote-command or --no-id.
    assert_eq!(exit(&["--no"]).code, 2);
    assert_eq!(exit(&["a", "b"]).code, 2);
    assert_eq!(exit(&["-w"]).code, 2);
    assert_eq!(exit(&["-Z"]).code, 2);
    assert!(exit(&["-b", "x"])
        .stderr
        .ends_with("rnsh: error: argument -b/--announce: invalid int value: 'x'\n"));
}

#[test]
fn rnsconfig_has_no_short_alias() {
    let error = CliOptions::parse(vec!["-r".into(), "/tmp/reticulum".into()], 80).unwrap_err();
    assert!(error
        .stderr
        .ends_with("rnsh: error: unrecognized arguments: -r\n"));
}

#[test]
fn explicit_rnsh_directory_is_expanded_and_created() {
    let home = test_dir("explicit-home");
    let selected = resolve_rnsh_config_dir(Some("~/nested/rnsh"), &home).unwrap();

    assert_eq!(selected, home.join("nested/rnsh"));
    assert!(selected.is_dir());
    assert_eq!(
        resolve_rns_config_dir(Some("~/reticulum"), &home),
        home.join("reticulum")
    );
    assert_eq!(resolve_rns_config_dir(None, &home), home.join(".reticulum"));
}

#[test]
fn default_rnsh_directory_prefers_existing_xdg_then_creates_legacy() {
    let xdg_home = test_dir("xdg-home");
    let xdg = xdg_home.join(".config/rnsh");
    fs::create_dir_all(&xdg).unwrap();
    assert_eq!(resolve_rnsh_config_dir(None, &xdg_home).unwrap(), xdg);

    let fresh_home = test_dir("legacy-home");
    let legacy = fresh_home.join(".rnsh");
    assert_eq!(resolve_rnsh_config_dir(None, &fresh_home).unwrap(), legacy);
    assert!(legacy.is_dir());
}

#[test]
fn default_identity_paths_match_upstream_for_initiator_and_listener() {
    let home = test_dir("identity-home");
    let config = home.join("rnsh");
    fs::create_dir_all(&config).unwrap();

    assert_eq!(
        rnsh_identity_path(&config, None, None, &home),
        config.join("identity")
    );
    assert_eq!(
        rnsh_identity_path(&config, None, Some("dev-shell_1!"), &home),
        config.join("identity.devshell1")
    );
    assert_eq!(
        rnsh_identity_path(&config, Some("~/keys/operator"), Some("ignored"), &home),
        home.join("keys/operator")
    );
}

#[test]
fn prepare_identity_uses_new_default_and_preserves_explicit_override() {
    let home = test_dir("prepare-home");
    let config = home.join("rnsh");
    fs::create_dir_all(&config).unwrap();
    let default_path = config.join("identity.default");

    let generated = prepare_identity_at(&default_path).unwrap();
    assert!(default_path.is_file());
    assert_eq!(
        rns_net::storage::load_identity(&default_path)
            .unwrap()
            .hash(),
        generated.hash()
    );

    let explicit = home.join("keys/explicit");
    let explicit_identity = prepare_identity_at(&explicit).unwrap();
    assert!(explicit.is_file());
    assert_eq!(
        rns_net::storage::load_identity(&explicit).unwrap().hash(),
        explicit_identity.hash()
    );
    assert!(!config.join("identity").exists());
}

#[test]
fn legacy_identity_migration_warning_names_both_paths_without_copying() {
    let home = test_dir("migration-home");
    let rns_config = home.join("reticulum");
    let old = rns_config.join("storage/identities/rnsh.default");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    fs::write(&old, [0x44; 64]).unwrap();
    let new = home.join("rnsh/identity.default");

    let warning = legacy_identity_migration_warning(&new, &old).unwrap();
    assert!(warning.contains(old.to_str().unwrap()));
    assert!(warning.contains(new.to_str().unwrap()));
    assert!(
        !new.exists(),
        "migration check must never copy key material"
    );

    fs::create_dir_all(new.parent().unwrap()).unwrap();
    fs::write(&new, [0x55; 64]).unwrap();
    assert!(legacy_identity_migration_warning(&new, &old).is_none());
}

#[test]
fn allowlist_and_logfile_are_scoped_to_selected_rnsh_directory() {
    let selected = test_dir("selected-config");
    let allowed_hash = "11111111111111111111111111111111";
    fs::write(
        selected.join("allowed_identities"),
        format!("{allowed_hash}\n"),
    )
    .unwrap();
    let opts = CliOptions::default();

    let allowed = load_allowed_identities(&opts, &selected).unwrap();

    assert!(allowed.contains(&[0x11; 16]));
    assert_eq!(rnsh_log_path(&selected, true), selected.join("logfile"));
    assert_eq!(
        rnsh_log_path(&selected, false),
        selected.join("logfile.initiator")
    );
}

#[test]
fn service_name_is_sanitized_like_upstream() {
    assert_eq!(sanitize_service_name("dev-shell_1!"), "devshell1");
}

#[test]
fn rnsh_logs_at_upstreams_levels() {
    assert_eq!(rnsh_log_level(0, 0), crate::pylog::LOG_INFO);
    assert_eq!(rnsh_log_level(1, 0), crate::pylog::LOG_VERBOSE);
    assert_eq!(rnsh_log_level(9, 0), 7);
    assert_eq!(rnsh_log_level(0, 9), crate::pylog::LOG_NONE);
}

#[test]
fn listener_rejects_unallowed_identity_and_tears_down() {
    let mut allowed = HashSet::new();
    allowed.insert([0x11; 16]);
    let config = ListenerConfig {
        allow_all: false,
        allowed,
        ..test_config()
    };
    let fake = FakeTransport::default();
    let mut session = ListenerSession::new(TEST_LINK, config);

    assert_eq!(session.state, ListenerState::WaitIdent);
    session.remote_identified(&fake, IdentityHash([0x22; 16]));

    assert_eq!(session.state, ListenerState::Closed);
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    let messages = fake.sent_messages();
    assert_eq!(messages.len(), 1);
    assert!(matches!(
        &messages[0].1,
        RnshMessage::Error { msg, fatal: true } if msg == "Identity is not allowed."
    ));
}

#[test]
fn denied_identity_cannot_pipeline_handshake_or_execute_after_termination() {
    let mut allowed = HashSet::new();
    allowed.insert([0x11; 16]);
    let config = ListenerConfig {
        allow_all: false,
        allowed,
        default_command: vec!["/bin/false".into()],
        ..test_config()
    };
    let fake = FakeTransport::default();
    let (tx, rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, config);

    session.remote_identified(&fake, IdentityHash([0x22; 16]));
    let version = version_message();
    session.handle_message(&fake, &tx, version.msgtype(), version.pack());
    let execute = exec_msg(Vec::new());
    session.handle_message(&fake, &tx, execute.msgtype(), execute.pack());
    session.handle_message(&fake, &tx, MSG_VERSION_INFO, vec![0xc1]);
    session.remote_identified(&fake, IdentityHash([0x11; 16]));

    assert_eq!(session.state, ListenerState::Closed);
    assert!(session.remote_identity.is_none());
    assert!(
        session.process.is_none(),
        "denied session spawned a process"
    );
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    let messages = fake.sent_messages();
    assert_eq!(messages.len(), 1, "closed session emitted another response");
    assert!(matches!(
        &messages[0].1,
        RnshMessage::Error { msg, fatal: true } if msg == "Identity is not allowed."
    ));
}

#[test]
fn command_start_requires_authenticated_wait_command_state() {
    let mut allowed = HashSet::new();
    allowed.insert([0x11; 16]);
    let config = ListenerConfig {
        allow_all: false,
        allowed,
        default_command: vec!["/bin/false".into()],
        ..test_config()
    };
    let fake = FakeTransport::default();
    let (tx, rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, config);

    let err = session
        .start_command(
            &fake,
            &tx,
            match exec_msg(Vec::new()) {
                RnshMessage::ExecuteCommand(command) => command,
                _ => unreachable!(),
            },
        )
        .expect_err("unauthenticated session must not start a command");

    assert!(err.to_string().contains("not authenticated"));
    assert_eq!(session.state, ListenerState::WaitIdent);
    assert!(session.process.is_none());
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn listener_accepts_allowed_identity_and_completes_version_handshake() {
    let mut allowed = HashSet::new();
    allowed.insert([0x11; 16]);
    let config = ListenerConfig {
        allow_all: false,
        allowed,
        ..test_config()
    };
    let fake = FakeTransport::default();
    let (tx, _rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, config);

    session.remote_identified(&fake, IdentityHash([0x11; 16]));
    assert_eq!(session.state, ListenerState::WaitVersion);
    let version = version_message();
    session.handle_message(&fake, &tx, version.msgtype(), version.pack());

    assert_eq!(session.state, ListenerState::WaitCommand);
    let messages = fake.sent_messages();
    assert_eq!(messages.len(), 1);
    assert!(matches!(
        &messages[0].1,
        RnshMessage::VersionInfo {
            protocol_version: PROTOCOL_VERSION,
            ..
        }
    ));
}

#[test]
fn listener_rejects_reidentification_after_version_handshake() {
    let fake = FakeTransport::default();
    let (tx, _rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, test_config());
    let version = version_message();
    session.handle_message(&fake, &tx, version.msgtype(), version.pack());
    assert_eq!(session.state, ListenerState::WaitCommand);

    session.remote_identified(&fake, IdentityHash([0x11; 16]));

    assert_eq!(session.state, ListenerState::Closed);
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    assert!(matches!(
        &fake.sent_messages()[1].1,
        RnshMessage::Error { msg, fatal: true } if msg == "unexpected remote identification"
    ));
}

#[test]
fn listener_rejects_reidentification_while_command_is_running() {
    let fake = FakeTransport::default();
    let mut session = ListenerSession::new(TEST_LINK, test_config());
    session.state = ListenerState::Running;

    session.remote_identified(&fake, IdentityHash([0x11; 16]));

    assert_eq!(session.state, ListenerState::Closed);
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    assert!(matches!(
        &fake.sent_messages()[0].1,
        RnshMessage::Error { msg, fatal: true } if msg == "unexpected remote identification"
    ));
}

#[test]
fn listener_rejects_incompatible_protocol_version() {
    let fake = FakeTransport::default();
    let (tx, _rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, test_config());
    let msg = RnshMessage::VersionInfo {
        sw_version: "future".into(),
        protocol_version: PROTOCOL_VERSION + 1,
    };

    session.handle_message(&fake, &tx, msg.msgtype(), msg.pack());

    assert_eq!(session.state, ListenerState::Closed);
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    assert!(matches!(
        &fake.sent_messages()[0].1,
        RnshMessage::Error { msg, fatal: true } if msg == "Incompatible protocol"
    ));
}

#[test]
fn listener_rejects_remote_command_when_disabled() {
    let fake = FakeTransport::default();
    let (tx, _rx) = mpsc::channel();
    let config = ListenerConfig {
        allow_remote_command: false,
        ..test_config()
    };
    let mut session = ListenerSession::new(TEST_LINK, config);
    let version = version_message();
    session.handle_message(&fake, &tx, version.msgtype(), version.pack());
    let exec = exec_msg(vec!["/bin/echo", "nope"]);

    session.handle_message(&fake, &tx, exec.msgtype(), exec.pack());

    assert_eq!(session.state, ListenerState::Closed);
    assert_eq!(fake.teardowns.lock().unwrap().as_slice(), &[TEST_LINK]);
    assert!(fake.sent_messages().iter().any(|(_, msg)| matches!(
        msg,
        RnshMessage::Error { msg, fatal: true }
            if msg.contains("Remote command line not allowed")
    )));
}

#[test]
fn listener_executes_default_command_and_forwards_stdin_to_process() {
    let fake = FakeTransport::default();
    let (tx, rx) = mpsc::channel();
    let mut session = ListenerSession::new(TEST_LINK, test_config());
    let version = version_message();
    session.handle_message(&fake, &tx, version.msgtype(), version.pack());
    let exec = exec_msg(Vec::new());
    session.handle_message(&fake, &tx, exec.msgtype(), exec.pack());
    assert_eq!(session.state, ListenerState::Running);

    let stdin = RnshMessage::StreamData(StreamDataMessage::new(
        STREAM_STDIN,
        b"hello over stdin".to_vec(),
        true,
        false,
    ));
    session.handle_message(&fake, &tx, stdin.msgtype(), stdin.pack());

    let started = Instant::now();
    let mut stdout = Vec::new();
    let mut exit = None;
    while started.elapsed() < Duration::from_secs(5) && exit.is_none() {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ProcessOutput {
                stream_id: STREAM_STDOUT,
                data,
                ..
            }) => stdout.extend(data),
            Ok(RnshEvent::ProcessExited { code, .. }) => exit = Some(code),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    assert_eq!(stdout, b"hello over stdin");
    assert_eq!(exit, Some(0));
}

#[test]
fn send_stream_chunks_splits_large_payload_and_appends_eof() {
    let fake = FakeTransport::default();
    let data = vec![0x55; STREAM_CHUNK_MAX * 2 + 3];

    send_stream_chunks(&fake, TEST_LINK, STREAM_STDOUT, &data, true).unwrap();

    let messages = fake.sent_messages();
    assert_eq!(messages.len(), 4);
    let mut payload = Vec::new();
    for (_, message) in &messages[..3] {
        match message {
            RnshMessage::StreamData(stream) => {
                assert_eq!(stream.stream_id, STREAM_STDOUT);
                assert!(!stream.eof);
                if payload.is_empty() {
                    assert_eq!(
                        stream.pack().len() + rns_core::constants::CHANNEL_ENVELOPE_OVERHEAD,
                        rns_core::constants::LINK_MDU
                    );
                }
                payload.extend_from_slice(&stream.data);
            }
            other => panic!("expected stream data, got {other:?}"),
        }
    }
    assert_eq!(payload, data);
    assert!(matches!(
        messages.last().unwrap().1,
        RnshMessage::StreamData(ref stream)
            if stream.stream_id == STREAM_STDOUT && stream.eof && stream.data.is_empty()
    ));
}

#[test]
fn process_pipe_mode_reports_stdout_stderr_and_exit() {
    let (tx, rx) = mpsc::channel();
    let link_id = [7u8; 16];
    let command = ExecuteCommand {
        cmdline: Vec::new(),
        pipe_stdin: true,
        pipe_stdout: true,
        pipe_stderr: true,
        term: None,
        rows: None,
        cols: None,
        hpix: None,
        vpix: None,
    };
    let _process = ChildProcess::spawn(
        link_id,
        &[
            "/bin/sh".into(),
            "-c".into(),
            "printf out; printf err >&2; exit 13".into(),
        ],
        &[],
        &command,
        tx,
    )
    .unwrap();

    let started = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    while started.elapsed() < Duration::from_secs(5) && exit.is_none() {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(RnshEvent::ProcessOutput {
                stream_id: STREAM_STDOUT,
                data,
                ..
            }) => stdout.extend(data),
            Ok(RnshEvent::ProcessOutput {
                stream_id: STREAM_STDERR,
                data,
                ..
            }) => stderr.extend(data),
            Ok(RnshEvent::ProcessExited { code, .. }) => exit = Some(code),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert_eq!(stdout, b"out");
    assert_eq!(stderr, b"err");
    assert_eq!(exit, Some(13));
}
