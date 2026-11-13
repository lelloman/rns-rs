use std::fs::{self, OpenOptions};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::{RpcAddr, RpcClient};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const FILE_SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
static HARNESS_START_LOCK: Mutex<()> = Mutex::new(());

struct TcpPortReservation {
    listener: TcpListener,
}

impl TcpPortReservation {
    fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").expect("reserve TCP test port"),
        }
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }
}

struct ProcessGuard {
    child: Child,
    log: PathBuf,
}

impl ProcessGuard {
    fn assert_running(&mut self, name: &str) {
        if let Some(status) = self.child.try_wait().expect("poll child") {
            panic!(
                "{name} exited early with {status}:\n{}",
                fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Harness {
    root: tempfile::TempDir,
    client_config: PathBuf,
    listener_config: PathBuf,
    client_home: PathBuf,
    listener_home: PathBuf,
    client_control_port: u16,
    /// Whether listeners wait until the client daemon learns their path. A
    /// filtering client daemon only learns it once a client asks for it.
    wait_for_client_paths: bool,
    _client_daemon: ProcessGuard,
    _listener_daemon: ProcessGuard,
}

impl Harness {
    fn start(label: &str) -> Self {
        Self::start_with_client_sections(label, "")
    }

    /// Start with extra config sections, such as `[filter]`, for the
    /// client-side shared instance.
    fn start_with_client_sections(label: &str, client_sections: &str) -> Self {
        // rnsd is a separate process, so the test cannot hand a bound listener
        // directly to it. Retain every reservation until its owning daemon is
        // ready to start, and serialize the short release/spawn handoff across
        // parallel harnesses in this test binary.
        let _startup_guard = HARNESS_START_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = tempfile::tempdir().expect("temporary integration directory");
        let client_config = root.path().join("client-reticulum");
        let listener_config = root.path().join("listener-reticulum");
        let client_home = root.path().join("client-home");
        let listener_home = root.path().join("listener-home");
        for directory in [
            &client_config,
            &listener_config,
            &client_home,
            &listener_home,
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let client_shared_reservation = TcpPortReservation::new();
        let listener_shared_reservation = TcpPortReservation::new();
        let client_control_reservation = TcpPortReservation::new();
        let listener_control_reservation = TcpPortReservation::new();
        let transport_reservation = TcpPortReservation::new();
        let client_shared_port = client_shared_reservation.port();
        let listener_shared_port = listener_shared_reservation.port();
        let client_control_port = client_control_reservation.port();
        let listener_control_port = listener_control_reservation.port();
        let transport_port = transport_reservation.port();
        let client_instance = format!("utility-{label}-client-{}", std::process::id());
        let listener_instance = format!("utility-{label}-listener-{}", std::process::id());
        fs::write(
            listener_config.join("config"),
            format!(
                "[reticulum]\n\
                 enable_transport = Yes\n\
                 share_instance = Yes\n\
                 instance_name = {listener_instance}\n\
                 shared_instance_port = {listener_shared_port}\n\
                 instance_control_port = {listener_control_port}\n\
                 discover_interfaces = No\n\
                 panic_on_interface_error = Yes\n\n\
                 [interfaces]\n\
                   [[utility server]]\n\
                     type = TCPServerInterface\n\
                     enabled = Yes\n\
                     listen_ip = 127.0.0.1\n\
                     listen_port = {transport_port}\n"
            ),
        )
        .unwrap();
        fs::write(
            client_config.join("config"),
            format!(
                "[reticulum]\n\
                 enable_transport = Yes\n\
                 share_instance = Yes\n\
                 instance_name = {client_instance}\n\
                 shared_instance_port = {client_shared_port}\n\
                 instance_control_port = {client_control_port}\n\
                 discover_interfaces = No\n\
                 panic_on_interface_error = Yes\n\n\
                 {client_sections}\n\
                 [interfaces]\n\
                   [[utility client]]\n\
                     type = TCPClientInterface\n\
                     enabled = Yes\n\
                     target_host = 127.0.0.1\n\
                     target_port = {transport_port}\n"
            ),
        )
        .unwrap();

        let listener_log = root.path().join("listener-rnsd.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rnsd"));
        command.args(["--config", &listener_config.to_string_lossy()]);
        command.env("HOME", &listener_home);
        drop(listener_shared_reservation);
        drop(listener_control_reservation);
        drop(transport_reservation);
        let mut listener_daemon = spawn_logged(command, &listener_log);
        wait_for_port(
            listener_control_port,
            &mut listener_daemon,
            "listener control port",
        );
        wait_for_port(transport_port, &mut listener_daemon, "transport listener");

        let client_log = root.path().join("client-rnsd.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rnsd"));
        command.args(["--config", &client_config.to_string_lossy()]);
        command.env("HOME", &client_home);
        drop(client_shared_reservation);
        drop(client_control_reservation);
        let mut client_daemon = spawn_logged(command, &client_log);
        wait_for_port(
            client_control_port,
            &mut client_daemon,
            "client control port",
        );
        thread::sleep(Duration::from_millis(250));

        Self {
            root,
            client_config,
            listener_config,
            client_home,
            listener_home,
            client_control_port,
            wait_for_client_paths: client_sections.is_empty(),
            _client_daemon: client_daemon,
            _listener_daemon: listener_daemon,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn rust_command(&self, binary: &str, side: Side) -> Command {
        let executable = match binary {
            "rncp" => env!("CARGO_BIN_EXE_rncp"),
            "rnsh" => env!("CARGO_BIN_EXE_rnsh"),
            "rnx" => env!("CARGO_BIN_EXE_rnx"),
            "rnpath" => env!("CARGO_BIN_EXE_rnpath"),
            _ => panic!("unknown Rust utility {binary}"),
        };
        let mut command = Command::new(executable);
        command.env("HOME", self.home(side));
        command
    }

    fn python_command(&self, utility: &str) -> Command {
        let mut command = Command::new("python3");
        command.args(["-m", &format!("RNS.Utilities.{utility}")]);
        command.env("PYTHONUNBUFFERED", "1");
        command
    }

    fn common_args(&self, identity: &Path, side: Side) -> [String; 4] {
        [
            "--config".into(),
            self.config(side).to_string_lossy().into_owned(),
            "-i".into(),
            identity.to_string_lossy().into_owned(),
        ]
    }

    fn destination(
        &self,
        implementation: Implementation,
        utility: &str,
        identity: &Path,
    ) -> String {
        let mut command = match implementation {
            Implementation::Rust => self.rust_command(utility, Side::Listener),
            Implementation::Python => self.python_command(utility),
        };
        command.args(self.common_args(identity, Side::Listener));
        command.arg("--print-identity");
        let output = run(command);
        assert_success(&output, "print listener identity");
        parse_destination(&output)
    }

    fn listener(
        &self,
        implementation: Implementation,
        utility: &str,
        identity: &Path,
        destination: &str,
        extra: &[String],
    ) -> ProcessGuard {
        let mut command = match implementation {
            Implementation::Rust => self.rust_command(utility, Side::Listener),
            Implementation::Python => self.python_command(utility),
        };
        if matches!(implementation, Implementation::Python) {
            // Upstream's default log level can suppress the informational
            // readiness line that the harness waits for.
            command.arg("--verbose");
        }
        command.args(self.common_args(identity, Side::Listener));
        command.arg("--listen");
        command.args(extra);
        let log = self.path(&format!("{utility}-{implementation:?}-listener.log"));
        let mut listener = spawn_logged(command, &log);
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            listener.assert_running(&format!("{implementation:?} {utility} listener"));
            let text = fs::read_to_string(&log).unwrap_or_default();
            let lower = text.to_ascii_lowercase();
            let upstream_rncp_ready = matches!(implementation, Implementation::Python)
                && utility == "rncp"
                // On a shared instance, pinned upstream versions can suppress
                // the subsequent LOG_INFO readiness line. This warning is
                // emitted after the destination is created and immediately
                // before its fetch handler is registered.
                && lower.contains("allowing unauthenticated fetch requests");
            if lower.contains("listening") || upstream_rncp_ready {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "listener did not become ready:\n{text}"
            );
            thread::sleep(Duration::from_millis(25));
        }
        // Upstream prints its readiness line immediately before issuing a
        // one-shot announce. Confirm that the client daemon has learned the
        // path, explicitly requesting it when the announce was missed under
        // CI load, before starting a short-lived utility client.
        if self.wait_for_client_paths {
            self.wait_for_client_path(destination, &listener);
        }
        listener
    }

    fn wait_for_client_path(&self, destination: &str, listener: &ProcessGuard) {
        let destination = parse_destination_hash(destination);
        let identity_path = self
            .client_config
            .join("storage")
            .join("identities")
            .join("identity");
        let identity = rns_net::storage::load_identity(&identity_path)
            .unwrap_or_else(|error| panic!("load client daemon identity: {error}"));
        let auth_key = derive_auth_key(
            &identity
                .get_private_key()
                .expect("client daemon identity has a private key"),
        );
        let address = RpcAddr::Tcp("127.0.0.1".into(), self.client_control_port);
        let deadline = Instant::now() + START_TIMEOUT;
        let mut requested = false;
        loop {
            if query_has_path(&address, &auth_key, &destination).unwrap_or(false) {
                return;
            }
            if !requested {
                request_path(&address, &auth_key, &destination)
                    .unwrap_or_else(|error| panic!("request listener path: {error}"));
                requested = true;
            }
            assert!(
                Instant::now() < deadline,
                "client daemon did not learn listener path:\nlistener:\n{}\nclient daemon:\n{}\nlistener daemon:\n{}",
                fs::read_to_string(&listener.log).unwrap_or_default(),
                fs::read_to_string(&self._client_daemon.log).unwrap_or_default(),
                fs::read_to_string(&self._listener_daemon.log).unwrap_or_default()
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn config(&self, side: Side) -> &Path {
        match side {
            Side::Client => &self.client_config,
            Side::Listener => &self.listener_config,
        }
    }

    fn home(&self, side: Side) -> &Path {
        match side {
            Side::Client => &self.client_home,
            Side::Listener => &self.listener_home,
        }
    }

    fn rnsh_command(&self, side: Side, app_config: &Path, identity: &Path) -> Command {
        let mut command = self.rust_command("rnsh", side);
        command
            .arg("--config")
            .arg(app_config)
            .arg("--rnsconfig")
            .arg(self.config(side))
            .arg("--identity")
            .arg(identity);
        command
    }
}

#[derive(Debug, Clone, Copy)]
enum Implementation {
    Rust,
    Python,
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Client,
    Listener,
}

fn wait_for_port(port: u16, process: &mut ProcessGuard, description: &str) {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        process.assert_running("rnsd");
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description} on {port}:\n{}",
            fs::read_to_string(&process.log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn parse_destination_hash(destination: &str) -> [u8; 16] {
    assert_eq!(destination.len(), 32, "invalid destination hash");
    let mut hash = [0u8; 16];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&destination[index * 2..index * 2 + 2], 16)
            .expect("destination hash is hexadecimal");
    }
    hash
}

fn query_has_path(
    address: &RpcAddr,
    auth_key: &[u8; 32],
    destination: &[u8; 16],
) -> Result<bool, String> {
    let mut client =
        RpcClient::connect(address, auth_key).map_err(|error| format!("RPC connect: {error}"))?;
    let response = client
        .call(&PickleValue::Dict(vec![
            (
                PickleValue::String("get".into()),
                PickleValue::String("next_hop".into()),
            ),
            (
                PickleValue::String("destination_hash".into()),
                PickleValue::Bytes(destination.to_vec()),
            ),
        ]))
        .map_err(|error| format!("RPC call: {error}"))?;
    Ok(response.as_bytes().is_some_and(|bytes| bytes.len() == 16))
}

fn request_path(
    address: &RpcAddr,
    auth_key: &[u8; 32],
    destination: &[u8; 16],
) -> Result<(), String> {
    let mut client =
        RpcClient::connect(address, auth_key).map_err(|error| format!("RPC connect: {error}"))?;
    client
        .call(&PickleValue::Dict(vec![(
            PickleValue::String("request_path".into()),
            PickleValue::Bytes(destination.to_vec()),
        )]))
        .map_err(|error| format!("RPC call: {error}"))?;
    Ok(())
}

fn spawn_logged(mut command: Command, log: &Path) -> ProcessGuard {
    let stdout = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(log)
        .unwrap();
    let stderr = stdout.try_clone().unwrap();
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(stderr));
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {:?}: {error}", command.get_program()));
    ProcessGuard {
        child,
        log: log.to_path_buf(),
    }
}

fn run(mut command: Command) -> Output {
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait().expect("poll command").is_some() {
            return child.wait_with_output().expect("collect command output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out output");
            panic!(
                "{program} timed out ({} stdout bytes):\nstdout prefix:\n{}\nstderr:\n{}",
                output.stdout.len(),
                String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(4096)]),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_success_with_process(
    output: &Output,
    operation: &str,
    process: &ProcessGuard,
    harness: &Harness,
) {
    assert!(
        output.status.success(),
        "{operation} failed with {}:\nstdout:\n{}\nstderr:\n{}\nlistener:\n{}\nclient daemon:\n{}\nlistener daemon:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&process.log).unwrap_or_default(),
        fs::read_to_string(&harness._client_daemon.log).unwrap_or_default(),
        fs::read_to_string(&harness._listener_daemon.log).unwrap_or_default()
    );
}

fn parse_destination(output: &Output) -> String {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in text.lines().filter(|line| line.contains("Listening on")) {
        if let (Some(start), Some(end)) = (line.rfind('<'), line.rfind('>')) {
            let hash = &line[start + 1..end];
            if hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return hash.to_string();
            }
        }
        if let Some(hash) = line.split_whitespace().last() {
            let hash = hash.trim_matches(['<', '>']);
            if hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return hash.to_string();
            }
        }
    }
    panic!("could not parse destination from:\n{text}");
}

fn patterned_file(path: &Path, size: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    fs::write(path, &data).unwrap();
    data
}

fn assert_file_contents(path: &Path, expected: &[u8]) {
    // A sender can observe Resource completion immediately before the receiver's
    // event loop persists the completed temporary file. Allow that asynchronous
    // handoff to settle instead of racing the listener under CI load.
    let deadline = Instant::now() + FILE_SETTLE_TIMEOUT;
    loop {
        match fs::read(path) {
            Ok(actual) if actual == expected => return,
            result if Instant::now() >= deadline => match result {
                Ok(actual) => {
                    let first_difference = actual
                        .iter()
                        .zip(expected)
                        .position(|(actual, expected)| actual != expected);
                    panic!(
                        "file contents differ after waiting {FILE_SETTLE_TIMEOUT:?}: actual length {}, expected length {}, first differing byte {:?}",
                        actual.len(),
                        expected.len(),
                        first_difference
                    );
                }
                Err(error) => panic!(
                    "{} did not become readable within {FILE_SETTLE_TIMEOUT:?}: {error}",
                    path.display()
                ),
            },
            _ => thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn rncp_send(
    harness: &Harness,
    implementation: Implementation,
    identity: &Path,
    source: &Path,
    destination: &str,
) -> Output {
    let mut command = match implementation {
        Implementation::Rust => harness.rust_command("rncp", Side::Client),
        Implementation::Python => harness.python_command("rncp"),
    };
    command.args(harness.common_args(identity, Side::Client));
    command.args(["-w", "30", "-S"]);
    command.arg(source);
    command.arg(destination);
    run(command)
}

fn rncp_fetch(
    harness: &Harness,
    implementation: Implementation,
    identity: &Path,
    requested: &str,
    destination: &str,
    save: &Path,
) -> Output {
    let mut command = match implementation {
        Implementation::Rust => harness.rust_command("rncp", Side::Client),
        Implementation::Python => harness.python_command("rncp"),
    };
    command.args(harness.common_args(identity, Side::Client));
    command.args(["-f", "-S", "-w", "30", "-s"]);
    command.arg(save);
    command.arg(requested);
    command.arg(destination);
    run(command)
}

fn rnx_execute(
    harness: &Harness,
    implementation: Implementation,
    identity: &Path,
    destination: &str,
    marker: &str,
) -> Output {
    rnx_execute_command(
        harness,
        implementation,
        identity,
        destination,
        &format!("/bin/printf {marker}"),
    )
}

fn rnx_execute_command(
    harness: &Harness,
    implementation: Implementation,
    identity: &Path,
    destination: &str,
    remote_command: &str,
) -> Output {
    let mut command = match implementation {
        Implementation::Rust => harness.rust_command("rnx", Side::Client),
        Implementation::Python => harness.python_command("rnx"),
    };
    command.args(harness.common_args(identity, Side::Client));
    command.args(["-w", "30"]);
    command.arg(destination);
    command.arg(remote_command);
    run(command)
}

fn assert_large_rnx_response(output: &Output, operation: &str) {
    assert_success(output, operation);
    assert!(
        output.stdout.len() > 3_000 && String::from_utf8_lossy(&output.stdout).contains("1000"),
        "{operation} did not return the expected Resource-sized output"
    );
}

#[test]
fn rust_rncp_send_and_fetch_end_to_end() {
    let harness = Harness::start("rust-rncp");
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("client.identity");
    let receive = harness.path("receive");
    let fetch_jail = harness.path("jail");
    let fetched = harness.path("fetched");
    fs::create_dir_all(&receive).unwrap();
    fs::create_dir_all(&fetch_jail).unwrap();
    fs::create_dir_all(&fetched).unwrap();
    let source = harness.path("streaming.bin");
    let source_data = patterned_file(&source, 2 * 1024 * 1024 + 73_001);
    let fetch_source = fetch_jail.join("fetch.bin");
    let fetch_data = patterned_file(&fetch_source, 131_071);
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let listener_args = vec![
        "--no-auth".into(),
        "--allow-fetch".into(),
        "--jail".into(),
        fetch_jail.to_string_lossy().into_owned(),
        "--save".into(),
        receive.to_string_lossy().into_owned(),
        "-b".into(),
        "1".into(),
    ];
    let _listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &listener_args,
    );

    let sent = rncp_send(
        &harness,
        Implementation::Rust,
        &client_identity,
        &source,
        &destination,
    );
    assert_success(&sent, "Rust rncp send");
    assert_file_contents(&receive.join("streaming.bin"), &source_data);

    let mut fetch = harness.rust_command("rncp", Side::Client);
    fetch.args(harness.common_args(&client_identity, Side::Client));
    fetch.args(["--fetch", "--silent", "--timeout", "30", "--save"]);
    fetch.arg(&fetched);
    fetch.arg("fetch.bin");
    fetch.arg(&destination);
    let fetched_output = run(fetch);
    assert_success(&fetched_output, "Rust rncp fetch");
    assert_file_contents(&fetched.join("fetch.bin"), &fetch_data);
}

#[test]
fn rust_rnx_executes_end_to_end() {
    let harness = Harness::start("rust-rnx");
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("client.identity");
    let destination = harness.destination(Implementation::Rust, "rnx", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rnx",
        &listener_identity,
        &destination,
        &["--noauth".into()],
    );
    let output = rnx_execute(
        &harness,
        Implementation::Rust,
        &client_identity,
        &destination,
        "rust-rnx-ok",
    );
    assert_success(&output, "Rust rnx execution");
    assert!(String::from_utf8_lossy(&output.stdout).contains("rust-rnx-ok"));
    let large = rnx_execute_command(
        &harness,
        Implementation::Rust,
        &client_identity,
        &destination,
        "/usr/bin/seq 1 1000",
    );
    assert_large_rnx_response(&large, "Rust rnx Resource response");
}

#[test]
fn rust_rnsh_delivers_burst_output_and_reuses_listener() {
    const OUTPUT_SIZE: usize = 16 * 1024;

    let harness = Harness::start("rust-rnsh-backpressure");
    let listener_identity = harness.path("rnsh-listener.identity");
    let client_identity = harness.path("rnsh-client.identity");
    let listener_app_config = harness.path("rnsh-listener");
    let client_app_config = harness.path("rnsh-client");

    let mut identity_command =
        harness.rnsh_command(Side::Listener, &listener_app_config, &listener_identity);
    identity_command.args(["--listen", "--print-identity"]);
    let identity_output = run(identity_command);
    assert_success(&identity_output, "print rnsh listener identity");
    let destination = parse_destination(&identity_output);

    let mut listener_command =
        harness.rnsh_command(Side::Listener, &listener_app_config, &listener_identity);
    listener_command.args([
        "--verbose",
        "--listen",
        "--no-auth",
        "--announce",
        "0",
        "--",
        "/bin/sh",
    ]);
    let listener_log = harness.path("rnsh-listener.log");
    let mut listener = spawn_logged(listener_command, &listener_log);
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        listener.assert_running("rnsh listener");
        if fs::read_to_string(&listener_log)
            .unwrap_or_default()
            .contains("rnsh listening on")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "rnsh listener did not become ready:\n{}",
            fs::read_to_string(&listener_log).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(25));
    }
    harness.wait_for_client_path(&destination, &listener);

    let mut burst = harness.rnsh_command(Side::Client, &client_app_config, &client_identity);
    burst.args([
        &destination,
        "--",
        "/bin/sh",
        "-c",
        &format!("head -c {OUTPUT_SIZE} /dev/zero"),
    ]);
    let burst_output = run(burst);
    assert_success_with_process(&burst_output, "rnsh burst output", &listener, &harness);
    assert_eq!(burst_output.stdout.len(), OUTPUT_SIZE);
    assert!(burst_output.stdout.iter().all(|byte| *byte == 0));
    assert!(
        fs::read_to_string(listener_app_config.join("logfile"))
            .unwrap_or_default()
            .contains("Channel send failed: NotReady"),
        "burst did not exercise channel backpressure"
    );
    listener.assert_running("rnsh listener after burst output");

    let mut followup = harness.rnsh_command(Side::Client, &client_app_config, &client_identity);
    followup.args([&destination, "--", "/bin/printf", "rnsh-still-available"]);
    let followup_output = run(followup);
    assert_success_with_process(
        &followup_output,
        "rnsh follow-up session",
        &listener,
        &harness,
    );
    assert_eq!(followup_output.stdout, b"rnsh-still-available");
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rncp_client_sends_to_rust_listener() {
    let harness = Harness::start("python-to-rust-rncp");
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("python-client.identity");
    let receive = harness.path("receive");
    let jail = harness.path("jail");
    let fetched = harness.path("fetched");
    fs::create_dir_all(&receive).unwrap();
    fs::create_dir_all(&jail).unwrap();
    fs::create_dir_all(&fetched).unwrap();
    let source = harness.path("python-send.bin");
    let expected = patterned_file(&source, 196_613);
    let fetch_source = jail.join("rust-fetch.bin");
    let fetch_expected = patterned_file(&fetch_source, 98_309);
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "--allow-fetch".into(),
            "--jail".into(),
            jail.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );
    let output = rncp_send(
        &harness,
        Implementation::Python,
        &client_identity,
        &source,
        &destination,
    );
    assert_success(&output, "Python rncp to Rust listener");
    assert_eq!(fs::read(receive.join("python-send.bin")).unwrap(), expected);
    let output = rncp_fetch(
        &harness,
        Implementation::Python,
        &client_identity,
        "rust-fetch.bin",
        &destination,
        &fetched,
    );
    assert_success(&output, "Python rncp fetch from Rust listener");
    assert_eq!(
        fs::read(fetched.join("rust-fetch.bin")).unwrap(),
        fetch_expected
    );
}

/// Upstream 825c2e19: a shared instance with `[filter] required_only`
/// drops announces of destination types no local application asked for.
const REQUIRED_ONLY_FILTER: &str = "[filter]\nrequired_only = Yes\n";

#[test]
fn rust_rncp_client_registers_with_a_filtering_shared_instance() {
    let harness = Harness::start_with_client_sections("rust-rncp-filtered", REQUIRED_ONLY_FILTER);
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("client.identity");
    let receive = harness.path("receive");
    fs::create_dir_all(&receive).unwrap();
    let source = harness.path("filtered.bin");
    let expected = patterned_file(&source, 65_537);
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );
    let output = rncp_send(
        &harness,
        Implementation::Rust,
        &client_identity,
        &source,
        &destination,
    );
    assert_success(&output, "Rust rncp through a filtering shared instance");
    assert_eq!(fs::read(receive.join("filtered.bin")).unwrap(), expected);
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rncp_client_registers_with_a_filtering_rust_instance() {
    let mut probe = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    probe.env("PYTHONUNBUFFERED", "1");
    probe.args([
        "-c",
        "import RNS; print(hasattr(RNS.Reticulum, 'wants_destination_type'))",
    ]);
    let probe = probe.output().unwrap();
    assert_success(&probe, "probe Reticulum.wants_destination_type");
    if String::from_utf8_lossy(&probe.stdout).trim() != "True" {
        eprintln!("Python Reticulum predates destination type filtering; skipping");
        return;
    }

    let harness = Harness::start_with_client_sections("python-rncp-filtered", REQUIRED_ONLY_FILTER);
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("python-client.identity");
    let receive = harness.path("receive");
    fs::create_dir_all(&receive).unwrap();
    let source = harness.path("python-filtered.bin");
    let expected = patterned_file(&source, 65_537);
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );
    let output = rncp_send(
        &harness,
        Implementation::Python,
        &client_identity,
        &source,
        &destination,
    );
    assert_success(&output, "Python rncp through a filtering Rust instance");
    assert_eq!(
        fs::read(receive.join("python-filtered.bin")).unwrap(),
        expected
    );
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_rncp_client_sends_to_python_listener() {
    let harness = Harness::start("rust-to-python-rncp");
    let listener_identity = harness.path("python-listener.identity");
    let client_identity = harness.path("rust-client.identity");
    let receive = harness.path("receive");
    let jail = harness.path("jail");
    let fetched = harness.path("fetched");
    fs::create_dir_all(&receive).unwrap();
    fs::create_dir_all(&jail).unwrap();
    fs::create_dir_all(&fetched).unwrap();
    let source = harness.path("rust-send.bin");
    let expected = patterned_file(&source, 196_621);
    let fetch_source = jail.join("python-fetch.bin");
    let fetch_expected = patterned_file(&fetch_source, 98_317);
    let destination = harness.destination(Implementation::Python, "rncp", &listener_identity);
    let listener = harness.listener(
        Implementation::Python,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "--allow-fetch".into(),
            "--jail".into(),
            jail.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );
    let output = rncp_send(
        &harness,
        Implementation::Rust,
        &client_identity,
        &source,
        &destination,
    );
    assert_success_with_process(&output, "Rust rncp to Python listener", &listener, &harness);
    assert_eq!(fs::read(receive.join("rust-send.bin")).unwrap(), expected);
    let output = rncp_fetch(
        &harness,
        Implementation::Rust,
        &client_identity,
        "python-fetch.bin",
        &destination,
        &fetched,
    );
    assert_success_with_process(
        &output,
        "Rust rncp fetch from Python listener",
        &listener,
        &harness,
    );
    assert_eq!(
        fs::read(fetched.join("python-fetch.bin")).unwrap(),
        fetch_expected
    );
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnx_client_executes_on_rust_listener() {
    let harness = Harness::start("python-to-rust-rnx");
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("python-client.identity");
    let destination = harness.destination(Implementation::Rust, "rnx", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rnx",
        &listener_identity,
        &destination,
        &["--noauth".into()],
    );
    let output = rnx_execute(
        &harness,
        Implementation::Python,
        &client_identity,
        &destination,
        "python-rnx-ok",
    );
    assert_success(&output, "Python rnx to Rust listener");
    assert!(String::from_utf8_lossy(&output.stdout).contains("python-rnx-ok"));

    // Each Python utility invocation is a new shared client. A rapid second
    // request for the same destination can fall inside the path-request
    // suppression interval after missing the listener's one-shot announce.
    // Use an independently announced destination to exercise the large
    // Resource response without depending on path cache timing.
    let large_listener_identity = harness.path("large-listener.identity");
    let large_destination =
        harness.destination(Implementation::Rust, "rnx", &large_listener_identity);
    let _large_listener = harness.listener(
        Implementation::Rust,
        "rnx",
        &large_listener_identity,
        &large_destination,
        &["--noauth".into()],
    );
    let large = rnx_execute_command(
        &harness,
        Implementation::Python,
        &client_identity,
        &large_destination,
        "/usr/bin/seq 1 1000",
    );
    assert_large_rnx_response(&large, "Python rnx Resource response from Rust");
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_rnx_client_executes_on_python_listener() {
    let harness = Harness::start("rust-to-python-rnx");
    let listener_identity = harness.path("python-listener.identity");
    let client_identity = harness.path("rust-client.identity");
    let destination = harness.destination(Implementation::Python, "rnx", &listener_identity);
    let _listener = harness.listener(
        Implementation::Python,
        "rnx",
        &listener_identity,
        &destination,
        &["--noauth".into()],
    );
    let output = rnx_execute(
        &harness,
        Implementation::Rust,
        &client_identity,
        &destination,
        "rust-python-rnx-ok",
    );
    assert_success(&output, "Rust rnx to Python listener");
    assert!(String::from_utf8_lossy(&output.stdout).contains("rust-python-rnx-ok"));
    let large = rnx_execute_command(
        &harness,
        Implementation::Rust,
        &client_identity,
        &destination,
        "/usr/bin/seq 1 1000",
    );
    assert_large_rnx_response(&large, "Rust rnx Resource response from Python");
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rns_is_available_for_utility_interop() {
    let mut command = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    command.env("PYTHONUNBUFFERED", "1");
    command.args(["-c", "import RNS, RNS.Utilities.rncp, RNS.Utilities.rnx"]);
    assert_success(&run(command), "import Python RNS utilities");
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnpath_lists_rust_path_table() {
    // Since rgit 21170877 Python's rnpath reads `value` and `lr_cost` from
    // every path table entry, so a daemon without them breaks `rnpath -t`.
    let harness = Harness::start("python-rnpath");
    let listener_identity = harness.path("listener.identity");
    let receive = harness.path("receive");
    fs::create_dir_all(&receive).unwrap();
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );

    // With -u, every line ends with its usage (upstream db67adea printed
    // the suffix it computed); rns-rs sends `used` on every entry, so none
    // reads "no usage info". Releases without -u skip this.
    if python_rnpath_source_contains("\"--usage\"") {
        let mut command = harness.python_command("rnpath");
        command.args([
            "--config",
            harness.client_config.to_str().unwrap(),
            "-t",
            "-u",
        ]);
        let output = run(command);
        assert_success(&output, "Python rnpath -t -u against the Rust daemon");
        let usage = String::from_utf8_lossy(&output.stdout);
        let line = usage
            .lines()
            .find(|line| line.contains(&destination))
            .unwrap_or_else(|| panic!("rnpath -u did not list {destination}:\n{usage}"));
        if python_rnpath_source_contains("{u_str}") {
            assert!(
                line.ends_with(", never used")
                    || (line.contains(", last used ") && line.ends_with(" ago")),
                "unexpected rnpath -u line: {line}"
            );
        }
        assert!(!usage.contains("no usage info"), "{usage}");
    }

    let mut command = harness.python_command("rnpath");
    command.args(["--config", harness.client_config.to_str().unwrap(), "-t"]);
    let output = run(command);
    assert_success(&output, "Python rnpath -t against the Rust daemon");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.contains(&destination))
        .unwrap_or_else(|| panic!("rnpath did not list {destination}:\n{stdout}"));

    let mut probe = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    probe.env("PYTHONUNBUFFERED", "1");
    probe.args(["-c", "import RNS; print(hasattr(RNS, 'prettycost'))"]);
    let probe = run(probe);
    assert_success(&probe, "probe RNS.prettycost");
    if String::from_utf8_lossy(&probe.stdout).trim() == "True" {
        // The listener's destination is a known destination of the client
        // daemon, so its stamp value is reported; it announces no link
        // request cost. `prettycost` prints a missing value as `?`, and as
        // `n` since rgit `d5891fde`.
        let missing = ["?", "n"];
        assert!(
            line.contains("(dv:")
                && !missing.iter().any(|m| line.contains(&format!("(dv:{m}/")))
                && missing.iter().any(|m| line.ends_with(&format!("/lc:{m})"))),
            "unexpected rnpath line: {line}"
        );
    }
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnpath_manages_rust_blackhole() {
    // Python's rnpath -B/-b/-U use the blackhole_identity,
    // blackholed_identities and unblackhole_identity RPC calls (upstream
    // since 1.1.0). The Rust rnpath lists the same entry.
    let harness = Harness::start("python-rnpath-blackhole");
    let identity = "0123456789abcdef0123456789abcdef";
    let config = harness.client_config.to_str().unwrap().to_string();
    let python = |args: &[&str]| {
        let mut command = harness.python_command("rnpath");
        command.args(["--config", &config]).args(args);
        let output = run(command);
        assert_success(&output, &format!("Python rnpath {args:?}"));
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let added = python(&["-B", identity, "--duration", "1", "--reason", "spam"]);
    assert!(
        added.contains(&format!("Blackholed identity {identity}")),
        "{added}"
    );
    // An application on the shared instance asks with `is_blackholed`.
    let mut is_blackholed = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    is_blackholed.env("PYTHONUNBUFFERED", "1");
    is_blackholed.args([
        "-c",
        "import RNS, sys; r = RNS.Reticulum(sys.argv[1]); \
         print(r.is_blackholed(bytes.fromhex(sys.argv[2])), \
         r.is_blackholed(bytes(16)))",
        &config,
        identity,
    ]);
    let is_blackholed = run(is_blackholed);
    assert_success(&is_blackholed, "Python Reticulum.is_blackholed");
    // Reticulum logs to stdout as well, so look for the printed line.
    let stdout = String::from_utf8_lossy(&is_blackholed.stdout);
    assert!(
        stdout.lines().any(|line| line.trim() == "True False"),
        "{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&is_blackholed.stderr)
    );

    let again = python(&["-B", identity]);
    assert!(
        again.contains(&format!("Identity {identity} already blackholed")),
        "{again}"
    );

    let listed = python(&["-b"]);
    let line = listed
        .lines()
        .find(|line| line.contains(identity))
        .unwrap_or_else(|| panic!("Python rnpath -b did not list {identity}:\n{listed}"));
    // No " by <source>" check: on an instance with transport off, upstream
    // too records its ephemeral transport identity as the source of local
    // entries (Transport.py:442), which a client process never matches.
    assert!(
        line.contains("blackholed for") && line.contains("(spam)"),
        "{line}"
    );

    let mut rust = harness.rust_command("rnpath", Side::Client);
    rust.args(["--config", &config, "-b"]);
    let rust_listed = run(rust);
    assert_success(&rust_listed, "Rust rnpath -b");
    let rust_listed = String::from_utf8_lossy(&rust_listed.stdout);
    assert!(
        rust_listed
            .lines()
            .any(|line| line.contains(identity) && line.contains("(spam)")),
        "{rust_listed}"
    );

    let lifted = python(&["-U", identity]);
    assert!(
        lifted.contains(&format!("Lifted blackhole for identity {identity}")),
        "{lifted}"
    );
    let not_listed = python(&["-U", identity]);
    assert!(
        not_listed.contains(&format!("Identity {identity} not blackholed")),
        "{not_listed}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_rnstatus_reaches_python_instance_on_unix_sockets() {
    // On Linux a Python shared instance serves RPC only on the abstract
    // socket \0rns/<instance>/rpc, with no TCP control port. The Rust
    // utilities reach it there.
    let root = tempfile::tempdir().unwrap();
    let instance = format!("rs-unix-rpc-{}", std::process::id());
    let (shared_port, control_port) = {
        let shared = TcpPortReservation::new();
        let control = TcpPortReservation::new();
        (shared.port(), control.port())
    };
    fs::write(
        root.path().join("config"),
        format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = {instance}\n  shared_instance_port = {shared_port}\n  \
             instance_control_port = {control_port}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[Default Interface]]\n    type = AutoInterface\n    \
             enabled = No\n"
        ),
    )
    .unwrap();
    let config = root.path().to_str().unwrap().to_string();
    let mut rnsd = Command::new("python3");
    rnsd.args(["-m", "RNS.Utilities.rnsd", "--config", &config])
        .env("PYTHONUNBUFFERED", "1");
    let mut daemon = spawn_logged(rnsd, &root.path().join("python-rnsd.log"));

    let deadline = Instant::now() + START_TIMEOUT;
    let stdout = loop {
        daemon.assert_running("Python rnsd");
        let mut rnstatus = Command::new(env!("CARGO_BIN_EXE_rnstatus"));
        rnstatus.args(["--config", &config]);
        let output = run(rnstatus);
        if output.status.success() {
            break String::from_utf8_lossy(&output.stdout).into_owned();
        }
        if Instant::now() >= deadline {
            panic!(
                "Rust rnstatus never reached the Python instance:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        TcpStream::connect(("127.0.0.1", control_port)).is_err(),
        "the Python instance unexpectedly serves RPC on TCP"
    );
    assert!(
        stdout.contains(&format!("Shared Instance[rns/{instance}]")),
        "{stdout}"
    );
}

/// Wait until a Linux abstract socket named `name` is listening.
#[cfg(target_os = "linux")]
fn wait_for_abstract_socket(name: &str, process: &mut ProcessGuard, description: &str) {
    let needle = format!("@{name}");
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        process.assert_running(description);
        let listening = fs::read_to_string("/proc/net/unix")
            .unwrap_or_default()
            .lines()
            .any(|line| line.split_whitespace().last() == Some(needle.as_str()));
        if listening {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{description} did not open {needle}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq)]
enum Daemon {
    Python,
    Rust,
}

#[cfg(target_os = "linux")]
/// Fetch a blackhole list from a publisher run by one implementation into
/// a node with `blackhole_sources` run by the other, over TCP. The fetcher
/// starts 20 seconds after startup, as upstream's does.
fn blackhole_source_fetch(publisher: Daemon, fetcher: Daemon) {
    let root = tempfile::tempdir().unwrap();
    let publisher_dir = root.path().join("publisher");
    let fetcher_dir = root.path().join("fetcher");
    fs::create_dir_all(publisher_dir.join("storage/identities")).unwrap();
    fs::create_dir_all(&fetcher_dir).unwrap();
    let blackholed = "0123456789abcdef0123456789abcdef";

    // The publisher's identity, where each implementation reads it, and a
    // blackhole list of one entry in upstream's format.
    let identity_file = match publisher {
        Daemon::Python => "storage/transport_identity",
        Daemon::Rust => "storage/identities/identity",
    };
    let mut prepare = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    prepare.env("PYTHONUNBUFFERED", "1");
    prepare.args([
        "-c",
        "import RNS, os, sys; from RNS.vendor import umsgpack; \
         i = RNS.Identity(); i.to_file(os.path.join(sys.argv[1], sys.argv[2])); \
         os.makedirs(os.path.join(sys.argv[1], 'storage', 'blackhole'), exist_ok=True); \
         open(os.path.join(sys.argv[1], 'storage', 'blackhole', 'local'), 'wb').write(\
         umsgpack.packb({bytes.fromhex(sys.argv[3]): \
         {'source': i.hash, 'until': None, 'reason': 'interop'}})); \
         print(i.hash.hex())",
        publisher_dir.to_str().unwrap(),
        identity_file,
        blackholed,
    ]);
    let prepared = run(prepare);
    assert_success(&prepared, "prepare blackhole publisher");
    let source = String::from_utf8_lossy(&prepared.stdout)
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert_eq!(source.len(), 32, "publisher identity hash: {source:?}");

    let ports: Vec<TcpPortReservation> = (0..5).map(|_| TcpPortReservation::new()).collect();
    let port = |i: usize| ports[i].port();
    let (transport_port, pub_shared, pub_control, fetch_shared, fetch_control) =
        (port(0), port(1), port(2), port(3), port(4));
    let pid = std::process::id();
    let label = if publisher == Daemon::Python {
        "py-rs"
    } else {
        "rs-py"
    };
    fs::write(
        publisher_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = Yes\n  share_instance = Yes\n  \
             instance_name = bh-publisher-{label}-{pid}\n  shared_instance_port = {pub_shared}\n  \
             instance_control_port = {pub_control}\n  publish_blackhole = Yes\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[publisher server]]\n    type = TCPServerInterface\n    \
             enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {transport_port}\n"
        ),
    )
    .unwrap();
    fs::write(
        fetcher_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = bh-fetcher-{label}-{pid}\n  shared_instance_port = {fetch_shared}\n  \
             instance_control_port = {fetch_control}\n  blackhole_sources = {source}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[fetcher client]]\n    type = TCPClientInterface\n    \
             enabled = Yes\n    target_host = 127.0.0.1\n    target_port = {transport_port}\n"
        ),
    )
    .unwrap();
    drop(ports);

    let daemon = |implementation: Daemon, dir: &Path, log: &str| {
        let config = dir.to_str().unwrap().to_string();
        let command = match implementation {
            Daemon::Python => {
                let mut command = Command::new("python3");
                command
                    .args(["-m", "RNS.Utilities.rnsd", "--config", &config])
                    .env("PYTHONUNBUFFERED", "1");
                command
            }
            Daemon::Rust => {
                let mut command = Command::new(env!("CARGO_BIN_EXE_rnsd"));
                command.args(["--config", &config]);
                command
            }
        };
        spawn_logged(command, &root.path().join(log))
    };
    let mut publisher_daemon = daemon(publisher, &publisher_dir, "publisher.log");
    wait_for_port(
        transport_port,
        &mut publisher_daemon,
        "publisher TCP server",
    );
    let mut fetcher_daemon = daemon(fetcher, &fetcher_dir, "fetcher.log");
    // A Python utility started before the daemon is up would become the
    // shared instance itself and leave the daemon a client of it.
    wait_for_abstract_socket(
        &format!("rns/bh-fetcher-{label}-{pid}"),
        &mut fetcher_daemon,
        "fetcher shared instance",
    );

    // Each implementation's rnpath lists the fetcher's blackhole entries.
    let fetcher_config = fetcher_dir.to_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        publisher_daemon.assert_running("publisher");
        fetcher_daemon.assert_running("fetcher");
        let mut rnpath = match fetcher {
            Daemon::Python => {
                let mut command = Command::new("python3");
                // Reticulum swaps stdout for /dev/null when it exits, which can drop
                // buffered output; print it as it is written.
                command.env("PYTHONUNBUFFERED", "1");
                command.args(["-m", "RNS.Utilities.rnpath"]);
                command
            }
            Daemon::Rust => Command::new(env!("CARGO_BIN_EXE_rnpath")),
        };
        rnpath.args(["--config", &fetcher_config, "-b"]);
        let listed = run(rnpath);
        let stdout = String::from_utf8_lossy(&listed.stdout);
        if let Some(line) = stdout.lines().find(|line| line.contains(blackholed)) {
            assert!(line.contains("(interop)"), "{line}");
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "the fetcher never listed the blackholed identity:\n{stdout}\n\
                 publisher log:\n{}\nfetcher log:\n{}",
                fs::read_to_string(root.path().join("publisher.log")).unwrap_or_default(),
                fs::read_to_string(root.path().join("fetcher.log")).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_secs(1));
    }
    // The source's list is saved where the next start loads it from.
    let saved = fetcher_dir.join("storage/blackhole").join(&source);
    let deadline = Instant::now() + FILE_SETTLE_TIMEOUT;
    while !saved.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(saved.exists(), "{} was not written", saved.display());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_instance_fetches_python_blackhole_source() {
    blackhole_source_fetch(Daemon::Python, Daemon::Rust);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_instance_fetches_rust_blackhole_source() {
    blackhole_source_fetch(Daemon::Rust, Daemon::Python);
}

/// Start an rnsd of `implementation` on the config directory `dir`.
#[cfg(target_os = "linux")]
fn spawn_daemon(implementation: Daemon, dir: &Path, log: &Path) -> ProcessGuard {
    let config = dir.to_str().unwrap().to_string();
    let command = match implementation {
        Daemon::Python => {
            let mut command = Command::new("python3");
            command
                .args(["-m", "RNS.Utilities.rnsd", "--config", &config])
                .env("PYTHONUNBUFFERED", "1");
            command
        }
        Daemon::Rust => {
            let mut command = Command::new(env!("CARGO_BIN_EXE_rnsd"));
            command.args(["--config", &config]);
            command
        }
    };
    spawn_logged(command, log)
}

/// An encrypted discovery announce (`discovery_encrypt`) from a publisher
/// run by one implementation is read by a receiver run by the other, both
/// holding the same `network_identity`.
#[cfg(target_os = "linux")]
fn encrypted_discovery(publisher: Daemon, receiver: Daemon) {
    let root = tempfile::tempdir().unwrap();
    let publisher_dir = root.path().join("publisher");
    let receiver_dir = root.path().join("receiver");
    fs::create_dir_all(&publisher_dir).unwrap();
    fs::create_dir_all(&receiver_dir).unwrap();
    let network_identity = root.path().join("network_identity");
    let mut prepare = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    prepare.env("PYTHONUNBUFFERED", "1");
    prepare.args([
        "-c",
        "import RNS, sys; RNS.Identity().to_file(sys.argv[1])",
        network_identity.to_str().unwrap(),
    ]);
    assert_success(&run(prepare), "create network identity");

    let ports: Vec<TcpPortReservation> = (0..6).map(|_| TcpPortReservation::new()).collect();
    let port = |i: usize| ports[i].port();
    let (transport_port, pub_shared, pub_control, recv_shared, recv_control, discovery_port) =
        (port(0), port(1), port(2), port(3), port(4), port(5));
    let pid = std::process::id();
    let label = if publisher == Daemon::Python {
        "py-rs"
    } else {
        "rs-py"
    };
    let identity = network_identity.to_str().unwrap();
    let name = "Encrypted Discovery Test";
    fs::write(
        publisher_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = Yes\n  share_instance = Yes\n  \
             instance_name = disc-publisher-{label}-{pid}\n  shared_instance_port = {pub_shared}\n  \
             instance_control_port = {pub_control}\n  network_identity = {identity}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[discovery server]]\n    type = TCPServerInterface\n    \
             enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {discovery_port}\n    \
             discoverable = Yes\n    discovery_name = {name}\n    \
             reachable_on = example.com\n    discovery_stamp_value = 2\n    \
             discovery_encrypt = Yes\n  \
             [[link to receiver]]\n    type = TCPClientInterface\n    enabled = Yes\n    \
             target_host = 127.0.0.1\n    target_port = {transport_port}\n"
        ),
    )
    .unwrap();
    fs::write(
        receiver_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = disc-receiver-{label}-{pid}\n  shared_instance_port = {recv_shared}\n  \
             instance_control_port = {recv_control}\n  network_identity = {identity}\n  \
             discover_interfaces = Yes\n  required_discovery_value = 2\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[publisher link]]\n    type = TCPServerInterface\n    \
             enabled = Yes\n    listen_ip = 127.0.0.1\n    listen_port = {transport_port}\n"
        ),
    )
    .unwrap();
    drop(ports);

    // The receiver listens and the publisher connects to it as it starts,
    // so the link is up before the publisher's first discovery announce,
    // which comes right after startup and then only every six hours.
    let mut receiver_daemon =
        spawn_daemon(receiver, &receiver_dir, &root.path().join("receiver.log"));
    wait_for_port(transport_port, &mut receiver_daemon, "receiver TCP server");
    wait_for_abstract_socket(
        &format!("rns/disc-receiver-{label}-{pid}"),
        &mut receiver_daemon,
        "receiver shared instance",
    );
    let mut publisher_daemon = spawn_daemon(
        publisher,
        &publisher_dir,
        &root.path().join("publisher.log"),
    );

    // Upstream's announcer waits a minute before its first announce.
    let receiver_config = receiver_dir.to_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        publisher_daemon.assert_running("publisher");
        receiver_daemon.assert_running("receiver");
        let mut rnstatus = match receiver {
            Daemon::Python => {
                let mut command = Command::new("python3");
                // Reticulum swaps stdout for /dev/null when it exits, which can drop
                // buffered output; print it as it is written.
                command.env("PYTHONUNBUFFERED", "1");
                command.args(["-m", "RNS.Utilities.rnstatus"]);
                command
            }
            Daemon::Rust => {
                // Releases before upstream sent its implementation in
                // discovery announces are listed only on request.
                let mut command = Command::new(env!("CARGO_BIN_EXE_rnstatus"));
                command.arg("--show-unknown");
                command
            }
        };
        rnstatus.args(["--config", &receiver_config, "-d"]);
        let listed = run(rnstatus);
        let stdout = String::from_utf8_lossy(&listed.stdout);
        if stdout.contains(name) {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "the receiver never listed the encrypted discovered interface:\n{stdout}\n\
                 publisher log:\n{}\nreceiver log:\n{}",
                fs::read_to_string(root.path().join("publisher.log")).unwrap_or_default(),
                fs::read_to_string(root.path().join("receiver.log")).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// A shared instance with `shared_instance_type = tcp` and an `rpc_key`,
/// run by one implementation, answers the other's rnstatus over TCP. The
/// client runs from a copy of the config without the daemon's storage, so
/// only the configured key, not one derived from the daemon's transport
/// identity, authenticates it.
#[cfg(target_os = "linux")]
fn tcp_shared_instance_with_rpc_key(daemon: Daemon) {
    let root = tempfile::tempdir().unwrap();
    let daemon_dir = root.path().join("daemon");
    let client_dir = root.path().join("client");
    fs::create_dir_all(&daemon_dir).unwrap();
    fs::create_dir_all(&client_dir).unwrap();
    let (shared_port, control_port) = {
        let shared = TcpPortReservation::new();
        let control = TcpPortReservation::new();
        (shared.port(), control.port())
    };
    let instance = format!("tcp-rpc-key-{}-{}", daemon as u8, std::process::id());
    let config = format!(
        "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
         instance_name = {instance}\n  shared_instance_type = tcp\n  \
         shared_instance_port = {shared_port}\n  instance_control_port = {control_port}\n  \
         rpc_key = 5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e\n\
         [logging]\n  loglevel = 4\n\
         [interfaces]\n"
    );
    fs::write(daemon_dir.join("config"), &config).unwrap();
    fs::write(client_dir.join("config"), &config).unwrap();

    let mut daemon_process = spawn_daemon(daemon, &daemon_dir, &root.path().join("daemon.log"));
    wait_for_port(control_port, &mut daemon_process, "TCP RPC port");
    // No abstract sockets with shared_instance_type = tcp.
    let unix_sockets = fs::read_to_string("/proc/net/unix").unwrap_or_default();
    assert!(
        !unix_sockets.contains(&format!("@rns/{instance}")),
        "the shared instance opened an abstract socket"
    );

    let client_config = client_dir.to_str().unwrap().to_string();
    let mut rnstatus = match daemon {
        Daemon::Python => Command::new(env!("CARGO_BIN_EXE_rnstatus")),
        Daemon::Rust => {
            let mut command = Command::new("python3");
            // Reticulum swaps stdout for /dev/null when it exits, which can drop
            // buffered output; print it as it is written.
            command.env("PYTHONUNBUFFERED", "1");
            command.args(["-m", "RNS.Utilities.rnstatus"]);
            command
        }
    };
    rnstatus.args(["--config", &client_config]);
    let output = run(rnstatus);
    daemon_process.assert_running("daemon");
    assert_success(
        &output,
        "rnstatus against a TCP shared instance with an RPC key",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Could not get") && !stdout.contains("No shared"),
        "{stdout}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_rnstatus_reaches_python_tcp_instance_with_rpc_key() {
    tcp_shared_instance_with_rpc_key(Daemon::Python);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnstatus_reaches_rust_tcp_instance_with_rpc_key() {
    tcp_shared_instance_with_rpc_key(Daemon::Rust);
}

/// A Rust node with `autoconnect_discovered_interfaces` auto-connects the
/// Backbone interface a Python node announces, under the default upstream
/// policy. The Python node listens for the Rust node's link, so the link is
/// up before Python's first discovery announce a minute after startup.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_instance_autoconnects_python_discovered_backbone() {
    // Upstream auto-connects `RNS` announcers from 1.5.7 on.
    let mut version = Command::new("python3");
    version.args(["-c", "import RNS; print(RNS.__version__)"]);
    let version = run(version);
    let version: Vec<u32> = String::from_utf8_lossy(&version.stdout)
        .trim()
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect();
    if version.as_slice() < [1, 5, 7].as_slice() {
        eprintln!("Python Reticulum {version:?} predates auto-connect qualification; skipping");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let python_dir = root.path().join("python");
    let rust_dir = root.path().join("rust");
    fs::create_dir_all(&python_dir).unwrap();
    fs::create_dir_all(&rust_dir).unwrap();
    let ports: Vec<TcpPortReservation> = (0..6).map(|_| TcpPortReservation::new()).collect();
    let port = |i: usize| ports[i].port();
    let (link_port, backbone_port, py_shared, py_control, rs_shared, rs_control) =
        (port(0), port(1), port(2), port(3), port(4), port(5));
    let pid = std::process::id();
    let name = "Python Backbone Target";
    fs::write(
        python_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = Yes\n  share_instance = Yes\n  \
             instance_name = ac-python-{pid}\n  shared_instance_port = {py_shared}\n  \
             instance_control_port = {py_control}\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[python backbone]]\n    type = BackboneInterface\n    \
             enabled = Yes\n    listen_on = ::\n    port = {backbone_port}\n    \
             discoverable = Yes\n    discovery_name = {name}\n    \
             reachable_on = localhost\n    discovery_stamp_value = 2\n  \
             [[link server]]\n    type = TCPServerInterface\n    enabled = Yes\n    \
             listen_ip = 127.0.0.1\n    listen_port = {link_port}\n"
        ),
    )
    .unwrap();
    fs::write(
        rust_dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = No\n  share_instance = Yes\n  \
             instance_name = ac-rust-{pid}\n  shared_instance_port = {rs_shared}\n  \
             instance_control_port = {rs_control}\n  discover_interfaces = Yes\n  \
             required_discovery_value = 2\n  autoconnect_discovered_interfaces = 1\n\
             [logging]\n  loglevel = 4\n\
             [interfaces]\n  [[link to python]]\n    type = TCPClientInterface\n    \
             enabled = Yes\n    target_host = 127.0.0.1\n    target_port = {link_port}\n"
        ),
    )
    .unwrap();
    drop(ports);

    let mut python = spawn_daemon(Daemon::Python, &python_dir, &root.path().join("python.log"));
    wait_for_port(link_port, &mut python, "Python link server");
    let mut rust = spawn_daemon(Daemon::Rust, &rust_dir, &root.path().join("rust.log"));

    // Upstream's announcer waits a minute before its first announce.
    let rust_config = rust_dir.to_str().unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        python.assert_running("Python rnsd");
        rust.assert_running("Rust rnsd");
        let mut rnstatus = Command::new(env!("CARGO_BIN_EXE_rnstatus"));
        rnstatus.args(["--config", &rust_config]);
        let output = run(rnstatus);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // The auto-connected interface is up under its discovered name.
        if stdout
            .split("\n\n")
            .any(|block| block.contains(name) && block.contains("Status    : Up"))
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "the Rust node never auto-connected the Python Backbone interface:\n{stdout}\n\
                 python log:\n{}\nrust log:\n{}",
                fs::read_to_string(root.path().join("python.log")).unwrap_or_default(),
                fs::read_to_string(root.path().join("rust.log")).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rust_instance_reads_python_encrypted_discovery() {
    encrypted_discovery(Daemon::Python, Daemon::Rust);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_instance_reads_rust_encrypted_discovery() {
    encrypted_discovery(Daemon::Rust, Daemon::Python);
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_client_retains_destination_data_on_rust_instance() {
    // A client of a shared instance marks known destinations as used,
    // retained or unretained with the destination_data and identity_data
    // RPC calls (upstream since 1.1.7).
    let harness = Harness::start("python-destination-data");
    let config = harness.client_config.to_str().unwrap().to_string();
    let mut command = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    command.env("PYTHONUNBUFFERED", "1");
    command.args([
        "-c",
        r#"
import RNS, sys, time
r = RNS.Reticulum(sys.argv[1])
identity = RNS.Identity()
destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "interop", "retain")
destination.announce()
deadline = time.time() + 15
while not r._used_destination_data(destination.hash):
    if time.time() > deadline: sys.exit("the shared instance never learned the destination")
    time.sleep(0.2)
print("retain", r._retain_destination_data(destination.hash))
print("used-while-retained", r._used_destination_data(destination.hash))
print("unretain", r._unretain_destination_data(destination.hash))
print("used", r._used_destination_data(destination.hash))
print("retain-unknown", r._retain_destination_data(bytes(16)))
print("retain-identity", r._retain_identity(identity.hash))
print("retain-unknown-identity", r._retain_identity(bytes(16)))
"#,
        &config,
    ]);
    let output = run(command);
    assert_success(&output, "Python destination_data calls");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let results: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.starts_with('['))
        .collect();
    assert_eq!(
        results,
        [
            "retain True",
            "used-while-retained False",
            "unretain True",
            "used True",
            "retain-unknown False",
            "retain-identity True",
            "retain-unknown-identity False",
        ],
        "{stdout}"
    );
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnstatus_manages_rust_interface() {
    let mut version_command = Command::new("python3");
    // Reticulum swaps stdout for /dev/null when it exits, which can drop
    // buffered output; print it as it is written.
    version_command.env("PYTHONUNBUFFERED", "1");
    version_command.args(["-c", "import RNS; print(RNS.__version__)"]);
    let version_output = run(version_command);
    assert_success(&version_output, "read Python Reticulum version");
    let version = String::from_utf8_lossy(&version_output.stdout);
    let parts: Vec<u32> = version
        .trim()
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect();
    if parts.as_slice() < [1, 5, 5].as_slice() {
        return;
    }

    let harness = Harness::start("python-management");
    let config_path = harness.listener_config.join("config");
    let mut config = fs::read_to_string(&config_path).unwrap();
    config.push_str(
        "\n  [[Managed UDP]]\n    type = UDPInterface\n    enabled = no\n    forward_ip = 127.0.0.1\n    forward_port = 9\n",
    );
    fs::write(&config_path, config).unwrap();

    for (action, result) in [
        ("attach", "attached"),
        ("reload", "reloaded"),
        ("detach", "detached"),
    ] {
        let mut command = harness.python_command("rnstatus");
        command.args([
            "--config",
            harness.listener_config.to_str().unwrap(),
            &format!("--{action}"),
            "Managed UDP",
        ]);
        let output = run(command);
        assert_success(&output, &format!("Python rnstatus --{action}"));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("was {result}")),
            "unexpected rnstatus output: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Whether the Python rnpath's source contains `needle`: `"--usage"` for
/// releases with `-u`, `{u_str}` for those that print its suffix (upstream
/// db67adea; before it the suffix was computed and never printed).
fn python_rnpath_source_contains(needle: &str) -> bool {
    python_utility_source_contains("rnpath", needle)
}

/// Whether the source of the Python utility `RNS.Utilities.<utility>`
/// contains `needle`.
fn python_utility_source_contains(utility: &str, needle: &str) -> bool {
    let mut probe = Command::new("python3");
    probe.env("PYTHONUNBUFFERED", "1");
    probe.args([
        "-c",
        &format!(
            "import inspect, RNS.Utilities.{utility} as m; print({needle:?} in inspect.getsource(m))"
        ),
    ]);
    let probe = run(probe);
    String::from_utf8_lossy(&probe.stdout).trim() == "True"
}

/// Upstream 134dc677: Python `rnstatus -F` reads the filtered traffic keys
/// of every interface and of the totals without checking for them, so a
/// Rust daemon must always report them.
#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn python_rnstatus_shows_rust_filtered_traffic() {
    if !python_utility_source_contains("rnstatus", "--filter-stats") {
        eprintln!("Python rnstatus predates filtered traffic stats; skipping");
        return;
    }
    let harness = Harness::start("python-filtered");
    let mut command = harness.python_command("rnstatus");
    command.args([
        "--config",
        harness.listener_config.to_str().unwrap(),
        "-F",
        "-t",
        "-s",
        "frx",
    ]);
    let output = run(command);
    assert_success(&output, "Python rnstatus -F -t -s frx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("    Filtered  : "), "{stdout}");
    assert!(stdout.contains(" Filtered     : "), "{stdout}");
}

/// What an `rnpath <destination>` run finally shows: the text after its
/// last carriage return, past the request spinner.
fn final_rnpath_line(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .trim_end()
        .rsplit('\r')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[test]
#[ignore = "requires Python Reticulum; exercised by the pinned interop CI matrix"]
fn rnpath_looks_up_a_destination_as_python_does() {
    let harness = Harness::start("rnpath-lookup");
    let listener_identity = harness.path("listener.identity");
    let receive = harness.path("receive");
    fs::create_dir_all(&receive).unwrap();
    let destination = harness.destination(Implementation::Rust, "rncp", &listener_identity);
    let listener = harness.listener(
        Implementation::Rust,
        "rncp",
        &listener_identity,
        &destination,
        &[
            "--no-auth".into(),
            "--save".into(),
            receive.to_string_lossy().into_owned(),
            "-b".into(),
            "1".into(),
        ],
    );
    harness.wait_for_client_path(&destination, &listener);
    let config = harness.client_config.to_str().unwrap().to_string();

    let lookup = |rust: bool, destination: &str, extra: &[&str]| -> Output {
        let mut command = if rust {
            harness.rust_command("rnpath", Side::Client)
        } else {
            harness.python_command("rnpath")
        };
        command
            .args(["--config", &config])
            .args(extra)
            .arg(destination);
        command.output().expect("run rnpath")
    };

    let python = lookup(false, &destination, &["-w", "5"]);
    let rust = lookup(true, &destination, &["-w", "5"]);
    for (name, output) in [("Python", &python), ("Rust", &rust)] {
        assert!(
            output.status.success(),
            "{name} rnpath failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let found = final_rnpath_line(&python);
    assert!(found.starts_with("Path found, destination"), "{found}");
    assert_eq!(final_rnpath_line(&rust), found);

    // Python's rnpath means to exit 1 on these failures, but a shared
    // instance client's exit races its LocalInterface reader, which on
    // seeing the connection close calls RNS.exit() and so os._exit(0);
    // on a slow runner Python exits 0. The output is what is compared.
    let python_failed = |output: &Output| matches!(output.status.code(), Some(0) | Some(1));

    let unknown = "0123456789abcdef0123456789abcdef";
    let python = lookup(false, unknown, &["-w", "1"]);
    let rust = lookup(true, unknown, &["-w", "1"]);
    assert!(python_failed(&python), "{:?}", python.status);
    assert_eq!(rust.status.code(), Some(1));
    assert_eq!(final_rnpath_line(&rust), final_rnpath_line(&python));
    assert_eq!(final_rnpath_line(&rust), "Path not found");

    for bad in ["abcd", "zz23456789abcdef0123456789abcdef"] {
        let python = lookup(false, bad, &[]);
        let rust = lookup(true, bad, &[]);
        assert!(python_failed(&python), "{:?}", python.status);
        assert_eq!(rust.status.code(), Some(1));
        assert_eq!(rust.stdout, python.stdout);
    }
}
