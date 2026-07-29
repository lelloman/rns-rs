use std::fs::{self, OpenOptions};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);

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
    _client_daemon: ProcessGuard,
    _listener_daemon: ProcessGuard,
}

impl Harness {
    fn start(label: &str) -> Self {
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
        let client_shared_port = free_port();
        let listener_shared_port = free_port();
        let client_control_port = free_port();
        let listener_control_port = free_port();
        let transport_port = free_port();
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
            "rnx" => env!("CARGO_BIN_EXE_rnx"),
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
        extra: &[String],
    ) -> ProcessGuard {
        let mut command = match implementation {
            Implementation::Rust => self.rust_command(utility, Side::Listener),
            Implementation::Python => self.python_command(utility),
        };
        command.args(self.common_args(identity, Side::Listener));
        command.arg("--listen");
        command.args(extra);
        let log = self.path(&format!("{utility}-{implementation:?}-listener.log"));
        let mut listener = spawn_logged(command, &log);
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            listener.assert_running(&format!("{implementation:?} {utility} listener"));
            let text = fs::read_to_string(&log).unwrap_or_default();
            if text.to_ascii_lowercase().contains("listening") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "listener did not become ready:\n{text}"
            );
            thread::sleep(Duration::from_millis(25));
        }
        // Upstream prints its readiness line immediately before issuing the
        // initial announce. Give that one-shot announce time to cross both
        // transport daemons before starting a client under parallel test load.
        thread::sleep(Duration::from_millis(500));
        listener
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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
                "{program} timed out:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
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
    assert_eq!(
        fs::read(receive.join("streaming.bin")).unwrap(),
        source_data
    );

    let mut fetch = harness.rust_command("rncp", Side::Client);
    fetch.args(harness.common_args(&client_identity, Side::Client));
    fetch.args(["--fetch", "--silent", "--timeout", "30", "--save"]);
    fetch.arg(&fetched);
    fetch.arg("fetch.bin");
    fetch.arg(&destination);
    let fetched_output = run(fetch);
    assert_success(&fetched_output, "Rust rncp fetch");
    assert_eq!(fs::read(fetched.join("fetch.bin")).unwrap(), fetch_data);
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

#[test]
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
fn python_rnx_client_executes_on_rust_listener() {
    let harness = Harness::start("python-to-rust-rnx");
    let listener_identity = harness.path("listener.identity");
    let client_identity = harness.path("python-client.identity");
    let destination = harness.destination(Implementation::Rust, "rnx", &listener_identity);
    let _listener = harness.listener(
        Implementation::Rust,
        "rnx",
        &listener_identity,
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
    let large = rnx_execute_command(
        &harness,
        Implementation::Python,
        &client_identity,
        &destination,
        "/usr/bin/seq 1 1000",
    );
    assert_large_rnx_response(&large, "Python rnx Resource response from Rust");
}

#[test]
fn rust_rnx_client_executes_on_python_listener() {
    let harness = Harness::start("rust-to-python-rnx");
    let listener_identity = harness.path("python-listener.identity");
    let client_identity = harness.path("rust-client.identity");
    let destination = harness.destination(Implementation::Python, "rnx", &listener_identity);
    let _listener = harness.listener(
        Implementation::Python,
        "rnx",
        &listener_identity,
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
fn python_rns_is_available_for_utility_interop() {
    let mut command = Command::new("python3");
    command.args(["-c", "import RNS, RNS.Utilities.rncp, RNS.Utilities.rnx"]);
    assert_success(&run(command), "import Python RNS utilities");
}
