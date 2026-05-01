use std::fs;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::{AnnouncedIdentity, Callbacks, DestHash, LinkId, PacketHash, RnsNode};

use rns_git::config::ServerConfig;
use rns_git::git;
use rns_git::protocol::{self, RefUpdate};
use rns_git::server::register_repository_destination;

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum Event {
    Announce(AnnouncedIdentity),
    LinkEstablished([u8; 16]),
    Response {
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
}

struct ClientCallbacks {
    tx: mpsc::Sender<Event>,
}

impl Callbacks for ClientCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(Event::Announce(announced));
    }

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        _is_initiator: bool,
    ) {
        let _ = self.tx.send(Event::LinkEstablished(link_id.0));
    }

    fn on_response_with_metadata(
        &mut self,
        _link_id: LinkId,
        _request_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) {
        let _ = self.tx.send(Event::Response { data, metadata });
    }
}

struct NoopCallbacks;

impl Callbacks for NoopCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }
}

#[test]
fn rngit_push_list_fetch_roundtrip_over_rns_link() {
    let tmp = tempfile::tempdir().unwrap();
    let port = find_free_port();

    let server_rns_dir = tmp.path().join("server-rns");
    let client_rns_dir = tmp.path().join("client-rns");
    fs::create_dir_all(&server_rns_dir).unwrap();
    fs::create_dir_all(&client_rns_dir).unwrap();
    fs::write(server_rns_dir.join("config"), server_rns_config(port)).unwrap();
    fs::write(client_rns_dir.join("config"), client_rns_config(port)).unwrap();

    let server_node = RnsNode::from_config(Some(&server_rns_dir), Box::new(NoopCallbacks)).unwrap();
    wait_for_tcp_port(port);

    let server_identity = Identity::new(&mut OsRng);
    let server_config = ServerConfig {
        dir: tmp.path().join("rngit"),
        reticulum_dir: Some(server_rns_dir),
        repositories_dir: tmp.path().join("repositories"),
        identity_path: tmp.path().join("repositories_identity"),
        client_identity_path: tmp.path().join("client_identity"),
        announce_interval_secs: 300,
        allow_read: vec!["all".into()],
        allow_write: vec!["all".into()],
    };
    let (sha, bundle) = create_source_bundle(tmp.path());
    git::apply_push(
        &server_config.repositories_dir.join("group/repo"),
        &bundle,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: None,
            new: Some(sha.clone()),
            force: true,
        }],
    )
    .unwrap();
    let destination =
        register_repository_destination(&server_node, server_config.clone(), &server_identity)
            .unwrap();

    let client_identity = Identity::new(&mut OsRng);
    let (tx, rx) = mpsc::channel();
    let client_node =
        RnsNode::from_config(Some(&client_rns_dir), Box::new(ClientCallbacks { tx })).unwrap();

    let announced = wait_for_announce(
        &rx,
        &server_node,
        &destination,
        &server_identity,
        destination.hash,
        TIMEOUT,
    );
    assert_eq!(announced.identity_hash.0, *server_identity.hash());

    let sig_pub: [u8; 32] = announced.public_key[32..64].try_into().unwrap();
    let link_id = client_node
        .create_link(destination.hash.0, sig_pub)
        .expect("client should create link to rngit server");
    wait_for_link(&rx, link_id, TIMEOUT);
    client_node
        .identify_on_link(link_id, client_identity.get_private_key().unwrap())
        .unwrap();

    let push = protocol::push_request(
        "group/repo",
        Vec::new(),
        vec![RefUpdate {
            refname: "refs/heads/copy".into(),
            old: None,
            new: Some(sha.clone()),
            force: true,
        }],
    );
    client_node
        .send_request(link_id, protocol::PATH_PUSH, &push)
        .unwrap();
    let push_response = wait_for_response(&rx, TIMEOUT);
    assert_eq!(decode_status_response(&push_response.data), b"ok");

    client_node
        .send_request(
            link_id,
            protocol::PATH_LIST,
            &protocol::repository_request("group/repo"),
        )
        .unwrap();
    let list_response = wait_for_response(&rx, TIMEOUT);
    let refs = String::from_utf8(decode_status_response(&list_response.data)).unwrap();
    assert!(
        refs.contains(&format!("{sha} refs/heads/copy")),
        "refs did not include pushed copy ref: {refs}"
    );

    client_node
        .send_request(
            link_id,
            protocol::PATH_FETCH,
            &protocol::fetch_request("group/repo", &[]),
        )
        .unwrap();
    let fetch_response = wait_for_response(&rx, TIMEOUT);
    assert_metadata_ok(fetch_response.metadata.as_deref().expect("fetch metadata"));
    let fetched_bundle = protocol::response_bin(&fetch_response.data).unwrap();
    assert!(!fetched_bundle.is_empty());

    let fetched_path = tmp.path().join("fetched.bundle");
    fs::write(&fetched_path, fetched_bundle).unwrap();
    let fetched_refs = run_git(
        Command::new("git")
            .arg("ls-remote")
            .arg(&fetched_path)
            .arg("refs/heads/copy"),
    );
    assert!(
        fetched_refs.contains(&format!("{sha}\trefs/heads/copy")),
        "fetched bundle did not contain pushed ref: {fetched_refs}"
    );
}

fn wait_for_announce(
    rx: &mpsc::Receiver<Event>,
    server_node: &RnsNode,
    destination: &rns_net::Destination,
    server_identity: &Identity,
    dest_hash: DestHash,
    timeout: Duration,
) -> AnnouncedIdentity {
    let deadline = Instant::now() + timeout;
    loop {
        server_node
            .announce(destination, server_identity, None)
            .expect("reannounce should succeed");
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Announce(announced)) if announced.dest_hash == dest_hash => {
                return announced;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(err) => panic!("timed out waiting for announce: {err}"),
        }
        assert!(Instant::now() < deadline, "timed out waiting for announce");
    }
}

fn wait_for_link(rx: &mpsc::Receiver<Event>, link_id: [u8; 16], timeout: Duration) {
    wait_for_event(rx, timeout, |event| match event {
        Event::LinkEstablished(id) if id == link_id => Some(()),
        _ => None,
    });
}

fn wait_for_response(rx: &mpsc::Receiver<Event>, timeout: Duration) -> ResponseEvent {
    wait_for_event(rx, timeout, |event| match event {
        Event::Response { data, metadata } => Some(ResponseEvent { data, metadata }),
        _ => None,
    })
}

struct ResponseEvent {
    data: Vec<u8>,
    metadata: Option<Vec<u8>>,
}

fn wait_for_event<T>(
    rx: &mpsc::Receiver<Event>,
    timeout: Duration,
    mut f: impl FnMut(Event) -> Option<T>,
) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        assert!(now < deadline, "timed out waiting for event");
        let event = rx
            .recv_timeout(deadline.saturating_duration_since(now))
            .unwrap();
        if let Some(value) = f(event) {
            return value;
        }
    }
}

fn decode_status_response(data: &[u8]) -> Vec<u8> {
    let bytes = protocol::response_bin(data).unwrap();
    let (&code, body) = bytes
        .split_first()
        .expect("status response must not be empty");
    assert_eq!(code, protocol::RES_OK, "unexpected status body: {body:?}");
    body.to_vec()
}

fn assert_metadata_ok(metadata: &[u8]) {
    let value = msgpack::unpack_exact(metadata).unwrap();
    let map = value.as_map().expect("metadata must be a map");
    let code = map.iter().find_map(|(key, value)| {
        if matches!(key, Value::UInt(v) if *v == protocol::IDX_RESULT_CODE) {
            value.as_uint()
        } else {
            None
        }
    });
    assert_eq!(code, Some(protocol::RES_OK as u64));
}

fn create_source_bundle(root: &std::path::Path) -> (String, Vec<u8>) {
    let work = root.join("source");
    fs::create_dir_all(&work).unwrap();
    run_git(Command::new("git").arg("init").arg(&work));
    fs::write(work.join("README.md"), "hello over rns\n").unwrap();
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("add")
            .arg("README.md"),
    );
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("-c")
            .arg("user.name=RNS E2E")
            .arg("-c")
            .arg("user.email=rns-e2e@example.invalid")
            .arg("commit")
            .arg("-m")
            .arg("initial"),
    );
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("branch")
            .arg("-M")
            .arg("main"),
    );
    let sha = run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("rev-parse")
            .arg("refs/heads/main"),
    )
    .trim()
    .to_string();
    let bundle_path = root.join("source.bundle");
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("bundle")
            .arg("create")
            .arg(&bundle_path)
            .arg("refs/heads/main"),
    );
    (sha, fs::read(bundle_path).unwrap())
}

fn run_git(cmd: &mut Command) -> String {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_tcp_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => panic!("TCP listener on {port} did not come up: {err}"),
        }
    }
}

fn server_rns_config(port: u16) -> String {
    format!(
        r#"[reticulum]
  enable_transport = Yes
  share_instance = No
  panic_on_interface_error = Yes

[interfaces]
  [[RNGit Server TCP]]
    type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = {port}
    mode = full
"#
    )
}

fn client_rns_config(port: u16) -> String {
    format!(
        r#"[reticulum]
  enable_transport = No
  share_instance = No
  panic_on_interface_error = Yes

[interfaces]
  [[RNGit Client TCP]]
    type = TCPClientInterface
    target_host = 127.0.0.1
    target_port = {port}
    mode = full
"#
    )
}
