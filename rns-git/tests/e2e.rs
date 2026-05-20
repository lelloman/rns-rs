use std::fs;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_net::{AnnouncedIdentity, Callbacks, DestHash, Destination, LinkId, PacketHash, RnsNode};

use rns_git::config::ServerConfig;
use rns_git::git;
use rns_git::pages;
use rns_git::protocol::{self, RefUpdate};
use rns_git::server::{register_server_destinations, ServerDestinations};
use rns_git::util::hex;
use rns_git::work;

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

struct E2eHarness {
    tmp: tempfile::TempDir,
    server_node: RnsNode,
    client_node: RnsNode,
    rx: mpsc::Receiver<Event>,
    server_identity: Identity,
    client_identity: Identity,
    server_config: ServerConfig,
    destinations: ServerDestinations,
}

impl E2eHarness {
    fn start(configure: impl FnOnce(&mut ServerConfig)) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let port = find_free_port();

        let server_rns_dir = tmp.path().join("server-rns");
        let client_rns_dir = tmp.path().join("client-rns");
        fs::create_dir_all(&server_rns_dir).unwrap();
        fs::create_dir_all(&client_rns_dir).unwrap();
        fs::write(server_rns_dir.join("config"), server_rns_config(port)).unwrap();
        fs::write(client_rns_dir.join("config"), client_rns_config(port)).unwrap();

        let server_node =
            RnsNode::from_config(Some(&server_rns_dir), Box::new(NoopCallbacks)).unwrap();
        wait_for_tcp_port(port);

        let server_identity = Identity::new(&mut OsRng);
        let mut server_config = ServerConfig {
            dir: tmp.path().join("rngit"),
            reticulum_dir: Some(server_rns_dir),
            repositories_dir: tmp.path().join("repositories"),
            identity_path: tmp.path().join("repositories_identity"),
            client_identity_path: tmp.path().join("client_identity"),
            node_name: "RNS Git Test Node".into(),
            announce_interval_secs: 300,
            serve_nomadnet: true,
            templates_dir: tmp.path().join("rngit/templates"),
            unicode_icons: false,
            record_stats: false,
            stats_ignore_identities: Vec::new(),
            identity_aliases: std::collections::BTreeMap::new(),
            allow_read: vec!["all".into()],
            allow_write: vec!["all".into()],
            allow_create: vec!["all".into()],
            allow_stats: vec!["none".into()],
            allow_release: vec!["none".into()],
            allow_interact: vec!["none".into()],
            allow_propose: vec!["none".into()],
            allow_admin: vec!["none".into()],
            log_level: rns_git::logging::DEFAULT_LOG_LEVEL,
        };
        configure(&mut server_config);
        let destinations =
            register_server_destinations(&server_node, server_config.clone(), &server_identity)
                .unwrap();

        let client_identity = Identity::new(&mut OsRng);
        let (tx, rx) = mpsc::channel();
        let client_node =
            RnsNode::from_config(Some(&client_rns_dir), Box::new(ClientCallbacks { tx })).unwrap();

        Self {
            tmp,
            server_node,
            client_node,
            rx,
            server_identity,
            client_identity,
            server_config,
            destinations,
        }
    }

    fn link_to(&self, destination: &Destination, app_data: Option<&[u8]>) -> [u8; 16] {
        let announced = wait_for_announce(
            &self.rx,
            &self.server_node,
            destination,
            &self.server_identity,
            destination.hash,
            app_data,
            TIMEOUT,
        );
        if let Some(expected) = app_data {
            assert_eq!(announced.app_data.as_deref(), Some(expected));
        }
        let sig_pub: [u8; 32] = announced.public_key[32..64].try_into().unwrap();
        let link_id = self
            .client_node
            .create_link(destination.hash.0, sig_pub)
            .expect("client should create link to destination");
        wait_for_link(&self.rx, link_id, TIMEOUT);
        self.client_node
            .identify_on_link(link_id, self.client_identity.get_private_key().unwrap())
            .unwrap();
        link_id
    }

    fn request(&self, link_id: [u8; 16], path: &str, data: &[u8]) -> ResponseEvent {
        self.client_node.send_request(link_id, path, data).unwrap();
        wait_for_response(&self.rx, TIMEOUT)
    }
}

#[test]
fn rngit_push_list_fetch_roundtrip_over_rns_link() {
    let harness = E2eHarness::start(|_| {});
    let (sha, bundle) = create_source_bundle(harness.tmp.path());
    git::apply_push(
        &harness.server_config.repositories_dir.join("group/repo"),
        &bundle,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: None,
            new: Some(sha.clone()),
            force: true,
        }],
    )
    .unwrap();
    run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(harness.server_config.repositories_dir.join("group/repo"))
            .arg("symbolic-ref")
            .arg("HEAD")
            .arg("refs/heads/main"),
    );
    let page_destination = harness
        .destinations
        .nomadnet
        .as_ref()
        .expect("Nomad Network destination should be registered");

    let link_id = harness.link_to(&harness.destinations.repositories, None);
    let page_announced = wait_for_announce(
        &harness.rx,
        &harness.server_node,
        page_destination,
        &harness.server_identity,
        page_destination.hash,
        Some(harness.server_config.node_name.as_bytes()),
        TIMEOUT,
    );
    assert_eq!(
        page_announced.app_data.as_deref(),
        Some(harness.server_config.node_name.as_bytes())
    );

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
    let push_response = harness.request(link_id, protocol::PATH_PUSH, &push);
    assert_eq!(decode_status_response(&push_response.data), b"ok");

    let list_response = harness.request(
        link_id,
        protocol::PATH_LIST,
        &protocol::repository_request("group/repo"),
    );
    let refs = String::from_utf8(decode_status_response(&list_response.data)).unwrap();
    assert!(
        refs.contains(&format!("{sha} refs/heads/copy")),
        "refs did not include pushed copy ref: {refs}"
    );

    let fetch_response = harness.request(
        link_id,
        protocol::PATH_FETCH,
        &protocol::fetch_request("group/repo", &[]),
    );
    assert_metadata_ok(fetch_response.metadata.as_deref().expect("fetch metadata"));
    let fetched_bundle = protocol::response_bin(&fetch_response.data).unwrap();
    assert!(!fetched_bundle.is_empty());

    let fetched_path = harness.tmp.path().join("fetched.bundle");
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

#[test]
fn rngit_create_permission_is_enforced_over_rns_link() {
    let harness = E2eHarness::start(|config| {
        config.allow_write = vec!["none".into()];
        config.allow_create = vec!["all".into()];
    });
    let link_id = harness.link_to(&harness.destinations.repositories, None);

    let create = protocol::push_request("group/created", Vec::new(), Vec::new());
    let create_response = harness.request(link_id, protocol::PATH_PUSH, &create);
    assert_eq!(decode_status_response(&create_response.data), b"ok");
    assert!(
        git::is_bare_repository(&harness.server_config.repositories_dir.join("group/created")),
        "create-permitted push should initialize a bare repository"
    );

    let update_existing = protocol::push_request("group/created", Vec::new(), Vec::new());
    let denied_response = harness.request(link_id, protocol::PATH_PUSH, &update_existing);
    assert_status_response(
        &denied_response.data,
        protocol::RES_DISALLOWED,
        b"write denied",
    );
}

#[test]
fn rngit_nomadnet_pages_render_over_rns_link() {
    let harness = E2eHarness::start(|config| {
        config.allow_stats = vec!["all".into()];
    });
    let (sha, bundle) = create_source_bundle(harness.tmp.path());
    git::apply_push(
        &harness.server_config.repositories_dir.join("group/repo"),
        &bundle,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: None,
            new: Some(sha),
            force: true,
        }],
    )
    .unwrap();
    run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(harness.server_config.repositories_dir.join("group/repo"))
            .arg("symbolic-ref")
            .arg("HEAD")
            .arg("refs/heads/main"),
    );

    let page_destination = harness
        .destinations
        .nomadnet
        .as_ref()
        .expect("Nomad Network destination should be registered");
    let page_link = harness.link_to(
        page_destination,
        Some(harness.server_config.node_name.as_bytes()),
    );

    let index = harness.request(page_link, pages::PATH_INDEX, &page_request(&[]));
    let index_page = decode_page_response(&index.data);
    assert!(
        index_page.contains("RNS Git Test Node"),
        "index page did not include node name:\n{index_page}"
    );
    assert!(
        index_page.contains("Groups"),
        "index page did not include groups heading:\n{index_page}"
    );
    assert!(
        index_page.contains("group"),
        "index page did not include repository group:\n{index_page}"
    );
    assert!(
        index_page.contains("repo"),
        "index page did not include repository link:\n{index_page}"
    );

    let repo = harness.request(
        page_link,
        pages::PATH_REPO,
        &page_request(&[("var_g", "group"), ("var_r", "repo")]),
    );
    let repo_page = decode_page_response(&repo.data);
    assert!(
        repo_page.contains("RNS Git Test Node"),
        "repo page did not include node name:\n{repo_page}"
    );
    assert!(
        repo_page.contains("rns://<repository-destination>/group/repo"),
        "repo page did not include repository URL:\n{repo_page}"
    );
    assert!(
        repo_page.contains("Files"),
        "repo page did not include Files navigation:\n{repo_page}"
    );
    assert!(
        repo_page.contains("Commits"),
        "repo page did not include Commits navigation:\n{repo_page}"
    );
    assert!(
        repo_page.contains("Stats"),
        "repo page did not include Stats navigation:\n{repo_page}"
    );
    assert!(
        repo_page.contains("hello over rns"),
        "repo page did not render README content:\n{repo_page}"
    );
}

#[test]
fn rngit_release_management_and_downloads_work_over_rns_link() {
    let harness = E2eHarness::start(|config| {
        config.allow_release = vec!["all".into()];
    });
    let (sha, bundle) = create_source_bundle(harness.tmp.path());
    let repo_path = harness.server_config.repositories_dir.join("group/repo");
    git::apply_push(
        &repo_path,
        &bundle,
        &[RefUpdate {
            refname: "refs/heads/main".into(),
            old: None,
            new: Some(sha),
            force: true,
        }],
    )
    .unwrap();
    run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo_path)
            .arg("symbolic-ref")
            .arg("HEAD")
            .arg("refs/heads/main"),
    );
    run_git(Command::new("git").arg("--git-dir").arg(&repo_path).args([
        "tag",
        "v1",
        "refs/heads/main",
    ]));

    let link_id = harness.link_to(&harness.destinations.repositories, None);
    let init = harness.request(
        link_id,
        protocol::PATH_RELEASE,
        &release_request(&[
            ("repository", Value::Str("group/repo".into())),
            ("operation", Value::Str("create".into())),
            ("step", Value::Str("init".into())),
            ("tag", Value::Str("v1".into())),
            ("notes", Value::Str("# Release\n\nFrom E2E\n".into())),
            ("notes_format", Value::Str("markdown".into())),
        ]),
    );
    assert_status_response(&init.data, protocol::RES_OK, b"ok");
    let artifact = harness.request(
        link_id,
        protocol::PATH_RELEASE,
        &release_request(&[
            ("repository", Value::Str("group/repo".into())),
            ("operation", Value::Str("create".into())),
            ("step", Value::Str("artifact".into())),
            ("tag", Value::Str("v1".into())),
            ("artifact_name", Value::Str("dist.tar".into())),
            ("artifact_data", Value::Bin(b"artifact over rns".to_vec())),
        ]),
    );
    assert_status_response(&artifact.data, protocol::RES_OK, b"ok");
    let finalize = harness.request(
        link_id,
        protocol::PATH_RELEASE,
        &release_request(&[
            ("repository", Value::Str("group/repo".into())),
            ("operation", Value::Str("create".into())),
            ("step", Value::Str("finalize".into())),
            ("tag", Value::Str("v1".into())),
        ]),
    );
    assert_status_response(&finalize.data, protocol::RES_OK, b"ok");

    let list = harness.request(
        link_id,
        protocol::PATH_RELEASE,
        &release_request(&[
            ("repository", Value::Str("group/repo".into())),
            ("operation", Value::Str("list".into())),
        ]),
    );
    let list_body = decode_ok_body(&list.data);
    let releases = msgpack::unpack_exact(&list_body).unwrap();
    assert_eq!(
        releases
            .map_get("releases")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );

    let page_destination = harness
        .destinations
        .nomadnet
        .as_ref()
        .expect("Nomad Network destination should be registered");
    let page_link = harness.link_to(
        page_destination,
        Some(harness.server_config.node_name.as_bytes()),
    );
    let release_page = harness.request(
        page_link,
        pages::PATH_RELEASE,
        &page_request(&[("var_g", "group"), ("var_r", "repo"), ("var_tag", "latest")]),
    );
    let release_page = decode_page_response(&release_page.data);
    assert!(release_page.contains(">Release v1"));
    assert!(release_page.contains("From E2E"));
    assert!(release_page.contains("dist.tar"));

    let download = harness.request(
        page_link,
        pages::PATH_DOWNLOAD,
        &page_request(&[
            ("var_g", "group"),
            ("var_r", "repo"),
            ("var_tag", "latest"),
            ("var_artifact", "dist.tar"),
        ]),
    );
    assert_metadata_ok(download.metadata.as_deref().expect("download metadata"));
    assert_eq!(
        protocol::response_bin(&download.data).unwrap(),
        b"artifact over rns"
    );
}

#[test]
fn rngit_work_document_lifecycle_works_over_rns_link() {
    let harness = E2eHarness::start(|config| {
        config.allow_interact = vec!["all".into()];
    });
    let repo_path = harness.server_config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let link_id = harness.link_to(&harness.destinations.repositories, None);

    let create = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("create".into())),
                ("title", Value::Str("Initial task".into())),
                ("content", Value::Str("Do the first thing".into())),
                ("format", Value::Str("markdown".into())),
            ],
        ),
    );
    let doc_id = work_response_id(&create.data);

    let comment = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("comment".into())),
                ("doc_id", Value::UInt(doc_id)),
                ("scope", Value::Str("active".into())),
                ("content", Value::Str("Looks good over RNS".into())),
            ],
        ),
    );
    assert_eq!(work_response_id(&comment.data), 1);

    let edit = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("edit".into())),
                ("doc_id", Value::UInt(doc_id)),
                ("scope", Value::Str("active".into())),
                ("title", Value::Str("Edited task".into())),
                ("content", Value::Str("Do the edited thing".into())),
            ],
        ),
    );
    assert_status_response(&edit.data, protocol::RES_OK, b"");

    let active_view = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("view".into())),
                ("doc_id", Value::UInt(doc_id)),
                ("scope", Value::Str("active".into())),
            ],
        ),
    );
    let active_doc = unpack_work_ok(&active_view.data);
    assert_eq!(
        active_doc.map_get("content").and_then(Value::as_str),
        Some("Do the edited thing")
    );
    let active_meta = active_doc.map_get("meta").and_then(Value::as_map).unwrap();
    assert_eq!(
        map_get_str(active_meta, "title").and_then(Value::as_str),
        Some("Edited task")
    );
    let comments = active_doc
        .map_get("comments")
        .and_then(Value::as_array)
        .expect("work view should include comments");
    assert_eq!(comments.len(), 1);
    assert_eq!(
        comments[0].map_get("content").and_then(Value::as_str),
        Some("Looks good over RNS")
    );

    let complete = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("complete".into())),
                ("doc_id", Value::UInt(doc_id)),
            ],
        ),
    );
    let complete_value = unpack_work_ok(&complete.data);
    assert_eq!(
        complete_value.map_get("scope").and_then(Value::as_str),
        Some("completed")
    );

    let completed_view = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("view".into())),
                ("doc_id", Value::UInt(doc_id)),
                ("scope", Value::Str("completed".into())),
            ],
        ),
    );
    assert_eq!(
        unpack_work_ok(&completed_view.data)
            .map_get("scope")
            .and_then(Value::as_str),
        Some("completed")
    );

    let activate = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("activate".into())),
                ("doc_id", Value::UInt(doc_id)),
            ],
        ),
    );
    let activate_value = unpack_work_ok(&activate.data);
    assert_eq!(
        activate_value.map_get("scope").and_then(Value::as_str),
        Some("active")
    );

    let list = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("list".into())),
                ("scope", Value::Str("all".into())),
            ],
        ),
    );
    let lists = unpack_work_ok(&list.data);
    assert_eq!(
        lists
            .map_get("active")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        lists
            .map_get("completed")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn rngit_work_document_local_permissions_work_over_rns_link() {
    let harness = E2eHarness::start(|config| {
        config.allow_write = vec!["none".into()];
        config.allow_interact = vec!["none".into()];
        config.allow_admin = vec!["none".into()];
    });
    let repo_path = harness.server_config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let work_path = work::work_sidecar_path(&repo_path);
    let created = work::create_document(
        &work_path,
        work::WorkInput {
            title: "Permission task".into(),
            content: "Doc-local permission target".into(),
            format: "markdown".into(),
            signature: None,
            identity: None,
            author: [0xAB; 16],
        },
    )
    .unwrap();
    let client_hash = *harness.client_identity.hash();
    let allowed = format!(
        "interact = {}\nadmin = {}\n",
        hex(&client_hash),
        hex(&client_hash)
    );
    work::set_document_permissions(&work_path, created.id, &allowed).unwrap();

    let link_id = harness.link_to(&harness.destinations.repositories, None);

    let get = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("perms".into())),
                ("step", Value::Str("get".into())),
                ("doc_id", Value::UInt(created.id)),
            ],
        ),
    );
    let perms = unpack_work_ok(&get.data);
    assert_eq!(
        perms.map_get("content").and_then(Value::as_str),
        Some(allowed.as_str())
    );

    let set = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("perms".into())),
                ("step", Value::Str("set".into())),
                ("doc_id", Value::UInt(created.id)),
                ("content", Value::Str(allowed.clone())),
            ],
        ),
    );
    assert_status_response(&set.data, protocol::RES_OK, b"");

    let comment = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("comment".into())),
                ("doc_id", Value::UInt(created.id)),
                ("content", Value::Str("Doc-local interact comment".into())),
            ],
        ),
    );
    assert_eq!(work_response_id(&comment.data), 1);

    let edit = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("edit".into())),
                ("doc_id", Value::UInt(created.id)),
                ("title", Value::Str("Should not edit".into())),
            ],
        ),
    );
    assert_status_response(&edit.data, protocol::RES_DISALLOWED, b"not allowed");

    let complete = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("complete".into())),
                ("doc_id", Value::UInt(created.id)),
            ],
        ),
    );
    assert_status_response(&complete.data, protocol::RES_DISALLOWED, b"not allowed");

    let view = harness.request(
        link_id,
        protocol::PATH_WORK,
        &work_request(
            "group/repo",
            &[
                ("operation", Value::Str("view".into())),
                ("doc_id", Value::UInt(created.id)),
            ],
        ),
    );
    let doc = unpack_work_ok(&view.data);
    let comments = doc
        .map_get("comments")
        .and_then(Value::as_array)
        .expect("work view should include comments");
    assert_eq!(comments.len(), 1);
    assert_eq!(
        comments[0].map_get("content").and_then(Value::as_str),
        Some("Doc-local interact comment")
    );
}

fn wait_for_announce(
    rx: &mpsc::Receiver<Event>,
    server_node: &RnsNode,
    destination: &rns_net::Destination,
    server_identity: &Identity,
    dest_hash: DestHash,
    app_data: Option<&[u8]>,
    timeout: Duration,
) -> AnnouncedIdentity {
    let deadline = Instant::now() + timeout;
    loop {
        server_node
            .announce(destination, server_identity, app_data)
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
    let bytes = decode_ok_body(data);
    bytes.to_vec()
}

fn decode_ok_body(data: &[u8]) -> Vec<u8> {
    let bytes = status_payload(data);
    let (&code, body) = bytes
        .split_first()
        .expect("status response must not be empty");
    assert_eq!(code, protocol::RES_OK, "unexpected status body: {body:?}");
    body.to_vec()
}

fn decode_page_response(data: &[u8]) -> String {
    String::from_utf8(protocol::response_bin(data).unwrap()).unwrap()
}

fn assert_status_response(data: &[u8], expected_code: u8, expected_body: &[u8]) {
    let bytes = status_payload(data);
    let (&code, body) = bytes
        .split_first()
        .expect("status response must not be empty");
    assert_eq!(code, expected_code, "unexpected status body: {body:?}");
    assert_eq!(body, expected_body);
}

fn status_payload(data: &[u8]) -> Vec<u8> {
    protocol::response_bin(data).unwrap_or_else(|_| data.to_vec())
}

fn page_request(fields: &[(&str, &str)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), Value::Str((*v).into())))
            .collect(),
    ))
}

fn release_request(fields: &[(&str, Value)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), v.clone()))
            .collect(),
    ))
}

fn work_request(repository: &str, fields: &[(&str, Value)]) -> Vec<u8> {
    let mut entries = vec![(
        Value::UInt(protocol::IDX_REPOSITORY),
        Value::Str(repository.to_string()),
    )];
    entries.extend(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), v.clone())),
    );
    msgpack::pack(&Value::Map(entries))
}

fn work_response_id(data: &[u8]) -> u64 {
    unpack_work_ok(data)
        .map_get("id")
        .and_then(Value::as_uint)
        .expect("work response should contain id")
}

fn unpack_work_ok(data: &[u8]) -> Value {
    let body = decode_ok_body(data);
    msgpack::unpack_exact(&body).expect("work response body should be msgpack")
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(map_key, value)| match map_key {
        Value::Str(map_key) if map_key == key => Some(value),
        _ => None,
    })
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
