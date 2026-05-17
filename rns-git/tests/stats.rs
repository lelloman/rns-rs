use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rns_core::msgpack::{self, Value};
use rns_git::acl::Access;
use rns_git::config::ServerConfig;
use rns_git::logging;
use rns_git::{pages, protocol, release, server};
use rns_net::RequestResponse;

const REMOTE: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const REMOTE_SIG: [u8; 64] = [0x42; 64];

#[test]
fn stats_permission_is_required_for_links_and_stats_page() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_stats = vec!["none".into()];
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access_rules = access(&config);

    let repo_page = pages::render_page(
        pages::PATH_REPO,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(!repo_page.contains("[Stats`:/page/stats.mu"));
    assert!(!repo_page.contains(pages::PATH_STATS));

    let stats_page = pages::render_page(
        pages::PATH_STATS,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(stats_page.contains(">Error"));
    assert!(stats_page.contains("repository was not found"));
}

#[test]
fn page_fetch_and_push_stats_are_recorded_and_rendered() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access_rules = access(&config);
    let remote = Some(&(REMOTE, REMOTE_SIG));

    pages::render_page(
        pages::PATH_INDEX,
        &config,
        &access_rules,
        &page_request(&[]),
        Some(&REMOTE),
    )
    .unwrap();
    pages::render_page(
        pages::PATH_GROUP,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public")]),
        Some(&REMOTE),
    )
    .unwrap();
    pages::render_page(
        pages::PATH_REPO,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();

    let fetch = server::handle_fetch(
        &config,
        &access_rules,
        &protocol::fetch_request("public/alpha", &[]),
        remote,
    )
    .unwrap();
    assert_fetch_ok(fetch);

    let push = server::handle_push(
        &config,
        &access_rules,
        &protocol::push_request("public/beta", Vec::new(), Vec::new()),
        remote,
    )
    .unwrap();
    assert_eq!(push[0], protocol::RES_OK);

    let alpha_stats = pages::render_page(
        pages::PATH_STATS,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(alpha_stats.contains(">Stats for alpha"));
    assert!(alpha_stats.contains("Views"));
    assert!(alpha_stats.contains("Fetches"));
    assert!(alpha_stats.contains("Views`f    :     1  total"));
    assert!(alpha_stats.contains("Fetches`f  :     1  total"));
    assert!(alpha_stats.contains("Pushes`f   :     0  total"));
    assert!(alpha_stats.contains("Activity`f :     2 points"));
    assert!(alpha_stats.contains("Low activity"));
    let persisted = msgpack::unpack_exact(&fs::read(config.dir.join("stats")).unwrap()).unwrap();
    assert_eq!(sum_counter(&persisted, &["pages", "front"]), 1);
    assert_eq!(sum_counter(&persisted, &["groups", "public", "view"]), 1);
    assert_eq!(
        sum_counter(
            &persisted,
            &["groups", "public", "repositories", "alpha", "view"]
        ),
        1
    );
    assert_eq!(
        sum_counter(
            &persisted,
            &["groups", "public", "repositories", "alpha", "fetch"]
        ),
        1
    );

    let beta_stats = pages::render_page(
        pages::PATH_STATS,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "beta")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(beta_stats.contains(">Stats for beta"));
    assert!(beta_stats.contains("Pushes`f   :     1  total"));
    assert!(beta_stats.contains("Activity`f :     5 points"));

    assert!(config.dir.join("stats").exists());
}

#[test]
fn download_stats_are_recorded_and_rendered() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "payload.txt",
        "blob bytes\n",
    );
    let releases_path = release::release_sidecar_path(&repo_path);
    let release_dir = releases_path.join("v1");
    fs::create_dir_all(release_dir.join("artifacts")).unwrap();
    fs::write(
        release_dir.join("META"),
        "tag = v1\ncreated = 1\nstatus = published\ncreated_by = test\n",
    )
    .unwrap();
    fs::write(release_dir.join("artifacts/dist.tar"), b"artifact bytes").unwrap();
    let access_rules = access(&config);

    let blob = pages::download_file(
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_ref", "HEAD"),
            ("var_path", "payload.txt"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert_resource_bytes(blob, b"blob bytes\n");

    let artifact = pages::download_file(
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "v1"),
            ("var_artifact", "dist.tar"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert_resource_bytes(artifact, b"artifact bytes");

    let alpha_stats = pages::render_page(
        pages::PATH_STATS,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(alpha_stats.contains("Downloads`f:     2  total"));
    assert!(alpha_stats.contains(">Downloads"));

    let persisted = msgpack::unpack_exact(&fs::read(config.dir.join("stats")).unwrap()).unwrap();
    assert_eq!(
        sum_counter(
            &persisted,
            &["groups", "public", "repositories", "alpha", "download"]
        ),
        1
    );
    assert_eq!(
        sum_counter(
            &persisted,
            &[
                "groups",
                "public",
                "repositories",
                "alpha",
                "release_download",
            ]
        ),
        1
    );
}

#[test]
fn denied_and_failed_operations_do_not_record_stats() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );

    config.allow_read = vec!["none".into()];
    let read_denied = access(&config);
    let denied_fetch = server::handle_fetch(
        &config,
        &read_denied,
        &protocol::fetch_request("public/alpha", &[]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    match denied_fetch {
        RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], protocol::RES_DISALLOWED),
        RequestResponse::Resource { .. } => panic!("denied fetch unexpectedly returned resource"),
    }

    config.allow_read = vec!["all".into()];
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let write_denied = access(&config);
    let denied_push = server::handle_push(
        &config,
        &write_denied,
        &protocol::push_request("public/beta", Vec::new(), Vec::new()),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(denied_push[0], protocol::RES_DISALLOWED);

    let missing_fetch = server::handle_fetch(
        &config,
        &write_denied,
        &protocol::fetch_request("public/missing", &[]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    match missing_fetch {
        RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], protocol::RES_NOT_FOUND),
        RequestResponse::Resource { .. } => panic!("missing fetch unexpectedly returned resource"),
    }

    assert!(!config.dir.join("stats").exists());
}

#[test]
fn stats_persist_across_config_reloads() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access_rules = access(&config);

    pages::render_page(
        pages::PATH_REPO,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();

    let reloaded = cfg(tmp.path());
    let reloaded_access = access(&reloaded);
    let stats = pages::render_page(
        pages::PATH_STATS,
        &reloaded,
        &reloaded_access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();

    assert!(stats.contains("Views`f    :     1  total"));
}

#[test]
fn ignored_identities_and_disabled_recording_do_not_mutate_stats() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ignored = cfg(tmp.path());
    ignored.stats_ignore_identities = vec![REMOTE];
    create_repo(
        ignored.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let ignored_access = access(&ignored);

    pages::render_page(
        pages::PATH_REPO,
        &ignored,
        &ignored_access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    let fetch = server::handle_fetch(
        &ignored,
        &ignored_access,
        &protocol::fetch_request("public/alpha", &[]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_fetch_ok(fetch);
    let push = server::handle_push(
        &ignored,
        &ignored_access,
        &protocol::push_request("public/beta", Vec::new(), Vec::new()),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(push[0], protocol::RES_OK);

    let ignored_stats = pages::render_page(
        pages::PATH_STATS,
        &ignored,
        &ignored_access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(ignored_stats.contains("Views`f    :     0  total"));
    assert!(ignored_stats.contains(
        "No development activity recorded for this repository in the selected time period.\n\n`*"
    ));
    let ignored_beta = pages::render_page(
        pages::PATH_STATS,
        &ignored,
        &ignored_access,
        &page_request(&[("var_g", "public"), ("var_r", "beta")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(ignored_beta.contains("Pushes`f   :     0  total"));

    let tmp = tempfile::tempdir().unwrap();
    let mut disabled = cfg(tmp.path());
    disabled.record_stats = false;
    create_repo(
        disabled.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let disabled_access = access(&disabled);

    pages::render_page(
        pages::PATH_REPO,
        &disabled,
        &disabled_access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();

    let disabled_stats = pages::render_page(
        pages::PATH_STATS,
        &disabled,
        &disabled_access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(disabled_stats.contains("Views`f    :     0  total"));
    assert!(!disabled.dir.join("stats").exists());
}

fn cfg(root: &Path) -> ServerConfig {
    ServerConfig {
        dir: root.to_path_buf(),
        reticulum_dir: None,
        repositories_dir: root.join("repositories"),
        identity_path: root.join("repositories_identity"),
        client_identity_path: root.join("client_identity"),
        node_name: "Stats Test Node".into(),
        announce_interval_secs: 300,
        serve_nomadnet: true,
        templates_dir: root.join("templates"),
        unicode_icons: false,
        record_stats: true,
        stats_ignore_identities: Vec::new(),
        allow_read: vec!["all".into()],
        allow_write: vec!["all".into()],
        allow_create: vec!["all".into()],
        allow_stats: vec!["all".into()],
        allow_release: vec!["none".into()],
        allow_interact: vec!["none".into()],
        allow_admin: vec!["none".into()],
        log_level: logging::DEFAULT_LOG_LEVEL,
    }
}

fn access(config: &ServerConfig) -> Access {
    Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap()
}

fn page_request(fields: &[(&str, &str)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), Value::Str((*v).into())))
            .collect(),
    ))
}

fn create_repo(path: PathBuf, file: &str, content: &str) -> PathBuf {
    let work = path.with_extension("work");
    fs::create_dir_all(&work).unwrap();
    run_git(Command::new("git").arg("init").arg(&work));
    let file_path = work.join(file);
    fs::create_dir_all(file_path.parent().unwrap()).unwrap();
    fs::write(&file_path, content).unwrap();
    run_git(Command::new("git").arg("-C").arg(&work).arg("add").arg("."));
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .arg("-c")
            .arg("user.name=RNS Stats Test")
            .arg("-c")
            .arg("user.email=rns-stats-test@example.invalid")
            .arg("commit")
            .arg("-m")
            .arg("initial"),
    );
    run_git(
        Command::new("git")
            .arg("-C")
            .arg(&work)
            .args(["branch", "-M", "main"]),
    );
    run_git(
        Command::new("git")
            .arg("clone")
            .arg("--bare")
            .arg(&work)
            .arg(&path),
    );
    path
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

fn assert_fetch_ok(response: RequestResponse) {
    match response {
        RequestResponse::Resource { metadata, .. } => {
            assert_eq!(
                metadata.as_deref(),
                Some(&protocol::metadata_status(protocol::RES_OK)[..])
            );
        }
        RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], protocol::RES_OK),
    }
}

fn assert_resource_bytes(response: RequestResponse, expected: &[u8]) {
    match response {
        RequestResponse::Resource { data, metadata, .. } => {
            assert_eq!(data, expected);
            assert_eq!(
                metadata.as_deref(),
                Some(&protocol::metadata_status(protocol::RES_OK)[..])
            );
        }
        RequestResponse::Bytes(bytes) => panic!("expected resource response, got {bytes:?}"),
    }
}

fn sum_counter(value: &Value, path: &[&str]) -> u64 {
    let mut cursor = value;
    for key in path {
        cursor = cursor.map_get(key).expect("stats path component");
    }
    cursor
        .as_map()
        .unwrap()
        .iter()
        .map(|(_, value)| value.as_integer().unwrap() as u64)
        .sum()
}
