use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rns_core::msgpack::{self, Value};
use rns_git::acl::Access;
use rns_git::config::ServerConfig;
use rns_git::logging;
use rns_git::{pages, protocol, server};
use rns_net::RequestResponse;

const REMOTE: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const REMOTE_SIG: [u8; 64] = [0x42; 64];

#[test]
fn release_create_requires_release_permission_but_list_and_view_require_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_release = vec!["none".into()];
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);

    let denied = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("init")),
            ("tag", strv("v1")),
            ("notes", strv("# Release\n")),
            ("notes_format", strv("markdown")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(denied[0], protocol::RES_DISALLOWED);

    let listed = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("list")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(listed[0], protocol::RES_OK);
    assert_eq!(listed_array(&listed).len(), 0);

    fs::write(
        config.repositories_dir.join("public/alpha/.allowed"),
        "release = all\n",
    )
    .unwrap();
    let access_rules = access(&config);
    let created = create_release(&config, &access_rules, "public/alpha", "v1", "# Release\n");
    assert_eq!(created[0], protocol::RES_OK);

    let listed = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("list")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    let releases = listed_array(&listed);
    assert_eq!(releases.len(), 1);
    assert_eq!(map_str(releases[0].as_map().unwrap(), "tag"), Some("v1"));
    assert_eq!(
        map_str(releases[0].as_map().unwrap(), "status"),
        Some("draft")
    );
}

#[test]
fn release_create_stores_metadata_notes_artifacts_and_finalizes() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);

    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v1", "# Release\n")[0],
        protocol::RES_OK
    );
    let artifact = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("artifact")),
            ("tag", strv("v1")),
            ("artifact_name", strv("../dist.tar")),
            ("artifact_data", binv(b"artifact bytes")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(artifact[0], protocol::RES_OK);
    let finalize = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("finalize")),
            ("tag", strv("v1")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(finalize[0], protocol::RES_OK);

    let release_dir = config.repositories_dir.join("public/alpha.releases/v1");
    assert!(release_dir.join("META").exists());
    assert_eq!(
        fs::read_to_string(release_dir.join("RELEASE.md")).unwrap(),
        "# Release\n"
    );
    assert_eq!(
        fs::read(release_dir.join("artifacts/dist.tar")).unwrap(),
        b"artifact bytes"
    );
    assert!(fs::read_to_string(release_dir.join("META"))
        .unwrap()
        .contains("status = published"));
    assert_eq!(
        fs::read_to_string(config.repositories_dir.join("public/alpha.releases/latest")).unwrap(),
        "v1"
    );

    let view = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("view")),
            ("tag", strv("v1")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(view[0], protocol::RES_OK);
    let release = body_value(&view);
    let map = release.as_map().unwrap();
    assert_eq!(map_str(map, "status"), Some("published"));
    assert_eq!(map_str(map, "notes_format"), Some("markdown"));
    assert_eq!(map_str(map, "notes"), Some("# Release\n"));
    assert_eq!(map_array(map, "artifacts").len(), 1);

    let late_artifact = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("artifact")),
            ("tag", strv("v1")),
            ("artifact_name", strv("late.tar")),
            ("artifact_data", binv(b"late bytes")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(late_artifact[0], protocol::RES_DISALLOWED);
    assert!(!release_dir.join("artifacts/late.tar").exists());
}

#[test]
fn release_delete_removes_sidecar_and_invalid_tags_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);

    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v1", "# Release\n")[0],
        protocol::RES_OK
    );
    let duplicate = create_release(&config, &access_rules, "public/alpha", "v1", "# Again\n");
    assert_eq!(duplicate[0], protocol::RES_DISALLOWED);

    let invalid = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("init")),
            ("tag", strv("missing")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(invalid[0], protocol::RES_INVALID_REQ);

    let delete = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("delete")),
            ("tag", strv("../v1")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(delete[0], protocol::RES_INVALID_REQ);
    assert!(config
        .repositories_dir
        .join("public/alpha.releases/v1")
        .exists());
}

#[test]
fn release_operations_reject_slash_containing_tags() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);
    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v1", "# Release\n")[0],
        protocol::RES_OK
    );

    for fields in [
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("view")),
            ("tag", strv("nested/v1")),
        ],
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("init")),
            ("tag", strv("nested/v1")),
        ],
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("artifact")),
            ("tag", strv("nested/v1")),
            ("artifact_name", strv("dist.tar")),
            ("artifact_data", binv(b"artifact")),
        ],
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("create")),
            ("step", strv("finalize")),
            ("tag", strv("nested/v1")),
        ],
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("delete")),
            ("tag", strv("nested/v1")),
        ],
        vec![
            ("repository", strv("public/alpha")),
            ("operation", strv("latest")),
            ("tag", strv("nested/v1")),
        ],
    ] {
        let response = server::handle_release(
            &config,
            &access_rules,
            &release_request(&fields),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap();
        assert_eq!(response[0], protocol::RES_INVALID_REQ, "{fields:?}");
    }
}

#[test]
fn release_pages_render_published_releases_latest_artifacts_and_thanks() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);
    create_published_release(&config, &access_rules, "public/alpha", "v1", "# Release\n");

    let repo_page = pages::render_page(
        pages::PATH_REPO,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(repo_page.contains("Releases (1)"));
    assert!(repo_page.contains(pages::PATH_RELEASES));

    let releases = pages::render_page(
        pages::PATH_RELEASES,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(releases.contains(">Releases (1)"));
    assert!(releases.contains("v1"));
    assert!(releases.contains("Release"));

    let release = pages::render_page(
        pages::PATH_RELEASE,
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "latest"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(release.contains(">Release v1"));
    assert!(release.contains(">Release"));
    assert!(release.contains("dist.tar"));
    assert!(release.contains("Thanks (0)"));

    let thanked = pages::render_page(
        pages::PATH_RELEASE,
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "v1"),
            ("var_thanks", "y"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(thanked.contains("Thanks (1)"));
}

#[test]
fn release_latest_operation_sets_explicit_latest_for_pages_and_downloads() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    tag_repo(&repo_path, "v2");
    let access_rules = access(&config);
    create_published_release(&config, &access_rules, "public/alpha", "v1", "# First\n");
    create_published_release(&config, &access_rules, "public/alpha", "v2", "# Second\n");

    let listed = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("list")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(listed_latest(&listed), Some("v2".to_string()));

    let latest = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("latest")),
            ("tag", strv("v1")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(latest[0], protocol::RES_OK);
    assert_eq!(
        fs::read_to_string(config.repositories_dir.join("public/alpha.releases/latest")).unwrap(),
        "v1"
    );

    let listed = server::handle_release(
        &config,
        &access_rules,
        &release_request(&[
            ("repository", strv("public/alpha")),
            ("operation", strv("list")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(listed_latest(&listed), Some("v1".to_string()));
    assert_eq!(listed_array(&listed).len(), 2);

    let releases = pages::render_page(
        pages::PATH_RELEASES,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(releases.contains("v1"));
    assert!(releases.contains("Latest"));

    let release = pages::render_page(
        pages::PATH_RELEASE,
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "latest"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(release.contains(">Release v1"));
    assert!(release.contains("First"));
    assert!(!release.contains("Second"));

    let artifact = pages::download_file(
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "latest"),
            ("var_artifact", "dist.tar"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert_response_bytes(artifact, b"artifact bytes");
}

#[test]
fn release_page_formats_empty_artifacts_and_sorts_artifact_links() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    tag_repo(&repo_path, "v2");
    let access_rules = access(&config);

    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v1", "# Empty\n")[0],
        protocol::RES_OK
    );
    assert_eq!(
        server::handle_release(
            &config,
            &access_rules,
            &release_request(&[
                ("repository", strv("public/alpha")),
                ("operation", strv("create")),
                ("step", strv("finalize")),
                ("tag", strv("v1")),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );

    let empty = pages::render_page(
        pages::PATH_RELEASE,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha"), ("var_tag", "v1")]),
        Some(&REMOTE),
    )
    .unwrap();
    assert!(empty.contains("`*No artifacts for this release`*"));

    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v2", "# Files\n")[0],
        protocol::RES_OK
    );
    for artifact in ["z-last.tar", "a-first.tar"] {
        assert_eq!(
            server::handle_release(
                &config,
                &access_rules,
                &release_request(&[
                    ("repository", strv("public/alpha")),
                    ("operation", strv("create")),
                    ("step", strv("artifact")),
                    ("tag", strv("v2")),
                    ("artifact_name", strv(artifact)),
                    ("artifact_data", binv(b"artifact bytes")),
                ]),
                Some(&(REMOTE, REMOTE_SIG)),
            )
            .unwrap()[0],
            protocol::RES_OK
        );
    }
    assert_eq!(
        server::handle_release(
            &config,
            &access_rules,
            &release_request(&[
                ("repository", strv("public/alpha")),
                ("operation", strv("create")),
                ("step", strv("finalize")),
                ("tag", strv("v2")),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );

    let with_artifacts = pages::render_page(
        pages::PATH_RELEASE,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "alpha"), ("var_tag", "v2")]),
        Some(&REMOTE),
    )
    .unwrap();
    let first = with_artifacts.find("a-first.tar").unwrap();
    let last = with_artifacts.find("z-last.tar").unwrap();
    assert!(first < last);
}

#[test]
fn release_pages_render_preview_formats() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/previews"),
        "README.md",
        "# Previews\n",
    );
    create_sidecar_release(
        &repo_path,
        "v-md",
        3,
        "RELEASE.md",
        "# Heading\n> quoted preface\n**Markdown** preview\n",
    );
    create_sidecar_release(&repo_path, "v-mu", 2, "RELEASE.mu", "`!Micron`! preview\n");
    create_sidecar_release(&repo_path, "v-txt", 1, "RELEASE.txt", "<text preview>\n");
    let access_rules = access(&config);

    let releases = pages::render_page(
        pages::PATH_RELEASES,
        &config,
        &access_rules,
        &page_request(&[("var_g", "public"), ("var_r", "previews")]),
        Some(&REMOTE),
    )
    .unwrap();

    assert!(releases.contains("`!Markdown`! preview"));
    assert!(!releases.contains("Heading"));
    assert!(!releases.contains("quoted preface"));
    assert!(releases.contains("`!Micron`! preview"));
    assert!(releases.contains("\\<text preview>"));
}

#[test]
fn release_and_blob_downloads_respect_read_access_and_safe_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "payload.txt",
        "blob bytes\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);
    create_published_release(&config, &access_rules, "public/alpha", "v1", "# Release\n");

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
    assert_response_bytes(blob, b"blob bytes\n");

    let artifact = pages::download_file(
        &config,
        &access_rules,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_tag", "latest"),
            ("var_artifact", "../dist.tar"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert_response_bytes(artifact, b"artifact bytes");

    config.allow_read = vec!["none".into()];
    let denied = pages::download_file(
        &config,
        &access(&config),
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_ref", "HEAD"),
            ("var_path", "payload.txt"),
        ]),
        Some(&REMOTE),
    )
    .unwrap();
    assert_response_status(denied, protocol::RES_NOT_FOUND);
}

#[test]
fn release_artifact_download_decodes_url_escaped_artifact_names() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    tag_repo(&repo_path, "v1");
    let access_rules = access(&config);

    assert_eq!(
        create_release(&config, &access_rules, "public/alpha", "v1", "# Release\n")[0],
        protocol::RES_OK
    );
    assert_eq!(
        server::handle_release(
            &config,
            &access_rules,
            &release_request(&[
                ("repository", strv("public/alpha")),
                ("operation", strv("create")),
                ("step", strv("artifact")),
                ("tag", strv("v1")),
                ("artifact_name", strv("dist file.tar")),
                ("artifact_data", binv(b"artifact bytes")),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );
    assert_eq!(
        server::handle_release(
            &config,
            &access_rules,
            &release_request(&[
                ("repository", strv("public/alpha")),
                ("operation", strv("create")),
                ("step", strv("finalize")),
                ("tag", strv("v1")),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );

    for encoded in ["dist+file.tar", "dist%20file.tar"] {
        let artifact = pages::download_file(
            &config,
            &access_rules,
            &page_request(&[
                ("var_g", "public"),
                ("var_r", "alpha"),
                ("var_tag", "v1"),
                ("var_artifact", encoded),
            ]),
            Some(&REMOTE),
        )
        .unwrap();
        assert_response_bytes(artifact, b"artifact bytes");
    }
}

fn cfg(root: &Path) -> ServerConfig {
    ServerConfig {
        dir: root.to_path_buf(),
        reticulum_dir: None,
        repositories_dir: root.join("repositories"),
        identity_path: root.join("repositories_identity"),
        client_identity_path: root.join("client_identity"),
        node_name: "Release Test Node".into(),
        announce_interval_secs: 300,
        serve_nomadnet: true,
        templates_dir: root.join("templates"),
        unicode_icons: false,
        record_stats: false,
        stats_ignore_identities: Vec::new(),
        identity_aliases: std::collections::BTreeMap::new(),
        allow_read: vec!["all".into()],
        allow_write: vec!["all".into()],
        allow_create: vec!["all".into()],
        allow_stats: vec!["all".into()],
        allow_release: vec!["all".into()],
        allow_interact: vec!["none".into()],
        allow_propose: vec!["none".into()],
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

fn release_request(fields: &[(&str, Value)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), v.clone()))
            .collect(),
    ))
}

fn page_request(fields: &[(&str, &str)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), Value::Str((*v).into())))
            .collect(),
    ))
}

fn strv(value: &str) -> Value {
    Value::Str(value.to_string())
}

fn binv(value: &[u8]) -> Value {
    Value::Bin(value.to_vec())
}

fn create_release(
    config: &ServerConfig,
    access_rules: &Access,
    repository: &str,
    tag: &str,
    notes: &str,
) -> Vec<u8> {
    let repo_path = config.repositories_dir.join(repository);
    let hash = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo_path)
            .args(["rev-parse", tag]),
    );
    server::handle_release(
        config,
        access_rules,
        &release_request(&[
            ("repository", strv(repository)),
            ("operation", strv("create")),
            ("step", strv("init")),
            ("tag", strv(tag)),
            ("hash", strv(hash.trim())),
            ("notes", strv(notes)),
            ("notes_format", strv("markdown")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap()
}

fn create_published_release(
    config: &ServerConfig,
    access_rules: &Access,
    repo: &str,
    tag: &str,
    notes: &str,
) {
    assert_eq!(
        create_release(config, access_rules, repo, tag, notes)[0],
        protocol::RES_OK
    );
    assert_eq!(
        server::handle_release(
            config,
            access_rules,
            &release_request(&[
                ("repository", strv(repo)),
                ("operation", strv("create")),
                ("step", strv("artifact")),
                ("tag", strv(tag)),
                ("artifact_name", strv("dist.tar")),
                ("artifact_data", binv(b"artifact bytes")),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );
    assert_eq!(
        server::handle_release(
            config,
            access_rules,
            &release_request(&[
                ("repository", strv(repo)),
                ("operation", strv("create")),
                ("step", strv("finalize")),
                ("tag", strv(tag)),
            ]),
            Some(&(REMOTE, REMOTE_SIG)),
        )
        .unwrap()[0],
        protocol::RES_OK
    );
}

fn create_sidecar_release(
    repo_path: &std::path::Path,
    tag: &str,
    created: u64,
    notes_file: &str,
    notes: &str,
) {
    let release_dir = rns_git::release::release_sidecar_path(repo_path).join(tag);
    fs::create_dir_all(release_dir.join("artifacts")).unwrap();
    fs::write(
        release_dir.join("META"),
        format!("tag = {tag}\ncreated = {created}\nstatus = published\ncreated_by = tester\n"),
    )
    .unwrap();
    fs::write(release_dir.join(notes_file), notes).unwrap();
}

fn listed_array(response: &[u8]) -> Vec<Value> {
    let body = body_value(response);
    match body {
        Value::Array(values) => values,
        Value::Map(entries) => entries
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (Value::Str(key), Value::Array(values)) if key == "releases" => {
                    Some(values.clone())
                }
                _ => None,
            })
            .unwrap(),
        _ => panic!("unexpected release list response: {body:?}"),
    }
}

fn listed_latest(response: &[u8]) -> Option<String> {
    let body = body_value(response);
    match body {
        Value::Map(entries) => entries
            .into_iter()
            .find_map(|(key, value)| match (key, value) {
                (Value::Str(key), Value::Str(value)) if key == "latest" => Some(value),
                _ => None,
            }),
        _ => None,
    }
}

fn body_value(response: &[u8]) -> Value {
    assert_eq!(response[0], protocol::RES_OK);
    msgpack::unpack_exact(&response[1..]).unwrap()
}

fn map_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (Value::Str(k), Value::Str(v)) if k == key => Some(v.as_str()),
        _ => None,
    })
}

fn map_array<'a>(map: &'a [(Value, Value)], key: &str) -> &'a [Value] {
    map.iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Str(k), Value::Array(values)) if k == key => Some(values.as_slice()),
            _ => None,
        })
        .unwrap()
}

fn assert_response_bytes(response: RequestResponse, expected: &[u8]) {
    match response {
        RequestResponse::Bytes(bytes) => assert_eq!(bytes, expected),
        RequestResponse::Resource { data, metadata, .. } => {
            assert_eq!(
                metadata.as_deref(),
                Some(&protocol::metadata_status(protocol::RES_OK)[..])
            );
            assert_eq!(data, expected);
        }
    }
}

fn assert_response_status(response: RequestResponse, status: u8) {
    match response {
        RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], status),
        RequestResponse::Resource { .. } => panic!("expected status response"),
    }
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
            .arg("user.name=RNS Release Test")
            .arg("-c")
            .arg("user.email=rns-release-test@example.invalid")
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

fn tag_repo(repo: &Path, tag: &str) {
    run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .args(["tag", tag, "refs/heads/main"]),
    );
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
