use super::*;
use crate::acl::Operation;
use rns_core::msgpack::{self, Value};
use rns_crypto::OsRng;

const REMOTE: [u8; 16] = [0x44; 16];
const OTHER_REMOTE: [u8; 16] = [0x55; 16];
const REMOTE_SIG: [u8; 64] = [0x66; 64];

fn cfg(root: &std::path::Path) -> ServerConfig {
    ServerConfig {
        dir: root.to_path_buf(),
        reticulum_dir: None,
        repositories_dir: root.join("repositories"),
        identity_path: root.join("repositories_identity"),
        client_identity_path: root.join("client_identity"),
        node_name: "Anonymous Git Node".into(),
        announce_interval_secs: 300,
        costs: Default::default(),
        pages_costs: Ok(Default::default()),
        serve_nomadnet: false,
        templates_dir: root.join("templates"),
        unicode_icons: false,
        media_conversion: true,
        record_stats: false,
        stats_ignore_identities: Vec::new(),
        stats_push_ignore_identities: Vec::new(),
        blocked_identities: Vec::new(),
        identity_aliases: std::collections::BTreeMap::new(),
        allow_read: vec!["all".into()],
        allow_write: vec!["all".into()],
        allow_create: vec!["all".into()],
        allow_stats: vec!["none".into()],
        allow_release: vec!["none".into()],
        allow_interact: vec!["none".into()],
        allow_propose: vec!["none".into()],
        allow_admin: vec!["none".into()],
        log_level: logging::DEFAULT_LOG_LEVEL,
    }
}

#[test]
fn parses_base256_print_identity_options() {
    let opts = ServerOptions::parse(vec![
        "--print-identity".to_string(),
        "--base256".to_string(),
    ])
    .unwrap();
    assert!(opts.print_identity);
    assert!(opts.base256);

    let short = ServerOptions::parse(vec!["-Z".to_string()]).unwrap();
    assert!(short.base256);
}

#[test]
fn rejects_unsupported_service_mode_flags() {
    let service = ServerOptions::parse(vec!["--service".to_string()]).unwrap_err();
    assert!(service.to_string().contains("not supported"));

    let interactive = ServerOptions::parse(vec!["--interactive".to_string()]).unwrap_err();
    assert!(interactive.to_string().contains("not supported"));
}

#[test]
fn repository_destination_uses_git_repositories_name() {
    let identity = Identity::new(&mut OsRng);
    let destination = repository_destination(&identity);
    let expected = Destination::single_in("git", &["repositories"], IdentityHash(*identity.hash()));
    assert_eq!(destination.hash, expected.hash);
}

#[test]
fn identity_report_includes_nomadnet_destination_only_when_enabled() {
    let identity = Identity::new(&mut OsRng);
    let client = Identity::new(&mut OsRng);

    let without_pages = identity_report(&identity, &client, false, false);
    assert!(!without_pages.contains("nomadnet_destination"));

    let with_pages = identity_report(&identity, &client, true, true);
    let nomadnet = pages::destination_for_identity(&identity);
    assert!(with_pages.contains(&format!("nomadnet_destination = {}", hex(&nomadnet.hash.0))));
    assert!(with_pages.contains("nomadnet_destination_b256 = "));
}

#[test]
fn list_missing_repo_returns_not_found_status() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::repository_request("group/repo");
    let resp = handle_list(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_NOT_FOUND);
}

#[test]
fn push_is_blocked_by_acl() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_DISALLOWED);
}

#[test]
fn push_can_create_missing_repo_with_global_create() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["all".into()];
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(
        &config.repositories_dir.join("repo")
    ));
}

#[test]
fn global_write_alone_cannot_create_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["all".into()];
    config.allow_create = vec!["none".into()];
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_DISALLOWED);
    assert!(!config.repositories_dir.join("repo").exists());
}

#[test]
fn existing_repo_push_still_requires_write() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("repo")).unwrap();
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_DISALLOWED);
}

#[test]
fn repo_allowed_file_can_grant_create_for_missing_bare_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let repo = config.repositories_dir.join("group/repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".allowed"), "create = all\n").unwrap();
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(&repo));
}

#[test]
fn repo_sidecar_allowed_file_can_grant_create_for_missing_bare_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let repo = config.repositories_dir.join("group/repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        config.repositories_dir.join("group/repo.allowed"),
        "create = all\n",
    )
    .unwrap();
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(&repo));
}

#[test]
fn group_allowed_file_can_grant_create_for_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let group = config.repositories_dir.join("group");
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(group.join("group.allowed"), "create = all\n").unwrap();
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(
        &config.repositories_dir.join("group/repo")
    ));
}

#[test]
fn group_sidecar_allowed_file_can_grant_create_for_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["none".into()];
    let group = config.repositories_dir.join("group");
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(
        config.repositories_dir.join("group.allowed"),
        "create = all\n",
    )
    .unwrap();
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("group/repo", Vec::new(), Vec::new());
    let resp = handle_push(&config, &access, &req, None).unwrap();
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(
        &config.repositories_dir.join("group/repo")
    ));
}

#[test]
fn create_handler_initializes_bare_repo_and_grants_creator_admin() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    let group = config.repositories_dir.join("group");
    std::fs::create_dir_all(&group).unwrap();
    let access = make_access(&config);
    let remote = ([0x11; 16], [0u8; 64]);
    let req = protocol::repository_request("group/created");

    let resp = handle_create(&config, &access, &req, Some(&remote)).unwrap();

    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(
        &config.repositories_dir.join("group/created")
    ));
    assert_eq!(
        std::fs::read_to_string(config.repositories_dir.join("group/created.allowed")).unwrap(),
        "adm:11111111111111111111111111111111\n"
    );
    assert!(access
        .allows(Operation::Write, "group/created", Some(&remote.0))
        .unwrap());
}

#[test]
fn create_handler_requires_identified_peer_and_existing_group() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    let access = make_access(&config);
    let req = protocol::repository_request("group/created");

    let anonymous = handle_create(&config, &access, &req, None).unwrap();
    assert_eq!(anonymous[0], protocol::RES_DISALLOWED);

    let remote = ([0x11; 16], [0u8; 64]);
    let missing_group = handle_create(&config, &access, &req, Some(&remote)).unwrap();
    assert_eq!(missing_group[0], protocol::RES_NOT_FOUND);
}

#[test]
fn create_handler_rejects_existing_or_invalid_repositories() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    git::ensure_bare_repository(&config.repositories_dir.join("group/existing")).unwrap();
    let access = make_access(&config);
    let remote = ([0x11; 16], [0u8; 64]);

    let existing = handle_create(
        &config,
        &access,
        &protocol::repository_request("group/existing"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(existing[0], protocol::RES_DISALLOWED);
    assert_eq!(&existing[1..], b"repository already exists");

    let nested = handle_create(
        &config,
        &access,
        &protocol::repository_request("group/nested/repo"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(nested[0], protocol::RES_INVALID_REQ);
}

#[test]
fn fork_handler_fetches_source_repo_and_records_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    create_source_repo(tmp.path());
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    let access = make_access(&config);
    let remote = ([0x22; 16], [0u8; 64]);
    let daemon = git::test_support::GitDaemon::serve(tmp.path());
    let source_url = daemon.url("source-master");
    let req = protocol::remote_clone_request("group/forked", &source_url);

    let resp = handle_fork(&config, &access, &req, Some(&remote)).unwrap();

    let target = config.repositories_dir.join("group/forked");
    assert_eq!(resp[0], protocol::RES_OK);
    assert!(git::is_bare_repository(&target));
    assert!(!git::list_refs(&target).unwrap().is_empty());
    assert_eq!(git_config(&target, "repository.rngit.type"), "fork");
    assert_eq!(
        git_config(&target, "repository.rngit.upstream.source"),
        source_url
    );
    assert!(git_config(&target, "repository.rngit.upstream.sync")
        .parse::<u64>()
        .is_ok());
    assert_eq!(
        std::fs::read_to_string(config.repositories_dir.join("group/forked.allowed")).unwrap(),
        "adm:22222222222222222222222222222222\n"
    );
}

#[test]
fn mirror_handler_records_mirror_type() {
    let tmp = tempfile::tempdir().unwrap();
    create_source_repo_on_branch(tmp.path(), "main");
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    let access = make_access(&config);
    let remote = ([0x22; 16], [0u8; 64]);
    let daemon = git::test_support::GitDaemon::serve(tmp.path());
    let req = protocol::remote_clone_request("group/mirrored", &daemon.url("source-main"));

    let resp = handle_mirror(&config, &access, &req, Some(&remote)).unwrap();

    let target = config.repositories_dir.join("group/mirrored");
    assert_eq!(resp[0], protocol::RES_OK);
    assert_eq!(git_config(&target, "repository.rngit.type"), "mirror");
    assert_eq!(git_symbolic_ref(&target, "HEAD"), "refs/heads/main");
    assert!(git_config(&target, "repository.rngit.upstream.sync")
        .parse::<u64>()
        .is_ok());
}

#[test]
fn remote_clone_rejects_missing_source_and_existing_target() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    git::ensure_bare_repository(&config.repositories_dir.join("group/existing")).unwrap();
    let access = make_access(&config);
    let remote = ([0x22; 16], [0u8; 64]);

    let missing_source = handle_fork(
        &config,
        &access,
        &protocol::repository_request("group/new"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(missing_source[0], protocol::RES_INVALID_REQ);

    let local_source = create_source_repo(tmp.path());
    for source in [
        local_source.to_str().expect("utf-8 path").to_string(),
        format!("file://{}", local_source.display()),
        "--option=value".to_string(),
    ] {
        let rejected = handle_fork(
            &config,
            &access,
            &protocol::remote_clone_request("group/new", &source),
            Some(&remote),
        )
        .unwrap();
        assert_eq!(rejected[0], protocol::RES_INVALID_REQ, "{source:?}");
        assert!(!config.repositories_dir.join("group/new").exists());
    }

    let existing = handle_fork(
        &config,
        &access,
        &protocol::remote_clone_request("group/existing", "https://example.invalid/unused.git"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(existing[0], protocol::RES_DISALLOWED);
    assert_eq!(&existing[1..], b"repository already exists");
}

#[test]
fn sync_handler_fetches_upstream_updates_for_fork() {
    let tmp = tempfile::tempdir().unwrap();
    let source = create_source_repo(tmp.path());
    let mut config = cfg(tmp.path());
    config.allow_create = vec!["all".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    let access = make_access(&config);
    let remote = ([0x22; 16], [0u8; 64]);
    let daemon = git::test_support::GitDaemon::serve(tmp.path());
    let fork_req = protocol::remote_clone_request("group/forked", &daemon.url("source-master"));
    assert_eq!(
        handle_fork(&config, &access, &fork_req, Some(&remote)).unwrap()[0],
        protocol::RES_OK
    );

    let updated_sha = commit_source_file(&source, "second.txt", "second\n");

    let resp = handle_sync(
        &config,
        &access,
        &protocol::repository_request("group/forked"),
        Some(&remote),
    )
    .unwrap();

    assert_eq!(resp[0], protocol::RES_OK);
    assert_eq!(
        git_rev_parse(&config.repositories_dir.join("group/forked"), "HEAD"),
        updated_sha
    );
    assert!(git_config(
        &config.repositories_dir.join("group/forked"),
        "repository.rngit.upstream.sync"
    )
    .parse::<u64>()
    .is_ok());
}

#[test]
fn sync_handler_rejects_non_clone_or_missing_write_access() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    let repo = config.repositories_dir.join("group/plain");
    git::ensure_bare_repository(&repo).unwrap();
    let access = make_access(&config);
    let remote = ([0x22; 16], [0u8; 64]);

    let no_write = handle_sync(
        &config,
        &access,
        &protocol::repository_request("group/plain"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(no_write[0], protocol::RES_DISALLOWED);

    config.allow_write = vec!["all".into()];
    let access = make_access(&config);
    let plain = handle_sync(
        &config,
        &access,
        &protocol::repository_request("group/plain"),
        Some(&remote),
    )
    .unwrap();
    assert_eq!(plain[0], protocol::RES_INVALID_REQ);
    assert_eq!(&plain[1..], b"repository is neither fork nor mirror");
}

#[test]
fn push_rejects_invalid_repository_name_before_create_acl() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_create = vec!["all".into()];
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let req = protocol::push_request("../repo", Vec::new(), Vec::new());
    assert!(handle_push(&config, &access, &req, None).is_err());
}

#[test]
fn push_rejects_invalid_ref_before_creating_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = make_access(&config);
    let req = protocol::push_request(
        "group/repo",
        Vec::new(),
        vec![protocol::RefUpdate {
            refname: "-refs/heads/main".into(),
            old: None,
            new: Some("0123456789abcdef0123456789abcdef01234567".into()),
            force: true,
        }],
    );

    let resp = handle_push(&config, &access, &req, None).unwrap();

    assert_eq!(resp[0], protocol::RES_INVALID_REQ);
    assert!(!config.repositories_dir.join("group/repo").exists());
}

#[test]
fn push_rejects_invalid_sha_before_creating_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = make_access(&config);
    let req = protocol::push_request(
        "group/repo",
        Vec::new(),
        vec![protocol::RefUpdate {
            refname: "refs/heads/main".into(),
            old: None,
            new: Some("--not-a-sha".into()),
            force: true,
        }],
    );

    let resp = handle_push(&config, &access, &req, None).unwrap();

    assert_eq!(resp[0], protocol::RES_INVALID_REQ);
    assert!(!config.repositories_dir.join("group/repo").exists());
}

#[test]
fn fetch_existing_repo_can_return_ok_status_or_resource() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
    )
    .unwrap();
    let repo = config.repositories_dir.join("repo");
    git::ensure_bare_repository(&repo).unwrap();
    let req = protocol::fetch_request("repo", &[]);
    match handle_fetch(&config, &access, &req, None).unwrap() {
        RequestResponse::File { .. } => panic!("fetch should return a value"),
        RequestResponse::Bytes(bytes) => assert_eq!(bytes[0], protocol::RES_OK),
        RequestResponse::Resource { metadata, .. } => assert!(metadata.is_some()),
    }
}

#[test]
fn fetch_rejects_invalid_have_sha() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = make_access(&config);
    let repo = config.repositories_dir.join("repo");
    git::ensure_bare_repository(&repo).unwrap();
    let req = protocol::fetch_request("repo", &["--upload-pack=/tmp/x".into()]);

    let response = handle_fetch(&config, &access, &req, None).unwrap();

    let RequestResponse::Bytes(bytes) = response else {
        panic!("invalid fetch request should return status bytes");
    };
    assert_eq!(bytes[0], protocol::RES_INVALID_REQ);
}

#[test]
fn git_failures_return_generic_client_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = make_access(&config);
    let repo = config.repositories_dir.join("broken");
    create_corrupt_bare_repo(&repo);

    let list = handle_list(
        &config,
        &access,
        &protocol::repository_request("broken"),
        None,
    )
    .unwrap();
    assert_generic_remote_error(&list);

    let fetch = handle_fetch(
        &config,
        &access,
        &protocol::fetch_request("broken", &[]),
        None,
    )
    .unwrap();
    let RequestResponse::Bytes(fetch) = fetch else {
        panic!("corrupt repository fetch should return status bytes");
    };
    assert_generic_remote_error(&fetch);

    git::ensure_bare_repository(&config.repositories_dir.join("push-target")).unwrap();
    let push = handle_push(
        &config,
        &access,
        &protocol::push_request("push-target", b"not a git bundle".to_vec(), Vec::new()),
        None,
    )
    .unwrap();
    assert_generic_remote_error(&push);
}

#[test]
fn work_protocol_enforces_read_interact_and_write_access() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();

    config.allow_read = vec!["none".into()];
    config.allow_write = vec!["all".into()];
    config.allow_interact = vec!["all".into()];
    let access = make_access(&config);
    let list = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("list")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(list[0], protocol::RES_NOT_FOUND);

    config.allow_read = vec!["all".into()];
    config.allow_write = vec!["all".into()];
    config.allow_interact = vec!["none".into()];
    let access = make_access(&config);
    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Task")),
            ("content", strv("Body")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(create[0], protocol::RES_DISALLOWED);

    config.allow_interact = vec!["all".into()];
    config.allow_write = vec!["none".into()];
    let access = make_access(&config);
    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Task")),
            ("content", strv("Body")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(create[0], protocol::RES_DISALLOWED);

    config.allow_write = vec!["all".into()];
    let access = make_access(&config);
    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Task")),
            ("content", strv("Body")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(create[0], protocol::RES_OK);

    config.allow_write = vec!["none".into()];
    let access = make_access(&config);
    let comment = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("comment")),
            ("doc_id", uintv(1)),
            ("content", strv("Comment")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(comment[0], protocol::RES_OK);
}

#[test]
fn work_protocol_lifecycle_round_trips_documents_and_comments() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_interact = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();
    let access = make_access(&config);

    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Initial title")),
            ("content", strv("Initial body")),
            ("format", strv("micron")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    let created = body_value(&create);
    assert_eq!(created.map_get("id").and_then(Value::as_integer), Some(1));
    assert_eq!(
        created.map_get("scope").and_then(Value::as_str),
        Some("active")
    );

    let comment = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("comment")),
            ("doc_id", uintv(1)),
            ("content", strv("Progress update")),
            ("format", strv("markdown")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(
        body_value(&comment)
            .map_get("id")
            .and_then(Value::as_integer),
        Some(1)
    );

    let view = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("view")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    let view = body_value(&view);
    assert_eq!(
        view.map_get("content").and_then(Value::as_str),
        Some("Initial body")
    );
    let comments = view
        .map_get("comments")
        .and_then(Value::as_array)
        .expect("comments array");
    assert_eq!(comments.len(), 1);
    assert_eq!(
        comments[0].map_get("content").and_then(Value::as_str),
        Some("Progress update")
    );

    let edit = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("edit")),
            ("doc_id", uintv(1)),
            ("title", strv("Edited title")),
            ("content", strv("Edited body")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(edit, vec![protocol::RES_OK]);

    let complete = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("complete")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(
        body_value(&complete)
            .map_get("scope")
            .and_then(Value::as_str),
        Some("completed")
    );

    let all = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("list")),
            ("scope", strv("all")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    let all = body_value(&all);
    assert_eq!(
        all.map_get("active")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        all.map_get("completed")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );

    let activate = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("activate")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(
        body_value(&activate)
            .map_get("scope")
            .and_then(Value::as_str),
        Some("active")
    );

    let delete = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("delete")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(delete, vec![protocol::RES_OK]);
}

#[test]
fn work_view_and_edit_scope_all_return_not_found_for_missing_document() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["all".into()];
    config.allow_interact = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();
    let access = make_access(&config);

    let view = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("view")),
            ("scope", strv("all")),
            ("doc_id", uintv(99)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(view[0], protocol::RES_NOT_FOUND);

    let edit = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("edit")),
            ("scope", strv("all")),
            ("doc_id", uintv(99)),
            ("title", strv("Missing")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(edit[0], protocol::RES_NOT_FOUND);
}

#[test]
fn work_protocol_proposes_signed_documents_in_proposed_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_interact = vec!["none".into()];
    config.allow_propose = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();
    let access = make_access(&config);
    let identity = Identity::new(&mut OsRng);
    let remote_hash = *identity.hash();
    let remote_pubkey: [u8; 64] = identity.get_public_key().unwrap();
    let signature = identity.sign(b"Proposal body").unwrap().to_vec();

    let proposed = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("propose")),
            ("title", strv("Proposal")),
            ("content", strv("Proposal body")),
            ("signature", binv(&signature)),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    let proposed = body_value(&proposed);
    assert_eq!(proposed.map_get("id").and_then(Value::as_integer), Some(1));
    assert_eq!(
        proposed.map_get("scope").and_then(Value::as_str),
        Some("proposed")
    );

    let list = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("list")),
            ("scope", strv("all")),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    let list = body_value(&list);
    assert_eq!(
        list.map_get("proposed")
            .and_then(Value::as_array)
            .unwrap()
            .len(),
        1
    );

    let edit = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("edit")),
            ("scope", strv("proposed")),
            ("doc_id", uintv(1)),
            ("title", strv("Updated proposal")),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    assert_eq!(edit, vec![protocol::RES_OK]);

    let invalid = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("propose")),
            ("title", strv("Unsigned")),
            ("content", strv("Unsigned body")),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    assert_eq!(invalid[0], protocol::RES_INVALID_REQ);
}

#[test]
fn work_protocol_validates_and_exposes_document_signatures() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_interact = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();
    let access = make_access(&config);
    let identity = Identity::new(&mut OsRng);
    let remote_hash = *identity.hash();
    let remote_pubkey: [u8; 64] = identity.get_public_key().unwrap();
    let signature = identity.sign(b"Signed body").unwrap().to_vec();

    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Signed task")),
            ("content", strv("Signed body")),
            ("signature", binv(&signature)),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    assert_eq!(create[0], protocol::RES_OK);

    let view = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("view")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    let view = body_value(&view);
    let meta = view.map_get("meta").unwrap();
    assert_eq!(
        meta.map_get("signature").and_then(Value::as_bin),
        Some(signature.as_slice())
    );
    assert_eq!(
        meta.map_get("identity").and_then(Value::as_bin),
        Some(remote_pubkey.as_slice())
    );

    let invalid = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Invalid task")),
            ("content", strv("Different body")),
            ("signature", binv(&signature)),
        ]),
        Some(&(remote_hash, remote_pubkey)),
    )
    .unwrap();
    assert_eq!(invalid[0], protocol::RES_INVALID_REQ);
}

#[test]
fn work_admins_can_transition_another_authors_document() {
    for document_admin in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = cfg(tmp.path());
        config.allow_interact = vec!["all".into()];
        if !document_admin {
            config.allow_admin = vec![crate::util::hex(&OTHER_REMOTE)];
        }
        let repo_path = config.repositories_dir.join("group/repo");
        git::ensure_bare_repository(&repo_path).unwrap();
        let work_path = crate::work::work_sidecar_path(&repo_path);
        crate::work::create_document(
            &work_path,
            crate::work::WorkInput {
                title: "Task".into(),
                content: "Body".into(),
                format: "plain".into(),
                signature: None,
                identity: None,
                author: REMOTE,
            },
        )
        .unwrap();
        if document_admin {
            crate::work::set_document_permissions(
                &work_path,
                1,
                &format!("admin = {}\n", crate::util::hex(&OTHER_REMOTE)),
            )
            .unwrap();
        }
        let access = make_access(&config);
        for operation in ["complete", "activate"] {
            let response = handle_work(
                &config,
                &access,
                &work_request(&[
                    ("repository", strv("group/repo")),
                    ("operation", strv(operation)),
                    ("doc_id", uintv(1)),
                ]),
                Some(&(OTHER_REMOTE, REMOTE_SIG)),
            )
            .unwrap();
            assert_eq!(response[0], protocol::RES_OK, "{operation}: {response:?}");
        }
        assert_eq!(crate::work::document_author(&work_path, 1).unwrap(), REMOTE);
        crate::work::set_document_permissions(&work_path, 1, "admin = none\n").unwrap();
        let denied = handle_work(
            &config,
            &access,
            &work_request(&[
                ("repository", strv("group/repo")),
                ("operation", strv("complete")),
                ("doc_id", uintv(1)),
            ]),
            Some(&(OTHER_REMOTE, REMOTE_SIG)),
        )
        .unwrap();
        assert_eq!(denied[0], protocol::RES_DISALLOWED);
        let response = handle_work(
            &config,
            &access,
            &work_request(&[
                ("repository", strv("group/repo")),
                ("operation", strv("edit")),
                ("doc_id", uintv(1)),
                ("content", strv("Other edit")),
            ]),
            Some(&(OTHER_REMOTE, REMOTE_SIG)),
        )
        .unwrap();
        assert_eq!(response[0], protocol::RES_DISALLOWED);
    }
}

#[test]
fn work_protocol_rejects_non_author_management_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_interact = vec!["all".into()];
    git::ensure_bare_repository(&config.repositories_dir.join("group/repo")).unwrap();
    let access = make_access(&config);

    let create = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("create")),
            ("title", strv("Task")),
            ("content", strv("Body")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(create[0], protocol::RES_OK);

    for operation in ["edit", "complete", "delete"] {
        let denied = handle_work(
            &config,
            &access,
            &work_request(&[
                ("repository", strv("group/repo")),
                ("operation", strv(operation)),
                ("doc_id", uintv(1)),
                ("content", strv("Other edit")),
            ]),
            Some(&(OTHER_REMOTE, REMOTE_SIG)),
        )
        .unwrap();
        assert_eq!(denied[0], protocol::RES_DISALLOWED);
    }
}

#[test]
fn work_document_local_interact_allows_comments_without_repo_interact() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_interact = vec!["none".into()];
    let repo_path = config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let work_path = crate::work::work_sidecar_path(&repo_path);
    crate::work::create_document(
        &work_path,
        crate::work::WorkInput {
            title: "Task".into(),
            content: "Body".into(),
            format: "markdown".into(),
            signature: None,
            identity: None,
            author: REMOTE,
        },
    )
    .unwrap();
    std::fs::write(work_path.join("1.allowed"), "interact = all\n").unwrap();
    let access = make_access(&config);

    let comment = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("comment")),
            ("doc_id", uintv(1)),
            ("content", strv("Comment from doc ACL")),
        ]),
        Some(&(OTHER_REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(comment[0], protocol::RES_OK);

    let edit = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("edit")),
            ("doc_id", uintv(1)),
            ("content", strv("Not allowed")),
        ]),
        Some(&(OTHER_REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(edit[0], protocol::RES_DISALLOWED);
}

#[test]
fn work_permissions_get_set_and_validation_are_author_gated() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_interact = vec!["all".into()];
    let repo_path = config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let work_path = crate::work::work_sidecar_path(&repo_path);
    crate::work::create_document(
        &work_path,
        crate::work::WorkInput {
            title: "Task".into(),
            content: "Body".into(),
            format: "markdown".into(),
            signature: None,
            identity: None,
            author: REMOTE,
        },
    )
    .unwrap();
    let access = make_access(&config);

    let get = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("get")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(
        body_value(&get).map_get("content").and_then(Value::as_str),
        Some("")
    );

    let content = format!(
        "interact = {}\nadmin = {}\n",
        crate::util::hex(&OTHER_REMOTE),
        crate::util::hex(&OTHER_REMOTE)
    );
    let set = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("set")),
            ("doc_id", uintv(1)),
            ("content", strv(&content)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(set, vec![protocol::RES_OK]);
    assert_eq!(
        std::fs::read_to_string(work_path.join("1.allowed")).unwrap(),
        content
    );

    let denied = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("get")),
            ("doc_id", uintv(1)),
        ]),
        Some(&([0x33; 16], REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(denied[0], protocol::RES_DISALLOWED);

    let invalid = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("set")),
            ("doc_id", uintv(1)),
            ("content", strv("interact = not-a-hex-identity\n")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(invalid[0], protocol::RES_INVALID_REQ);
    assert_eq!(
        std::fs::read_to_string(work_path.join("1.allowed")).unwrap(),
        content
    );

    let missing = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("get")),
            ("doc_id", uintv(99)),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(missing[0], protocol::RES_NOT_FOUND);
}

#[test]
fn work_document_admin_can_get_and_set_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    config.allow_interact = vec!["none".into()];
    let repo_path = config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let work_path = crate::work::work_sidecar_path(&repo_path);
    crate::work::create_document(
        &work_path,
        crate::work::WorkInput {
            title: "Task".into(),
            content: "Body".into(),
            format: "markdown".into(),
            signature: None,
            identity: None,
            author: REMOTE,
        },
    )
    .unwrap();
    std::fs::write(
        work_path.join("1.allowed"),
        format!("admin = {}\n", crate::util::hex(&OTHER_REMOTE)),
    )
    .unwrap();
    let access = make_access(&config);

    let get = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("get")),
            ("doc_id", uintv(1)),
        ]),
        Some(&(OTHER_REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(get[0], protocol::RES_OK);

    let set = handle_work(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("perms")),
            ("step", strv("set")),
            ("doc_id", uintv(1)),
            ("content", strv("interact = all\n")),
        ]),
        Some(&(OTHER_REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(set, vec![protocol::RES_OK]);
    assert_eq!(
        std::fs::read_to_string(work_path.join("1.allowed")).unwrap(),
        "interact = all\n"
    );
}

#[test]
#[cfg(unix)]
fn permissions_updates_preserve_executable_resolvers() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    for relative in ["group.allowed", "group/repo.allowed"] {
        let path = config.repositories_dir.join(relative);
        let original = "#!/bin/sh\necho 'read = all'\n";
        std::fs::write(&path, original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let response = handle_permissions_step(
            &config,
            &[
                (strv("step"), strv("set")),
                (strv("content"), strv("read = none\n")),
            ],
            &path,
        )
        .unwrap();
        assert_eq!(response[0], protocol::RES_DISALLOWED);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[test]
fn permissions_updates_are_visible_without_rebuilding_access() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_write = vec!["none".into()];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    let access = make_access(&config);
    for relative in ["group.allowed", "group/repo.allowed"] {
        let path = config.repositories_dir.join(relative);
        for (content, allowed) in [("write = all\n", true), ("write = none\n", false)] {
            let response = handle_permissions_step(
                &config,
                &[
                    (strv("step"), strv("set")),
                    (strv("content"), strv(content)),
                ],
                &path,
            )
            .unwrap();
            assert_eq!(response, vec![protocol::RES_OK]);
            assert_eq!(
                access
                    .allows(Operation::Write, "group/repo", Some(&REMOTE))
                    .unwrap(),
                allowed
            );
        }
    }
}

#[test]
fn repository_permissions_get_set_and_validate_allowed_file() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_admin = vec![crate::util::hex(&REMOTE)];
    let repo_path = config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let access = make_access(&config);

    let get = handle_perms(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("rperms")),
            ("step", strv("get")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(
        body_value(&get).map_get("content").and_then(Value::as_str),
        Some("")
    );

    let set = handle_perms(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("rperms")),
            ("step", strv("set")),
            (
                "content",
                strv(
                    "write = all
",
                ),
            ),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(set, vec![protocol::RES_OK]);
    assert_eq!(
        std::fs::read_to_string(config.repositories_dir.join("group/repo.allowed")).unwrap(),
        "write = all
"
    );

    let invalid = handle_perms(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("rperms")),
            ("step", strv("set")),
            (
                "content",
                strv(
                    "write = not-a-hex-identity
",
                ),
            ),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(invalid[0], protocol::RES_INVALID_REQ);
    assert_eq!(
        std::fs::read_to_string(config.repositories_dir.join("group/repo.allowed")).unwrap(),
        "write = all
"
    );
}

#[test]
fn group_permissions_write_group_sidecar_allowed_file() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_admin = vec![crate::util::hex(&REMOTE)];
    std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
    let access = make_access(&config);

    let request = msgpack::pack(&Value::Map(vec![
        (Value::UInt(protocol::IDX_GROUP), strv("group")),
        (Value::Str("operation".into()), strv("gperms")),
        (Value::Str("step".into()), strv("set")),
        (
            Value::Str("content".into()),
            strv(
                "create = all
",
            ),
        ),
    ]));
    let set = handle_perms(&config, &access, &request, Some(&(REMOTE, REMOTE_SIG))).unwrap();
    assert_eq!(set, vec![protocol::RES_OK]);
    assert_eq!(
        std::fs::read_to_string(config.repositories_dir.join("group.allowed")).unwrap(),
        "create = all
"
    );
}

#[test]
fn permissions_management_requires_admin_access() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = config.repositories_dir.join("group/repo");
    git::ensure_bare_repository(&repo_path).unwrap();
    let access = make_access(&config);

    let denied = handle_perms(
        &config,
        &access,
        &work_request(&[
            ("repository", strv("group/repo")),
            ("operation", strv("rperms")),
            ("step", strv("get")),
        ]),
        Some(&(REMOTE, REMOTE_SIG)),
    )
    .unwrap();
    assert_eq!(denied[0], protocol::RES_DISALLOWED);
}

fn make_access(config: &ServerConfig) -> Access {
    Access::new_with_aliases(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
        config.identity_aliases.clone(),
    )
    .unwrap()
    .with_propose(&config.allow_propose)
    .unwrap()
}

fn create_corrupt_bare_repo(path: &std::path::Path) {
    std::fs::create_dir_all(path.join("objects")).unwrap();
    std::fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
}

fn create_source_repo(root: &std::path::Path) -> std::path::PathBuf {
    create_source_repo_on_branch(root, "master")
}

fn create_source_repo_on_branch(root: &std::path::Path, branch: &str) -> std::path::PathBuf {
    let source = root.join(format!("source-{branch}"));
    std::fs::create_dir_all(&source).unwrap();
    run_git(&source, &["init", "-b", branch]);
    std::fs::write(source.join("README.md"), "source\n").unwrap();
    run_git(&source, &["add", "README.md"]);
    run_git(
        &source,
        &[
            "-c",
            "user.name=rngit test",
            "-c",
            "user.email=rngit@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
    );
    source
}

fn commit_source_file(repo: &std::path::Path, file: &str, content: &str) -> String {
    std::fs::write(repo.join(file), content).unwrap();
    run_git(repo, &["add", file]);
    run_git(
        repo,
        &[
            "-c",
            "user.name=rngit test",
            "-c",
            "user.email=rngit@example.invalid",
            "commit",
            "-m",
            file,
        ],
    );
    git_rev_parse(repo, "HEAD")
}

fn git_symbolic_ref(repo: &std::path::Path, name: &str) -> String {
    let output = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .arg("symbolic-ref")
        .arg(name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git symbolic-ref failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn git_rev_parse(repo: &std::path::Path, rev: &str) -> String {
    let output = if repo.join(".git").is_dir() {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("rev-parse")
            .arg(rev)
            .output()
            .unwrap()
    } else {
        std::process::Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("rev-parse")
            .arg(rev)
            .output()
            .unwrap()
    };
    assert!(
        output.status.success(),
        "git rev-parse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn git_config(repo: &std::path::Path, key: &str) -> String {
    let output = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .arg("config")
        .arg("--get")
        .arg(key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn run_git(cwd: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_generic_remote_error(response: &[u8]) {
    assert_eq!(response[0], protocol::RES_REMOTE_FAIL);
    assert_eq!(&response[1..], b"Remote error");
}

fn work_request(fields: &[(&str, Value)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(key, value)| {
                let key = if *key == "repository" {
                    Value::UInt(protocol::IDX_REPOSITORY)
                } else {
                    Value::Str((*key).into())
                };
                (key, value.clone())
            })
            .collect(),
    ))
}

fn strv(value: &str) -> Value {
    Value::Str(value.to_string())
}

fn uintv(value: u64) -> Value {
    Value::UInt(value)
}

fn binv(value: &[u8]) -> Value {
    Value::Bin(value.to_vec())
}

fn body_value(response: &[u8]) -> Value {
    assert_eq!(response[0], protocol::RES_OK);
    msgpack::unpack_exact(&response[1..]).unwrap()
}
