use super::*;
use crate::acl::Access;
use crate::config::ServerConfig;

#[test]
fn media_preserves_original_for_disabled_webp_nonimage_and_failed_conversion() {
    for (enabled, name) in [
        (false, "test.png"),
        (true, "test.WEBP"),
        (true, "test.txt"),
        (true, "bad.png"),
    ] {
        let original = b"not an image".to_vec();
        let (bytes, response_name) = media_response_data(enabled, name, name, original.clone());
        assert_eq!(bytes, original);
        assert_eq!(response_name, name);
    }
}

#[test]
fn media_serves_decoded_blob_with_filename_and_checks_access() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    let payload = b"RIFF\0image bytes";
    create_repo_bytes(
        config.repositories_dir.join("public/images"),
        "docs/a + b.webp",
        payload,
    );
    let request = msgpack::pack(&Value::Map(vec![
        (Value::Str("key".into()), Value::Bin(vec![1, 2, 3])),
        (
            Value::Str("path".into()),
            Value::Str("/media/public/images/HEAD/docs%2Fa+%2B+b.webp".into()),
        ),
    ]));
    match serve_media(&config, &access(&config), &request, None).unwrap() {
        RequestResponse::File {
            data,
            metadata,
            auto_compress,
        } => {
            assert!(!auto_compress, "media responses must not auto-compress");
            assert_eq!(data, payload);
            assert_eq!(
                msgpack::unpack_exact(&metadata).unwrap(),
                Value::Map(vec![(
                    Value::Str("name".into()),
                    Value::Bin(b"a + b.webp".to_vec())
                ),])
            );
        }
        _ => panic!("expected media resource"),
    }
    config.allow_read = vec!["none".into()];
    assert!(
        matches!(serve_media(&config, &access(&config), &request, None).unwrap(), RequestResponse::Bytes(data) if data == msgpack::pack(&Value::Bool(false)))
    );
}

#[test]
fn media_rejects_missing_key_bad_paths_and_unknown_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo_bytes(
        config.repositories_dir.join("public/images"),
        "image.webp",
        b"RIFF\0data",
    );
    let access = access(&config);
    let mut requests = vec![
        page_request(&[("path", "/media/public/images/HEAD/image.webp")]),
        msgpack::pack(&Value::Bool(true)),
    ];
    for path in [
        "/media/public/images",
        "/media/public/images/HEAD/../secret",
        "/media/public/images/missing/image.webp",
        "/media/public/images/HEAD/missing.webp",
        "/media/../images/HEAD/image.webp",
    ] {
        requests.push(page_request(&[("key", "k"), ("path", path)]));
    }
    for request in requests {
        assert!(
            matches!(serve_media(&config, &access, &request, None).unwrap(), RequestResponse::Bytes(data) if data == msgpack::pack(&Value::Bool(false)))
        );
    }
}

#[test]
fn binary_image_blob_renders_micron_media_reference() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo_bytes(
        config.repositories_dir.join("public/images"),
        "docs/a + b.PNG",
        &vec![0; 256 * 1024 + 1],
    );
    let page = render_page(
        PATH_BLOB,
        &config,
        &access(&config),
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "images"),
            ("var_path", "docs/a + b.PNG"),
        ]),
        None,
    )
    .unwrap();
    assert!(page.contains("`(Image file`w=n`a=c`:/media/public/images/HEAD/docs%2Fa+%2B+b.PNG)"));
    assert!(!page.contains("Binary file is not displayed"));
}

#[test]
fn blob_path_normalization_removes_only_the_explicit_relative_prefix() {
    assert_eq!(normalize_blob_path("./docs/guide.md"), "docs/guide.md");
    assert_eq!(normalize_blob_path("docs/./guide.md"), "docs/guide.md");
    assert_eq!(normalize_blob_path(".hidden/config"), ".hidden/config");
    assert_eq!(normalize_blob_path(".../guide.md"), ".../guide.md");
    assert_eq!(normalize_blob_path("/absolute.md"), "/absolute.md");
    assert!(validate_git_path(&normalize_blob_path("/absolute.md")).is_err());
}
use crate::logging;
use rns_core::msgpack::{self, Value};
use rns_crypto::OsRng;
use std::fs;
use std::process::Command;

#[test]
fn nomadnet_destination_uses_upstream_name() {
    let identity = Identity::new(&mut OsRng);
    let destination = destination_for_identity(&identity);
    let expected =
        Destination::single_in("nomadnetwork", &["node"], IdentityHash(*identity.hash()));
    assert_eq!(destination.hash, expected.hash);
}

#[test]
fn chart_renders_positive_values_on_bottom_row() {
    let labels = ["start".to_string(), "end".to_string()];
    let chart = render_chart(&[1, 100], &labels, "57c", None, 1.3, 10);
    let bottom_row = chart.lines().nth(10).unwrap();

    assert!(bottom_row.starts_with("│`FT"));
    assert!(bottom_row.contains('▄'));
}

#[test]
fn git_command_timeout_kills_slow_process() {
    let start = Instant::now();

    let err =
        run_git_output(Command::new("sleep").arg("5"), Duration::from_millis(30)).unwrap_err();

    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(err.to_string().contains("timed out"));
}

#[test]
fn commit_message_formatter_escapes_leading_dash_lines() {
    let formatted = format_commit_message("subject\n- rendered literally\npath\\with`tick`");

    assert_eq!(
        formatted,
        "subject\n\\- rendered literally\npath\\\\with\\`tick\\`"
    );
}

#[test]
fn front_page_lists_only_readable_groups() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.allow_read = vec!["none".into()];
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "alpha readme\n",
    );
    create_repo(
        config.repositories_dir.join("private/secret"),
        "README.md",
        "secret\n",
    );
    fs::write(
        config.repositories_dir.join("public/group.allowed"),
        "read = all\n",
    )
    .unwrap();
    fs::write(
        config.repositories_dir.join("private/group.allowed"),
        "read = none\n",
    )
    .unwrap();
    let access = access(&config);

    let page = render_page(PATH_INDEX, &config, &access, &page_request(&[]), None).unwrap();
    assert!(page.contains("public"));
    assert!(page.contains("alpha"));
    assert!(!page.contains("private"));
    assert!(!page.contains("secret"));
}

#[test]
fn group_and_repo_pages_use_repository_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    fs::write(repo.join("description"), "Alpha repository\n").unwrap();
    let access = access(&config);

    let group = render_page(
        PATH_GROUP,
        &config,
        &access,
        &page_request(&[("var_g", "public")]),
        None,
    )
    .unwrap();
    assert!(group.contains("Alpha repository"));
    assert!(group.contains("alpha"));

    let repo = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(repo.contains("rns://"));
    assert!(repo.contains("Alpha repository"));
    assert!(repo.contains(">Alpha"));
}

#[test]
fn repo_page_renders_fork_and_mirror_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let fork = create_repo(
        config.repositories_dir.join("public/forked"),
        "README.md",
        "# Forked\n",
    );
    let mirror = create_repo(
        config.repositories_dir.join("public/mirrored"),
        "README.md",
        "# Mirrored\n",
    );
    run_git(Command::new("git").arg("--git-dir").arg(&fork).args([
        "config",
        "repository.rngit.type",
        "fork",
    ]));
    run_git(Command::new("git").arg("--git-dir").arg(&fork).args([
        "config",
        "repository.rngit.upstream.source",
        "rns://00112233445566778899aabbccddeeff/source/repo",
    ]));
    run_git(Command::new("git").arg("--git-dir").arg(&fork).args([
        "config",
        "repository.rngit.upstream.sync",
        "1",
    ]));
    run_git(Command::new("git").arg("--git-dir").arg(&mirror).args([
        "config",
        "repository.rngit.type",
        "mirror",
    ]));
    run_git(Command::new("git").arg("--git-dir").arg(&mirror).args([
        "config",
        "repository.rngit.upstream.source",
        "https://example.invalid/upstream.git",
    ]));
    run_git(Command::new("git").arg("--git-dir").arg(&mirror).args([
        "config",
        "repository.rngit.upstream.sync",
        "1",
    ]));
    let access = access(&config);

    let fork_page = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "forked")]),
        None,
    )
    .unwrap();
    assert!(fork_page.contains("Forked from"));
    assert!(fork_page.contains("rns://00112233445566778899aabbccddeeff/source/repo"));
    assert!(fork_page.contains("synced"));
    assert!(fork_page.contains("ago"));

    let mirror_page = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "mirrored")]),
        None,
    )
    .unwrap();
    assert!(mirror_page.contains("Mirrored from"));
    assert!(mirror_page.contains("https://example.invalid/upstream.git"));
    assert!(mirror_page.contains("synced"));
    assert!(mirror_page.contains("ago"));
}

#[test]
fn tree_blob_commits_commit_and_refs_pages_are_git_backed() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo = create_repo(
        config.repositories_dir.join("public/alpha"),
        "src/lib.rs",
        "pub fn answer() -> u8 { 42 }\n",
    );
    run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo)
            .args(["tag", "v1", "refs/heads/main"]),
    );
    let access = access(&config);

    let tree = render_page(
        PATH_TREE,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(tree.contains("src/"));

    let blob = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_path", "src/lib.rs"),
        ]),
        None,
    )
    .unwrap();
    assert!(blob.contains("answer"));
    assert!(blob.contains("pub fn answer()"));

    let commits = render_page(
        PATH_COMMITS,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(commits.contains("initial"));

    let commit_hash = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo)
            .args(["rev-parse", "refs/heads/main"]),
    );
    run_git(Command::new("git").arg("--git-dir").arg(&repo).args([
        "update-ref",
        "refs/heads/feature",
        commit_hash.trim(),
    ]));
    let branch_commits = render_page(
        PATH_COMMITS,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_ref", "feature"),
        ]),
        None,
    )
    .unwrap();
    assert!(branch_commits.contains("|ref=feature|h="));
    let commit = render_page(
        PATH_COMMIT,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_ref", "feature"),
            ("var_h", commit_hash.trim()),
        ]),
        None,
    )
    .unwrap();
    assert!(commit.contains("initial"));
    assert!(commit.contains("src/lib.rs"));
    assert!(commit.contains("/page/commits.mu`g=public|r=alpha|ref=feature"));
    assert!(!commit.contains("Signature:"));

    let refs = render_page(
        PATH_REFS,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(refs.contains("main"));
    assert!(refs.contains("v1"));
}

#[test]
fn commit_page_shows_valid_reticulum_signature_status() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo = create_repo(
        config.repositories_dir.join("public/alpha"),
        "src/lib.rs",
        "pub fn answer() -> u8 { 42 }\n",
    );
    let access = access(&config);
    let tree = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo)
            .args(["rev-parse", "refs/heads/main^{tree}"]),
    );
    let identity = Identity::new(&mut OsRng);
    let author = crate::util::hex(identity.hash());
    let signed_content = format!(
            "tree {}\nauthor RNS Page Test <{}> 0 +0000\ncommitter RNS Page Test <{}> 0 +0000\n\nsigned commit\n",
            tree.trim(),
            author,
            author
        );
    let armored = crate::commitsigs::sign_message(&identity, signed_content.as_bytes()).unwrap();
    let (headers, rest) = signed_content.split_once("\n\n").unwrap();
    let mut raw_commit = format!("{headers}\n");
    let mut sig_lines = armored.lines();
    raw_commit.push_str("gpgsig ");
    raw_commit.push_str(sig_lines.next().unwrap());
    raw_commit.push('\n');
    for line in sig_lines {
        raw_commit.push(' ');
        raw_commit.push_str(line);
        raw_commit.push('\n');
    }
    raw_commit.push('\n');
    raw_commit.push_str(rest);
    let commit_file = tmp.path().join("signed-commit");
    fs::write(&commit_file, raw_commit).unwrap();
    let commit_hash = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo)
            .args(["hash-object", "-t", "commit", "-w"])
            .arg(&commit_file),
    );
    run_git(Command::new("git").arg("--git-dir").arg(&repo).args([
        "update-ref",
        "refs/heads/main",
        commit_hash.trim(),
    ]));

    let page = render_page(
        PATH_COMMIT,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_h", commit_hash.trim()),
        ]),
        None,
    )
    .unwrap();

    assert!(page.contains("signed commit"));
    assert!(page.contains("Signature: Valid, signed by author"));
}

#[test]
fn blob_page_renders_tree_when_path_is_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "src/lib.rs",
        "pub fn answer() -> u8 { 42 }\n",
    );
    let access = access(&config);

    let page = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha"), ("var_path", "src")]),
        None,
    )
    .unwrap();

    assert!(page.contains("files / src"));
    assert!(page.contains("lib.rs"));
    assert!(page.contains(PATH_BLOB));
    assert!(!page.contains("Displaying Raw"));
}

#[test]
fn page_requests_reject_invalid_repository_names() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = access(&config);
    let err = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", ".."), ("var_r", "repo")]),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid repository name"));
}

#[test]
fn page_ref_resolution_rejects_invalid_refs_before_git_lookup() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    for (path, vars) in [
        (
            PATH_TREE,
            vec![
                ("var_g", "public"),
                ("var_r", "alpha"),
                ("var_ref", "--upload-pack=/tmp/x"),
            ],
        ),
        (
            PATH_BLOB,
            vec![
                ("var_g", "public"),
                ("var_r", "alpha"),
                ("var_path", "README.md"),
                ("var_ref", "refs/heads/main:README.md"),
            ],
        ),
        (
            PATH_COMMITS,
            vec![
                ("var_g", "public"),
                ("var_r", "alpha"),
                ("var_ref", "refs/heads/main..refs/heads/other"),
            ],
        ),
    ] {
        let err = render_page(path, &config, &access, &page_request(&vars), None).unwrap_err();
        assert_eq!(err.to_string(), "invalid git ref");
    }
}

#[test]
fn pages_use_base_template_breadcrumbs_and_micron_links() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    let repo = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();

    assert!(repo.starts_with("#!c=0\n>Test Git Node\n\n>>\n"));
    assert!(repo.contains("`!`[Node`:/page/index.mu]`!"));
    assert!(repo.contains("`!`[public`:/page/group.mu`g=public]`!"));
    assert!(repo.contains("`[Files`:/page/tree.mu`g=public|r=alpha|ref=HEAD]"));
    assert!(repo.contains("`[Commits"));
    assert!(repo.contains("`[Branches (1)`:/page/refs.mu`g=public|r=alpha|type=heads]"));
    assert!(repo.contains("`[Tags (0)`:/page/refs.mu`g=public|r=alpha|type=tags]"));
    assert!(repo.contains("<\n-\n`a`F666`[Served by rngit`:/page/index.mu]"));
}

#[test]
fn custom_templates_wrap_page_content_and_replace_variables() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    fs::create_dir_all(&config.templates_dir).unwrap();
    fs::write(
        config.templates_dir.join("base.mu"),
        "BASE {NODE_NAME} {VERSION} {GEN_TIME}\n{PAGE_CONTENT}\n{NAVIGATION}   \n",
    )
    .unwrap();
    fs::write(
        config.templates_dir.join("repo.mu"),
        "REPO-BEGIN\n{PAGE_CONTENT}\nREPO-END   \n",
    )
    .unwrap();
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    let repo = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();

    assert!(repo.starts_with("BASE Test Git Node "));
    assert!(repo.contains("\nREPO-BEGIN\n"));
    assert!(repo.contains(">Alpha"));
    assert!(repo.contains("\nREPO-END\n"));
    assert!(repo.contains(env!("CARGO_PKG_VERSION")));
    assert!(repo.contains("0ms"));
    assert!(!repo.ends_with("   \n"));
}

#[test]
fn blocked_unidentified_requests_use_no_ident_page_for_every_page_path() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.blocked_identities.push(NULL_IDENTITY_HASH);
    let access = access(&config);

    for path in PAGE_PATHS {
        let page = render_page(path, &config, &access, &page_request(&[]), None).unwrap();
        assert!(
            page.contains(
                ">>No Identity\n\nThis page requires identification, and none was received."
            ),
            "{path} did not render the no-ident page: {page}"
        );
    }
}

#[test]
fn no_ident_page_requires_both_missing_identity_and_blocked_null_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    let access = access(&config);

    let allowed_unidentified =
        render_page(PATH_INDEX, &config, &access, &page_request(&[]), None).unwrap();
    assert!(!allowed_unidentified.contains(">>No Identity"));

    config.blocked_identities.push(NULL_IDENTITY_HASH);
    let identified = [0x42; 16];
    let allowed_identified = render_page(
        PATH_INDEX,
        &config,
        &access,
        &page_request(&[]),
        Some(&identified),
    )
    .unwrap();
    assert!(!allowed_identified.contains(">>No Identity"));
}

#[test]
fn custom_no_ident_template_overrides_the_default() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.blocked_identities.push(NULL_IDENTITY_HASH);
    fs::create_dir_all(&config.templates_dir).unwrap();
    fs::write(
        config.templates_dir.join("no_ident.mu"),
        ">>Identify First\n\nCustom unidentified response for {NODE_NAME}.\n",
    )
    .unwrap();
    let access = access(&config);

    let page = render_page(PATH_INDEX, &config, &access, &page_request(&[]), None).unwrap();

    assert!(page.contains(">>Identify First"));
    assert!(page.contains("Custom unidentified response for Test Git Node."));
    assert!(!page.contains(">>No Identity"));
}

#[test]
fn template_substitution_does_not_rewrite_page_content_placeholders() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());

    let out = apply_template(
        "Template {NODE_NAME}\n{PAGE_CONTENT}",
        "Literal {NODE_NAME}",
        &config,
    );

    assert!(out.starts_with("Template Test Git Node\n"));
    assert!(out.ends_with("Literal {NODE_NAME}"));
}

#[test]
fn unicode_icon_config_changes_repository_navigation_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.unicode_icons = true;
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    let repo = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();

    assert!(repo.contains("🗀 Files"));
    assert!(repo.contains("🖹 Commits"));
    assert!(repo.contains("⑃ Branches"));
    assert!(repo.contains("⌆ Tags"));
}

#[test]
fn repo_page_renders_and_persists_thanks_count() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    let first = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(first.contains("Thanks (0)"));
    assert!(!repo_path.with_extension("thanks").exists());

    let thanked = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha"), ("var_thanks", "y")]),
        None,
    )
    .unwrap();
    assert!(thanked.contains("Thanks (1)"));
    assert_eq!(
        fs::read_to_string(repo_path.with_extension("thanks")).unwrap(),
        "1\n"
    );

    let incremented = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha"), ("var_thanks", "y")]),
        None,
    )
    .unwrap();
    assert!(incremented.contains("Thanks (2)"));

    let viewed = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(viewed.contains("Thanks (2)"));
}

#[test]
fn repo_page_uses_unicode_heart_for_thanks_when_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    config.unicode_icons = true;
    create_repo(
        config.repositories_dir.join("public/alpha"),
        "README.md",
        "# Alpha\n",
    );
    let access = access(&config);

    let page = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();

    assert!(page.contains("♥ Thanks (0)"));
    assert!(page.contains("thanks=y"));
}

#[test]
fn empty_page_request_data_is_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let access = access(&config);

    let index = render_page(PATH_INDEX, &config, &access, &[], None).unwrap();
    assert!(index.contains(">Groups"));

    let err = render_page(PATH_REPO, &config, &access, &[], None).unwrap_err();
    assert!(err.to_string().contains("missing page variable g"));
}

#[test]
fn tree_blob_and_commit_pages_escape_content_and_format_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo = create_repo(
        config.repositories_dir.join("public/alpha"),
        "src/lib.rs",
        "pub fn `answer`() -> u8 { 42 }\n",
    );
    let access = access(&config);

    let tree = render_page(
        PATH_TREE,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "alpha")]),
        None,
    )
    .unwrap();
    assert!(tree.contains("`[src/`:/page/tree.mu`g=public|r=alpha|ref=HEAD|path=src]"));

    let blob = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_path", "src/lib.rs"),
        ]),
        None,
    )
    .unwrap();
    assert!(blob.contains("Text, "));
    assert!(!blob.contains("View raw"));
    assert!(blob.contains("answer"));
    assert!(blob.contains("\\`"));

    let silly_blob = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_path", "./src/./lib.rs"),
        ]),
        None,
    )
    .unwrap();
    assert!(silly_blob.contains(">src/lib.rs `F666"));
    assert!(silly_blob.contains("answer"));

    let commit_hash = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repo)
            .args(["rev-parse", "refs/heads/main"]),
    );
    let commit = render_page(
        PATH_COMMIT,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "alpha"),
            ("var_h", commit_hash.trim()),
        ]),
        None,
    )
    .unwrap();
    assert!(commit.contains("Author: RNS Page Test"));
    assert!(commit.contains("Files changed"));
    assert!(commit.contains("A src/lib.rs"));
}

#[test]
fn markdown_converter_handles_links_code_lists_rules_and_tables() {
    let input = "# Title\n\
\n\
See [the docs](https://example.invalid/a_b) and `literal *code*`.\n\
\n\
- **bold** and *italic*\n\
---\n\
| Name | Link |\n\
| --- | --- |\n\
| Row | [go](rns://abc) |\n";

    let out = markdown_to_micron(input);
    assert!(out.contains(">Title"));
    assert!(out.contains("`_`!`[the docs`https://example.invalid/a_b]`!`_"));
    assert!(out.contains("`BT383838`Fdddliteral *code*`f`b"));
    assert!(out.contains(" • `!bold`! and `*italic`*"));
    assert!(out.contains("\n-\n"));
    assert!(out.contains("│ Name"));
    assert!(out.contains("`_`!`[go`rns://abc]`!`_"));
}

#[test]
fn markdown_converter_handles_blockquotes_and_heading_inline_markup() {
    let out = markdown_to_micron(
        "# **Important**\n\
> **Quoted** text\n\
> with [link](rns://abc)\n\
\n\
after\n",
    );
    assert!(out.contains(">`!Important`!"));
    assert!(out.contains(" │ `!Quoted`! text with `_`!`[link`rns://abc]`!`_"));
    assert!(out.contains("\nafter\n"));
}

#[test]
fn markdown_link_conversion_is_isolated_from_later_substitutions() {
    let out = markdown_to_micron("[**bold** `code`](https://example.invalid?q=*x*)");
    assert!(out.contains("`_`!`[**bold** code`https://example.invalid?q=*x*]`!`_"));
    assert!(!out.contains("`!`!"));
    assert!(!out.contains("`*x`*"));
}

#[test]
fn markdown_link_style_can_disable_wrappers_and_apply_color() {
    let plain = format_markdown_link(
        "label",
        "rns://abc",
        None,
        MarkdownLinkStyle {
            bold: false,
            underline: false,
            color: None,
        },
    );
    assert_eq!(plain, "`[label`rns://abc]");

    let short_color = format_markdown_link(
        "label",
        "rns://abc",
        None,
        MarkdownLinkStyle {
            bold: true,
            underline: false,
            color: Some("abc"),
        },
    );
    assert_eq!(short_color, "`Fabc`!`[label`rns://abc]`!`f");

    let true_color = format_markdown_link(
        "label",
        "rns://abc",
        None,
        MarkdownLinkStyle {
            bold: false,
            underline: true,
            color: Some("aabbcc"),
        },
    );
    assert_eq!(true_color, "`FTaabbcc`_`[label`rns://abc]`_`f");
}

#[test]
fn markdown_inline_code_that_looks_like_link_does_not_hide_real_links() {
    let out = markdown_to_micron(
        "`[literal](https://example.invalid/no)` and [real](https://example.invalid/yes)",
    );

    assert!(out.contains("`BT383838`Fddd[literal](https://example.invalid/no)`f`b"));
    assert!(out.contains("`_`!`[real`https://example.invalid/yes]`!`_"));
    assert!(!out.contains("`_`!`[literal`https://example.invalid/no]`!`_"));
}

#[test]
fn markdown_tables_handle_empty_cells_escaped_pipes_alignment_and_visible_width() {
    let input = "| Name | Status | Notes |\n\
| :--- | ---: | :---: |\n\
| `code` | **ok** | a\\|b |\n\
| empty | | [go](rns://abc) |\n";

    let out = markdown_to_micron(input);
    assert!(out.contains("┌"));
    assert!(out.contains("├"));
    assert!(out.contains("└"));
    assert!(out.contains("│ Name"));
    assert!(out.contains("`BT383838`Fdddcode`f`b"));
    assert!(out.contains("`!ok`!"));
    assert!(out.contains("a|b"));
    assert!(out.contains("empty"));
    assert!(out.contains("`_`!`[go`rns://abc]`!`_"));
    assert!(!out.contains("a\\|b"));
}

#[test]
fn markdown_table_width_ignores_generated_micron_tags() {
    let input = "| A | B |\n\
| --- | --- |\n\
| [x](rns://abc) | `y` |\n";

    let out = markdown_to_micron(input);
    assert!(out.contains("│ `_`!`[x`rns://abc]`!`_ "));
    assert!(out.contains("│ `BT383838`Fdddy`f`b "));
    assert!(out.contains("┌─────┬─────┐"));
}

#[test]
fn markdown_escaping_does_not_create_or_corrupt_micron_tags() {
    let out = markdown_to_micron("literal `!not bold`! and [bad`label](rns://abc`def) plus `raw`");
    assert!(out.contains("literal \\`!not bold\\`!"));
    assert!(out.contains("`_`!`[badlabel`rns://abcdef]`!`_"));
    assert!(out.contains("`BT383838`Fdddraw`f`b"));
    assert!(!out.contains("`!not bold`!"));
}

#[test]
fn markdown_escapes_backslashes_and_expands_tabs_before_inline_formatting() {
    let out = markdown_to_micron("plain\\path\t**bold\\path** and `code\\path`\n");

    assert!(out.contains("plain\\\\path   `!bold\\\\path`!"));
    assert!(out.contains("`BT383838`Fdddcode\\\\path`f`b"));
}

#[test]
fn markdown_plain_lines_escape_micron_line_start_controls() {
    let out = markdown_to_micron("-not a list\n<not alignment\n- list item\n---\n");
    assert!(out.contains("\\-not a list\n"));
    assert!(out.contains("\\<not alignment\n"));
    assert!(out.contains(" • list item\n"));
    assert!(out.contains("-\n"));
}

#[test]
fn markdown_converter_keeps_code_blocks_and_unmatched_markers_literal() {
    let out = markdown_to_micron(
        "```rust\n\
**not bold** and `not inline`\n\
```\n\
Unmatched * marker\n\
1. numbered\n",
    );
    assert!(out.contains("not bold"));
    assert!(out.contains("\\`not inline\\`"));
    assert!(out.contains("`=\n**not bold** and \\`not inline\\`\n`=\n"));
    assert!(!out.contains("`!not bold`!"));
    assert!(out.contains("Unmatched * marker"));
    assert!(out.contains("1. numbered"));
}

#[test]
fn rawmu_fenced_blocks_pass_through_without_escaping() {
    let markdown = markdown_to_micron(
        "```rawmu
`!raw micron`!
>Heading
```
",
    );

    assert!(markdown.contains(
        "`!raw micron`!
>Heading
"
    ));
    assert!(!markdown.contains(r"\`!raw micron"));
    assert!(!markdown.contains(
        "`=
"
    ));
}

#[test]
fn unknown_extension_and_fence_language_fall_back_to_plain_literals() {
    let blob = crate::highlight::literal_block("value `tick`\n", Some("blob.unknown"), None);
    assert!(!blob.contains("`FT"));
    assert!(blob.contains("value \\`tick\\`"));

    let markdown = markdown_to_micron("```not-a-language\nvalue `tick`\n```\n");
    assert!(!markdown.contains("`FT"));
    assert!(markdown.contains("value \\`tick\\`"));
}

#[test]
fn binary_and_oversized_blobs_use_plain_fallback_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo_bytes(
        config.repositories_dir.join("public/binary"),
        "payload.bin",
        b"abc\0def",
    );
    let large = vec![b'x'; 256 * 1024 + 1];
    create_repo_bytes(
        config.repositories_dir.join("public/large"),
        "payload.rs",
        &large,
    );
    let access = access(&config);

    let binary = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "binary"),
            ("var_path", "payload.bin"),
        ]),
        None,
    )
    .unwrap();
    assert!(binary.contains("Binary"));
    assert!(binary.contains("Binary file is not displayed."));
    assert!(!binary.contains("`FT"));

    let oversized = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "large"),
            ("var_path", "payload.rs"),
        ]),
        None,
    )
    .unwrap();
    assert!(oversized.contains("File is too large to display"));
    assert!(!oversized.contains("`FT"));
}

#[test]
fn markdown_blob_defaults_to_rendered_view_and_raw_view_escapes_source() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/docs"),
        "docs/readme.md",
        "# Title\n\nSee [docs](https://example.invalid), [guide](guide.md#intro) and `tick`.\n",
    );
    let access = access(&config);

    let rendered = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
        ]),
        None,
    )
    .unwrap();
    assert!(rendered.contains("Displaying Rendered"));
    assert!(rendered.contains("View raw"));
    assert!(rendered.contains(">Title"));
    assert!(rendered.contains("`_`!`[docs`https://example.invalid]`!`_"));
    assert!(rendered.contains(
        "`_`!`[guide`:/page/blob.mu`g=public|r=docs|ref=HEAD|path=docs/guide.md|anchor=intro]`!`_"
    ));
    assert!(rendered.contains("`BT383838`Fdddtick`f`b"));
    assert!(!rendered.contains("# Title"));

    let raw = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
            ("var_raw", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(raw.contains("Displaying Raw"));
    assert!(raw.contains("View rendered"));
    assert!(raw.contains("Title"));
    assert!(raw.contains("\\`"));
    assert!(raw.contains("tick"));
    assert!(!raw.contains("`_`!`[docs`https://example.invalid]`!`_"));
}

#[test]
fn micron_blob_defaults_to_rendered_passthrough_and_raw_view_is_literal() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/micron"),
        "README.mu",
        ">Micron\n\n`!Already formatted`!\n",
    );
    let access = access(&config);

    let rendered = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "micron"),
            ("var_path", "README.mu"),
        ]),
        None,
    )
    .unwrap();
    assert!(rendered.contains("Displaying Rendered"));
    assert!(rendered.contains(">Micron"));
    assert!(rendered.contains("`!Already formatted`!"));
    assert!(!rendered.contains("\\`!Already formatted\\`!"));

    let raw = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "micron"),
            ("var_path", "README.mu"),
            ("var_raw", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(raw.contains("Displaying Raw"));
    assert!(raw.contains("\\`!Already formatted\\`!"));
}

#[test]
fn explicit_render_parameter_renders_markdown_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/docs"),
        "docs/readme.md",
        "# Explicit\n",
    );
    let access = access(&config);

    let rendered = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
            ("var_raw", "y"),
            ("var_render", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(rendered.contains("Displaying Raw"));
    assert!(rendered.contains("#"));
    assert!(rendered.contains("Explicit"));

    let rendered = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
            ("var_render", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(rendered.contains("Displaying Rendered"));
    assert!(rendered.contains(">Explicit"));
    assert!(!rendered.contains("# Explicit"));
}

#[test]
fn markdown_blob_downloads_as_scoped_micron() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/docs"),
        "docs/readme.md",
        "# Guide\n\n[Next](next.md)\n",
    );
    let access = access(&config);
    let page = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
        ]),
        None,
    )
    .unwrap();
    assert!(page.contains("Download"));
    assert!(page.contains("as micron"));
    assert!(page.contains("fmt=mu"));

    let request = page_request(&[
        ("var_g", "public"),
        ("var_r", "docs"),
        ("var_path", "docs/readme.md"),
        ("var_fmt", "mu"),
    ]);
    let response = download_file(&config, &access, &request, None).unwrap();
    let RequestResponse::Resource { data, metadata, .. } = response else {
        panic!("expected converted resource");
    };
    let converted = String::from_utf8(data).unwrap();
    assert!(converted.contains(">Guide"));
    assert!(converted.contains("path=docs/next.md"));
    let metadata = msgpack::unpack_exact(&metadata.unwrap()).unwrap();
    assert_eq!(
        metadata.map_get("name").and_then(Value::as_bin),
        Some(&b"readme.mu"[..])
    );

    let raw = download_file(
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "docs"),
            ("var_path", "docs/readme.md"),
        ]),
        None,
    )
    .unwrap();
    assert_resource_response(raw, b"# Guide\n\n[Next](next.md)\n");
}

#[test]
fn unsupported_blob_extension_ignores_render_parameter_and_uses_raw_literal() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/text"),
        "notes.txt",
        "# Not a heading\npath\\name\t`literal`\n",
    );
    let access = access(&config);

    let page = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "text"),
            ("var_path", "notes.txt"),
            ("var_render", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(!page.contains("Displaying Rendered"));
    assert!(!page.contains("View raw"));
    assert!(page.contains("Displaying Raw"));
    assert!(page.contains("Download"));
    assert!(page.contains("Not a heading"));
    assert!(page.contains("path\\\\name   \\`literal\\`"));
    assert!(page.contains("\\`literal\\`"));
}

#[test]
fn renderable_binary_and_oversized_blobs_do_not_render_content() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo_bytes(
        config.repositories_dir.join("public/binary-md"),
        "payload.md",
        b"# Binary\0payload\n",
    );
    let large = vec![b'#'; 256 * 1024 + 1];
    create_repo_bytes(
        config.repositories_dir.join("public/large-md"),
        "payload.md",
        &large,
    );
    let access = access(&config);

    let binary = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "binary-md"),
            ("var_path", "payload.md"),
        ]),
        None,
    )
    .unwrap();
    assert!(binary.contains("Binary"));
    assert!(binary.contains("Binary file is not displayed."));
    assert!(!binary.contains(">Binary"));

    let oversized = render_page(
        PATH_BLOB,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "large-md"),
            ("var_path", "payload.md"),
            ("var_render", "y"),
        ]),
        None,
    )
    .unwrap();
    assert!(oversized.contains("File is too large to display"));
    assert!(!oversized.contains("Displaying Rendered\n\n>"));
}

#[test]
fn code_blocks_render_plain_literal_blocks() {
    let blob = crate::highlight::literal_block("pub fn main() {}\n", Some("main.rs"), None);
    assert!(!blob.contains("`FT"));
    assert!(blob.contains("pub fn main() {}"));

    let markdown = markdown_to_micron("```rust\npub fn main() {}\n```\n");
    assert!(!markdown.contains("`FT"));
    assert!(markdown.contains("pub fn main() {}"));
}

#[test]
fn repo_page_renders_markdown_readme_and_passes_micron_readme_through() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/markdown"),
        "README.md",
        "# Markdown\n\nSee [docs](https://example.invalid) and [local](docs/intro.md).\n",
    );
    create_repo(
        config.repositories_dir.join("public/micron"),
        "README.mu",
        ">Micron\n\n`!Already formatted`!\n",
    );
    create_repo(
        config.repositories_dir.join("public/microntight"),
        "README.mu",
        ">Micron without trailing newline",
    );
    create_repo(
        config.repositories_dir.join("public/micronblank"),
        "README.mu",
        ">Micron with trailing blanks\n\n\n",
    );
    let access = access(&config);

    let markdown = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "markdown")]),
        None,
    )
    .unwrap();
    assert!(markdown.contains(">Markdown"));
    assert!(markdown.contains("`_`!`[docs`https://example.invalid]`!`_"));
    assert!(markdown.contains(
        "`_`!`[local`:/page/blob.mu`g=public|r=markdown|ref=HEAD|path=docs/intro.md]`!`_"
    ));

    let micron = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "micron")]),
        None,
    )
    .unwrap();
    assert!(micron.contains(">Micron"));
    assert!(micron.contains("`!Already formatted`!"));

    let micron = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "microntight")]),
        None,
    )
    .unwrap();
    assert!(micron.contains(">Micron without trailing newline\n"));
    assert!(!micron.contains(">Micron without trailing newline<"));

    let micron = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "micronblank")]),
        None,
    )
    .unwrap();
    assert!(micron.contains(">Micron with trailing blanks\n"));
    assert!(!micron.contains(">Micron with trailing blanks\n\n\n"));
}

#[test]
fn work_pages_render_documents_comments_and_repo_links() {
    let tmp = tempfile::tempdir().unwrap();
    let config = cfg(tmp.path());
    let repo_path = create_repo(
        config.repositories_dir.join("public/worked"),
        "README.md",
        "# Worked\n",
    );
    let work_path = crate::work::work_sidecar_path(&repo_path);
    let created = crate::work::create_document(
        &work_path,
        crate::work::WorkInput {
            title: "Active task".into(),
            content: "# Active Body\n".into(),
            format: "markdown".into(),
            signature: None,
            identity: None,
            author: [0x11; 16],
        },
    )
    .unwrap();
    crate::work::add_comment(
        &work_path,
        crate::work::WorkScope::Active,
        created.id,
        crate::work::WorkCommentInput {
            content: "Progress update".into(),
            format: "markdown".into(),
            signature: None,
            author: [0x22; 16],
        },
    )
    .unwrap();
    let completed = crate::work::create_document(
        &work_path,
        crate::work::WorkInput {
            title: "Completed task".into(),
            content: "Done".into(),
            format: "micron".into(),
            signature: None,
            identity: None,
            author: [0x11; 16],
        },
    )
    .unwrap();
    crate::work::complete_document(&work_path, completed.id, &[0x11; 16]).unwrap();
    let access = access(&config);

    let repo = render_page(
        PATH_REPO,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked")]),
        None,
    )
    .unwrap();
    assert!(repo.contains("Work (2)"));
    assert!(repo.contains(PATH_WORK));

    let active = render_page(
        PATH_WORK,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked")]),
        None,
    )
    .unwrap();
    assert!(active.contains(">Active Work Documents"));
    assert!(active.contains("[Active (1)`:/page/work.mu"));
    assert!(active.contains("[Completed (1)`:/page/work.mu"));
    assert!(active.contains("[Proposed (0)`:/page/work.mu"));
    assert!(active.contains("[All (2)`:/page/work.mu"));
    assert!(active.contains("#1 Active task"));
    assert!(active.contains("1 updates"));
    assert!(!active.contains("Completed task"));

    let completed_page = render_page(
        PATH_WORK,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "worked"),
            ("var_scope", "completed"),
        ]),
        None,
    )
    .unwrap();
    assert!(completed_page.contains(">Completed Work Documents"));
    assert!(completed_page.contains("[Active (1)`:/page/work.mu"));
    assert!(completed_page.contains("Completed task"));

    let doc = render_page(
        PATH_WORK_DOC,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked"), ("var_id", "1")]),
        None,
    )
    .unwrap();
    assert!(doc.contains(">Active task"));
    assert!(doc.contains(">Active Body"));
    assert!(doc.contains(">Updates (1)"));
    assert!(doc.contains("Progress update"));
    assert!(doc.contains("`[Download`:/file/workdoc`g=public|r=worked|scope=active|id=1]"));

    let completed_doc = render_page(
        PATH_WORK_DOC,
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "worked"),
            ("var_id", &completed.id.to_string()),
        ]),
        None,
    )
    .unwrap();
    assert!(completed_doc.contains(">Completed task"));
    assert!(completed_doc.contains("Status: completed"));
    assert!(completed_doc.contains("`[work`:/page/work.mu`g=public|r=worked|scope=completed]"));
    assert!(completed_doc.contains(&format!(
        "`[Download`:/file/workdoc`g=public|r=worked|scope=completed|id={}]",
        completed.id
    )));

    let active_download = download_work_document(
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "worked"),
            ("var_scope", "active"),
            ("var_id", "1"),
        ]),
        None,
    )
    .unwrap();
    assert_resource_response(active_download, b"# Active Body");

    let completed_download = download_work_document(
        &config,
        &access,
        &page_request(&[
            ("var_g", "public"),
            ("var_r", "worked"),
            ("var_id", &completed.id.to_string()),
        ]),
        None,
    )
    .unwrap();
    assert_resource_response(completed_download, b"Done");

    crate::work::set_document_permissions(&work_path, created.id, "read = none\n").unwrap();
    let active_after_deny = render_page(
        PATH_WORK,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked")]),
        None,
    )
    .unwrap();
    assert!(active_after_deny.contains("[Active (0)`:/page/work.mu"));
    assert!(active_after_deny.contains("[All (1)`:/page/work.mu"));
    assert!(!active_after_deny.contains("Active task"));
    let denied_doc = render_page(
        PATH_WORK_DOC,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked"), ("var_id", "1")]),
        None,
    )
    .unwrap();
    assert!(denied_doc.contains("Work Document Not Found"));
    let denied_download = download_work_document(
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "worked"), ("var_id", "1")]),
        None,
    )
    .unwrap();
    assert!(matches!(
        denied_download,
        RequestResponse::Bytes(bytes) if bytes.first() == Some(&protocol::RES_NOT_FOUND)
    ));
}

#[test]
fn work_pages_respect_read_access() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = cfg(tmp.path());
    create_repo(
        config.repositories_dir.join("public/private-work"),
        "README.md",
        "# Private\n",
    );
    config.allow_read = vec!["none".into()];
    let access = access(&config);

    assert!(render_page(
        PATH_WORK,
        &config,
        &access,
        &page_request(&[("var_g", "public"), ("var_r", "private-work")]),
        None,
    )
    .is_err());
}

fn cfg(root: &std::path::Path) -> ServerConfig {
    ServerConfig {
        dir: root.to_path_buf(),
        reticulum_dir: None,
        repositories_dir: root.join("repositories"),
        identity_path: root.join("repositories_identity"),
        client_identity_path: root.join("client_identity"),
        node_name: "Test Git Node".into(),
        announce_interval_secs: 300,
        serve_nomadnet: true,
        templates_dir: root.join("templates"),
        unicode_icons: false,
        media_conversion: true,
        record_stats: false,
        stats_ignore_identities: Vec::new(),
        stats_push_ignore_identities: Vec::new(),
        blocked_identities: Vec::new(),
        identity_aliases: std::collections::BTreeMap::new(),
        allow_read: vec!["all".into()],
        allow_write: vec!["none".into()],
        allow_create: vec!["none".into()],
        allow_stats: vec!["none".into()],
        allow_release: vec!["none".into()],
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

fn page_request(fields: &[(&str, &str)]) -> Vec<u8> {
    msgpack::pack(&Value::Map(
        fields
            .iter()
            .map(|(k, v)| (Value::Str((*k).into()), Value::Str((*v).into())))
            .collect(),
    ))
}

fn assert_resource_response(response: RequestResponse, expected: &[u8]) {
    match response {
        RequestResponse::Resource { data, metadata, .. } => {
            assert_eq!(data, expected);
            assert_eq!(
                metadata.as_deref(),
                Some(&protocol::metadata_status(protocol::RES_OK)[..])
            );
        }
        RequestResponse::Bytes(bytes) => panic!("expected resource response, got {bytes:?}"),
        RequestResponse::File { .. } => panic!("expected value response, got file"),
    }
}

fn create_repo(path: std::path::PathBuf, file: &str, content: &str) -> std::path::PathBuf {
    create_repo_bytes(path, file, content.as_bytes())
}

fn create_repo_bytes(path: std::path::PathBuf, file: &str, content: &[u8]) -> std::path::PathBuf {
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
            .arg("user.name=RNS Page Test")
            .arg("-c")
            .arg("user.email=rns-page-test@example.invalid")
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
