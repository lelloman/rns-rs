use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};
use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{Destination, RequestResponse, RnsNode};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::util::validate_repo_name;
use crate::{Error, Result};

pub const APP_NAME: &str = "nomadnetwork";
pub const ASPECT_NODE: &str = "node";

pub const PATH_INDEX: &str = "/page/index.mu";
pub const PATH_GROUP: &str = "/page/group.mu";
pub const PATH_REPO: &str = "/page/repo.mu";
pub const PATH_TREE: &str = "/page/tree.mu";
pub const PATH_BLOB: &str = "/page/blob.mu";
pub const PATH_COMMITS: &str = "/page/commits.mu";
pub const PATH_COMMIT: &str = "/page/commit.mu";
pub const PATH_REFS: &str = "/page/refs.mu";
pub const PATH_STATS: &str = "/page/stats.mu";
pub const PATH_RELEASES: &str = "/page/releases.mu";
pub const PATH_RELEASE: &str = "/page/release.mu";
pub const PATH_WORK: &str = "/page/work.mu";
pub const PATH_WORK_DOC: &str = "/page/work_doc.mu";
pub const PATH_DOWNLOAD: &str = "/file/download";
pub const PATH_WORK_DOC_DOWNLOAD: &str = "/file/workdoc";

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const RCLR_PUSH: &str = "B9A810";
const RCLR_PUSH_G: &str = "791212";
const RCLR_FETCH: &str = "10b981";
const RCLR_FETCH_G: &str = "1c5e71";
const RCLR_VIEW: &str = "3b82f6";
const RCLR_VIEW_G: &str = "13428A";
const RCLR_DOWNLOAD: &str = "7831E0";
const RCLR_DOWNLOAD_G: &str = "c5754d";

const PAGE_PATHS: &[&str] = &[
    PATH_INDEX,
    PATH_GROUP,
    PATH_REPO,
    PATH_TREE,
    PATH_BLOB,
    PATH_COMMITS,
    PATH_COMMIT,
    PATH_REFS,
    PATH_STATS,
    PATH_RELEASES,
    PATH_RELEASE,
    PATH_WORK,
    PATH_WORK_DOC,
];

pub fn destination_for_identity(identity: &Identity) -> Destination {
    Destination::single_in(APP_NAME, &[ASPECT_NODE], IdentityHash(*identity.hash()))
}

pub fn register_nomadnet_destination(
    node: &RnsNode,
    config: &ServerConfig,
    identity: &Identity,
) -> Result<Destination> {
    let destination = destination_for_identity(identity);
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("repository identity has no public key"))?;
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| Error::msg("repository identity has no private key"))?;
    let sig_prv: [u8; 32] = private_key[32..64].try_into().unwrap();
    let sig_pub: [u8; 32] = public_key[32..64].try_into().unwrap();

    node.register_link_destination(
        destination.hash.0,
        sig_prv,
        sig_pub,
        ResourceStrategy::AcceptAll as u8,
    )
    .map_err(|_| Error::msg("failed to register Nomad Network page destination"))?;

    let access = Access::new_with_aliases(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        &config.allow_release,
        &config.allow_interact,
        &config.allow_admin,
        config.repositories_dir.clone(),
        config.identity_aliases.clone(),
    )?
    .with_propose(&config.allow_propose)?
    .with_blocked_identities(config.blocked_identities.clone());
    register_page_handlers(node, config.clone(), access)?;

    Ok(destination)
}

fn register_page_handlers(node: &RnsNode, config: ServerConfig, access: Access) -> Result<()> {
    for path in PAGE_PATHS {
        let handler_path = *path;
        let handler_config = config.clone();
        let handler_access = access.clone();
        node.register_request_handler(handler_path, None, move |_link, path, data, remote| {
            let remote_hash = remote.map(|(hash, _)| hash);
            Some(
                match render_page(path, &handler_config, &handler_access, data, remote_hash) {
                    Ok(page) => page.into_bytes(),
                    Err(err) => error_page(&handler_config.node_name, &err.to_string()),
                },
            )
        })
        .map_err(|_| Error::msg(format!("failed to register page handler {handler_path}")))?;
    }
    let download_config = config.clone();
    let download_access = access.clone();
    node.register_request_handler_response(
        PATH_DOWNLOAD,
        None,
        move |_link, _path, data, remote| {
            let remote_hash = remote.map(|(hash, _)| hash);
            Some(
                download_file(&download_config, &download_access, data, remote_hash)
                    .unwrap_or_else(|err| RequestResponse::Bytes(error_response_bytes(&err))),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register file download handler"))?;
    let workdoc_download_config = config.clone();
    let workdoc_download_access = access.clone();
    node.register_request_handler_response(
        PATH_WORK_DOC_DOWNLOAD,
        None,
        move |_link, _path, data, remote| {
            let remote_hash = remote.map(|(hash, _)| hash);
            Some(
                download_work_document(
                    &workdoc_download_config,
                    &workdoc_download_access,
                    data,
                    remote_hash,
                )
                .unwrap_or_else(|err| RequestResponse::Bytes(error_response_bytes(&err))),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register work document download handler"))?;
    Ok(())
}

pub fn render_page(
    path: &str,
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&[u8; 16]>,
) -> Result<String> {
    let vars = parse_page_vars(data)?;
    let (template, content) = match path {
        PATH_INDEX => ("front", render_front_page(config, access, remote)?),
        PATH_GROUP => ("group", render_group_page(config, access, remote, &vars)?),
        PATH_REPO => ("repo", render_repo_page(config, access, remote, &vars)?),
        PATH_TREE => ("tree", render_tree_page(config, access, remote, &vars)?),
        PATH_BLOB => ("blob", render_blob_page(config, access, remote, &vars)?),
        PATH_COMMITS => (
            "commits",
            render_commits_page(config, access, remote, &vars)?,
        ),
        PATH_COMMIT => ("commit", render_commit_page(config, access, remote, &vars)?),
        PATH_REFS => ("refs", render_refs_page(config, access, remote, &vars)?),
        PATH_STATS => ("stats", render_stats_page(config, access, remote, &vars)?),
        PATH_RELEASES => (
            "releases",
            render_releases_page(config, access, remote, &vars)?,
        ),
        PATH_RELEASE => (
            "release",
            render_release_page(config, access, remote, &vars)?,
        ),
        PATH_WORK => ("work", render_work_page(config, access, remote, &vars)?),
        PATH_WORK_DOC => (
            "work_doc",
            render_work_doc_page(config, access, remote, &vars)?,
        ),
        _ => return Err(Error::msg("unknown page path")),
    };
    record_page_view(path, config, &vars, remote);
    Ok(render_template(config, template, &content))
}

fn record_page_view(
    path: &str,
    config: &ServerConfig,
    vars: &BTreeMap<String, String>,
    remote: Option<&[u8; 16]>,
) {
    match path {
        PATH_INDEX => crate::stats::record_front_view(config, remote),
        PATH_GROUP => {
            if let Some(group) = var(vars, "g") {
                crate::stats::record_group_view(config, group, remote);
            }
        }
        PATH_REPO | PATH_TREE | PATH_BLOB | PATH_COMMITS | PATH_COMMIT | PATH_REFS
        | PATH_RELEASES | PATH_RELEASE | PATH_WORK | PATH_WORK_DOC => {
            if let (Some(group), Some(repo)) = (var(vars, "g"), var(vars, "r")) {
                crate::stats::record_repository_view(config, group, repo, remote);
            }
        }
        _ => {}
    }
}

fn parse_page_vars(data: &[u8]) -> Result<BTreeMap<String, String>> {
    if data.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("page request must be a msgpack map"))?;
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let Some(key) = key.as_str() else {
            continue;
        };
        let value = match value {
            Value::Str(value) => value.clone(),
            Value::UInt(value) => value.to_string(),
            Value::Int(value) => value.to_string(),
            Value::Bool(value) => {
                if *value {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            _ => continue,
        };
        out.insert(key.to_string(), value);
    }
    Ok(out)
}

fn render_template(config: &ServerConfig, template: &str, content: &str) -> String {
    let page = apply_template(&page_template(config, template), content, config);
    apply_template(&base_template(config), &page, config)
}

fn error_page(node_name: &str, message: &str) -> Vec<u8> {
    default_base_template()
        .replace("{PAGE_CONTENT}", &format!(">Error\n\n{message}\n"))
        .replace("{NODE_NAME}", &m_escape(node_name))
        .replace("{VERSION}", env!("CARGO_PKG_VERSION"))
        .replace("{NAVIGATION}", "")
        .replace("{GEN_TIME}", "0ms")
        .into_bytes()
}

fn error_response_bytes(err: &Error) -> Vec<u8> {
    protocol::status_bytes(protocol::RES_INVALID_REQ, err.to_string())
}

fn base_template(config: &ServerConfig) -> String {
    load_template(config, "base").unwrap_or_else(|| default_base_template().to_string())
}

fn page_template(config: &ServerConfig, template: &str) -> String {
    load_template(config, template).unwrap_or_else(|| "{PAGE_CONTENT}".to_string())
}

fn load_template(config: &ServerConfig, template: &str) -> Option<String> {
    if !template
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return None;
    }
    let path = config.templates_dir.join(format!("{template}.mu"));
    fs::read_to_string(path)
        .ok()
        .map(|template| template.trim_end().to_string())
}

fn apply_template(template: &str, content: &str, config: &ServerConfig) -> String {
    template
        .replace("{NODE_NAME}", &m_escape(&config.node_name))
        .replace("{VERSION}", env!("CARGO_PKG_VERSION"))
        .replace("{NAVIGATION}", "")
        .replace("{GEN_TIME}", "0ms")
        .replace("{PAGE_CONTENT}", content)
}

fn default_base_template() -> &'static str {
    "#!c=0\n>{NODE_NAME}\n\n{PAGE_CONTENT}\n<\n-\n`a`F666`[Served by rngit`:/page/index.mu] - Generated by rngit`f\n"
}

fn icon(config: &ServerConfig, name: &str) -> &'static str {
    if !config.unicode_icons {
        return "";
    }
    match name {
        "sep" => "•",
        "folder" => "🗀",
        "file" => "🗎",
        "branch" => "⑃",
        "tag" => "⌆",
        "commits" => "🖹",
        "package" => "▣",
        "stats" => "🗠",
        "heart" => "♥",
        _ => "",
    }
}

fn icon_label(config: &ServerConfig, name: &str, label: &str) -> String {
    let icon = icon(config, name);
    if icon.is_empty() {
        label.to_string()
    } else {
        format!("{icon} {label}")
    }
}

fn icon_sep(config: &ServerConfig) -> &'static str {
    let sep = icon(config, "sep");
    if sep.is_empty() {
        "•"
    } else {
        sep
    }
}

fn m_link(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    format!("`!{}`!", m_link_raw(label, path, fields))
}

fn m_link_raw(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    let mut out = String::from("`[");
    out.push_str(&sanitize_label(label));
    out.push_str("`:");
    out.push_str(path);
    if !fields.is_empty() {
        out.push('`');
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push('|');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(&sanitize_field(value));
        }
    }
    out.push(']');
    out
}

fn markdown_blob_url_scope(group: &str, repo: &str, reference: &str, current_path: &str) -> String {
    let directory = current_path
        .rsplit_once('/')
        .map(|(directory, _)| format!("{directory}/"))
        .unwrap_or_default();
    let mut out = format!(":{PATH_BLOB}`");
    for (index, (key, value)) in [
        ("g", group),
        ("r", repo),
        ("ref", reference),
        ("path", directory.as_str()),
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            out.push('|');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&sanitize_field(value));
    }
    out
}

fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '[' && *ch != ']' && *ch != '`')
        .collect()
}

fn sanitize_field(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn m_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('\t', "   ")
}

fn m_escape_line_start_controls(value: &str) -> String {
    let escaped = m_escape(value);
    if value.starts_with('-') || value.starts_with('>') || value.starts_with('<') {
        format!("\\{escaped}")
    } else {
        escaped
    }
}

fn format_commit_message(value: &str) -> String {
    value
        .split('\n')
        .map(|line| {
            let escaped = m_escape(line);
            if line.starts_with('-') {
                format!("\\{escaped}")
            } else {
                escaped
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn join_git_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_unix_time(timestamp: i64) -> String {
    timestamp.to_string()
}

fn render_front_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
) -> Result<String> {
    let groups = accessible_groups(config, access, remote)?;
    let mut out = format!(">>\n{} /\n\n>Groups\n\n", m_link("Node", PATH_INDEX, &[]));
    if groups.is_empty() {
        out.push_str("No repository groups available.\n");
        return Ok(out);
    }
    for (group, repos) in groups {
        out.push_str(&format!(
            "{} ({} repositories)\n",
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            repos.len()
        ));
        for repo in repos {
            out.push_str(&format!(
                "  - {}\n",
                m_link_raw(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
            ));
        }
    }
    Ok(out)
}

fn render_group_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let group = required_var(vars, "g")?;
    validate_group_name(group)?;
    let repos = accessible_repositories(config, access, remote, group)?;
    if repos.is_empty() {
        return Ok(">Group Not Found\n\nThe requested group was not found.\n".to_string());
    }

    let mut out = format!(
        ">>\n{} / {}\n\n>Repositories\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_escape(group)
    );
    for repo in repos {
        let repo_path = config.repositories_dir.join(group).join(&repo);
        let description = repository_description(&repo_path)?;
        out.push_str(&format!(
            "- {}",
            m_link(&repo, PATH_REPO, &[("g", group), ("r", &repo)])
        ));
        if !description.is_empty() {
            out.push_str(&format!(" - {}", m_escape(&description)));
        }
        out.push('\n');
    }
    Ok(out)
}

fn render_repo_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let description = repository_description(&repository)?;
    let origin = repository_origin(&repository)?;
    let refs = git_refs(&repository)?;
    let readme = readme_content(&repository)?;
    let repo_url = format!("rns://<repository-destination>/{group}/{repo}");
    let thanks = repository_thanks(&repository, var(vars, "thanks").is_some())?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let release_count = crate::release::list_releases(&releases_path)?
        .into_iter()
        .filter(|release| release.status == "published")
        .count();
    let work_path = crate::work::work_sidecar_path(&repository);
    let work_lists = crate::work::list_documents(&work_path, crate::work::WorkListScope::All)?;
    let work_count = work_lists.active.len() + work_lists.completed.len();

    let branch_count = refs.heads.len().to_string();
    let tag_count = refs.tags.len().to_string();
    let mut out = format!(
        ">>\n{} / {} / {} `F666{}`f\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_escape(&repo),
        m_escape(&repo_url)
    );
    if let Some(origin) = origin {
        out.push_str(&format!(
            "`F666{} from {}`f",
            origin.label(),
            m_escape(&origin.source)
        ));
        if let Some(synced_at) = origin.synced_at {
            out.push_str(&format!(
                " `*`F666synced {} ago`f`*",
                format_sync_age(synced_at)
            ));
        }
        out.push('\n');
    }
    out.push('\n');
    if !description.is_empty() {
        out.push_str(&format!("{}\n\n", m_escape(&description)));
    }
    let mut nav_links = vec![
        m_link_raw(
            &icon_label(config, "folder", "Files"),
            PATH_TREE,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            &icon_label(config, "commits", "Commits"),
            PATH_COMMITS,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            &icon_label(config, "branch", &format!("Branches ({branch_count})")),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "heads")],
        ),
        m_link_raw(
            &icon_label(config, "tag", &format!("Tags ({tag_count})")),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "tags")],
        ),
        m_link_raw(
            &icon_label(config, "heart", &format!("Thanks ({thanks})")),
            PATH_REPO,
            &[("g", &group), ("r", &repo), ("thanks", "y")],
        ),
    ];
    if release_count > 0 {
        nav_links.push(m_link_raw(
            &icon_label(config, "package", &format!("Releases ({release_count})")),
            PATH_RELEASES,
            &[("g", &group), ("r", &repo)],
        ));
    }
    if work_count > 0 {
        nav_links.push(m_link_raw(
            &icon_label(config, "work", &format!("Work ({work_count})")),
            PATH_WORK,
            &[("g", &group), ("r", &repo)],
        ));
    }
    if access.allows(Operation::Stats, &format!("{group}/{repo}"), remote)? {
        nav_links.push(m_link_raw(
            &icon_label(config, "stats", "Stats"),
            PATH_STATS,
            &[("g", &group), ("r", &repo)],
        ));
    }
    let sep = format!(" {} ", icon_sep(config));
    out.push_str(&format!("{}\n\n", nav_links.join(&sep)));
    if let Some(readme) = readme {
        if !readme.content.trim_start().starts_with('>') {
            out.push_str("-\n");
        }
        if readme.markdown {
            out.push_str(&markdown_to_micron_scoped(
                &readme.content,
                Some(&markdown_blob_url_scope(&group, &repo, "HEAD", "README.md")),
            ));
            if !out.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(readme.content.trim_end());
            out.push('\n');
        }
    } else {
        out.push_str("No README file found in this repository.\n");
    }
    Ok(out)
}

fn render_tree_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let path = var(vars, "path").unwrap_or("");
    validate_git_path(path)?;
    let resolved = resolve_ref(&repository, reference)?;
    let entries = tree_entries(&repository, &resolved, path)?;
    let title_path = if path.is_empty() { "/" } else { path };

    let mut out = format!(
        ">>\n{} / {} / {} / files / {}\n\n>Contents: {} ({})\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(title_path),
        m_escape(reference),
        &resolved[..8]
    );
    if entries.is_empty() {
        out.push_str("Empty directory.\n");
    } else {
        for entry in entries {
            let entry_path = join_git_path(path, &entry.name);
            if entry.kind == "tree" {
                let label = icon_label(config, "folder", &format!("{}/", entry.name));
                out.push_str(&format!(
                    "{}\n",
                    m_link_raw(
                        &label,
                        PATH_TREE,
                        &[
                            ("g", &group),
                            ("r", &repo),
                            ("ref", reference),
                            ("path", &entry_path)
                        ]
                    )
                ));
            } else {
                let label = icon_label(config, "file", &entry.name);
                out.push_str(&format!(
                    "{} {}\n",
                    m_link_raw(
                        &label,
                        PATH_BLOB,
                        &[
                            ("g", &group),
                            ("r", &repo),
                            ("ref", reference),
                            ("path", &entry_path)
                        ]
                    ),
                    entry.size_label()
                ));
            }
        }
    }
    Ok(out)
}

fn render_blob_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let path = normalize_blob_path(required_var(vars, "path")?);
    validate_git_path(&path)?;
    let resolved = resolve_ref(&repository, reference)?;
    if git_object_kind(&repository, &resolved, &path)? == "tree" {
        return render_tree_page(config, access, remote, vars);
    }
    let blob = blob_info(&repository, &resolved, &path)?;
    let renderable = renderable_blob(&path);
    let raw_requested = var(vars, "raw").is_some();
    let render_requested = var(vars, "render").is_some();
    let render =
        renderable.is_some() && !raw_requested && (render_requested || render_by_default(&path));
    let download_link = m_link(
        "Download",
        PATH_DOWNLOAD,
        &[
            ("g", &group),
            ("r", &repo),
            ("ref", reference),
            ("path", path.as_str()),
        ],
    );
    let controls = if renderable.is_some() {
        let render_link = m_link(
            "View rendered",
            PATH_BLOB,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path.as_str()),
                ("render", "y"),
            ],
        );
        let raw_link = m_link(
            "View raw",
            PATH_BLOB,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path.as_str()),
                ("raw", "y"),
            ],
        );
        let sep = icon_sep(config);
        Some(if render {
            format!("Displaying Rendered {sep} {raw_link}")
        } else {
            format!("Displaying Raw {sep} {render_link} {sep} {download_link}")
        })
    } else {
        Some(format!(
            "Displaying Raw {} {download_link}",
            icon_sep(config)
        ))
    };
    let content = if !blob.displayable {
        crate::highlight::plain_literal_block(&blob.content)
    } else if render {
        match renderable {
            Some(RenderableBlob::Markdown) => markdown_to_micron_scoped(
                &blob.content,
                Some(&markdown_blob_url_scope(&group, &repo, reference, &path)),
            ),
            Some(RenderableBlob::Micron) => {
                let mut out = blob.content.clone();
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out
            }
            None => crate::highlight::literal_block(&blob.content, Some(&path), None),
        }
    } else {
        crate::highlight::literal_block(&blob.content, Some(&path), None)
    };
    let controls = controls
        .map(|controls| format!("{controls}\n\n"))
        .unwrap_or_default();
    Ok(format!(
        ">>\n{} / {} / {} / {}\n\n>{} `F666{} ({}, {})`f\n\n{}{}",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(&path),
        m_escape(&path),
        &resolved[..8],
        if blob.binary { "Binary" } else { "Text" },
        format_size(blob.size),
        controls,
        content
    ))
}

#[derive(Debug, Clone, Copy)]
enum RenderableBlob {
    Markdown,
    Micron,
}

fn renderable_blob(path: &str) -> Option<RenderableBlob> {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("md") => Some(RenderableBlob::Markdown),
        Some("mu") => Some(RenderableBlob::Micron),
        _ => None,
    }
}

fn render_by_default(path: &str) -> bool {
    renderable_blob(path).is_some()
}

fn render_commits_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let resolved = resolve_ref(&repository, reference)?;
    let commits = commits(&repository, &resolved, 100)?;

    let mut out = format!(
        ">>\n{} / {} / {} / commits\n\n>Commits `F666{} ({})`f\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(reference),
        &resolved[..8]
    );
    if commits.is_empty() {
        out.push_str("No commits found.\n");
    } else {
        for commit in commits {
            out.push_str(&format!(
                "{} {} `F666{}`f\n{}\n\n",
                m_link_raw(
                    &commit.hash[..7],
                    PATH_COMMIT,
                    &[
                        ("g", &group),
                        ("r", &repo),
                        ("ref", reference),
                        ("h", &commit.hash),
                    ],
                ),
                m_escape(&commit.author),
                format_unix_time(commit.timestamp),
                m_escape(&commit.subject)
            ));
        }
    }
    Ok(out)
}

fn render_commit_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let _resolved = resolve_ref(&repository, reference)?;
    let hash = required_var(vars, "h")?;
    validate_refish(hash)?;
    let commit = commit_info(&repository, hash)?;
    let signature = commit_signature_status(&repository, hash)?;
    let commits_link = m_link(
        "commits",
        PATH_COMMITS,
        &[("g", &group), ("r", &repo), ("ref", reference)],
    );
    let mut out = format!(
        ">>\n{} / {} / {} / {} / commit {}\n\n>Commit {}\n\n{}\nAuthor: {} <{}>\nDate: {}\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        commits_link,
        &commit.hash[..7],
        commit.hash,
        m_escape(&commit.subject),
        m_escape(&commit.author),
        m_escape(&commit.email),
        format_unix_time(commit.timestamp)
    );
    if let Some(signature) = signature {
        out.push_str(&format!("Signature: {}\n", m_escape(&signature)));
    }
    if !commit.body.is_empty() {
        out.push_str(&format!("\n{}\n", format_commit_message(&commit.body)));
    }
    out.push_str("\n>Files changed\n\n");
    for file in commit.files {
        out.push_str(&format!("{} {}\n", file.status, m_escape(&file.path)));
    }
    Ok(out)
}

fn commit_signature_status(repo: &Path, hash: &str) -> Result<Option<String>> {
    let commit = raw_commit_object(repo, hash)?;
    let (Some(signature), signed_content) = crate::commitsigs::split_commit_signature(&commit)
    else {
        return Ok(None);
    };
    let status = crate::commitsigs::verify_message_signature(&signature, &signed_content, None);
    if status.valid && status.author_match {
        Ok(Some("Valid, signed by author".into()))
    } else if status.valid {
        Ok(Some(status.message))
    } else {
        Ok(Some(format!("Invalid signature: {}", status.message)))
    }
}

fn render_refs_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let refs = git_refs(&repository)?;
    let mut out = format!(
        ">>\n{} / {} / {} / refs\n\n>Refs\n\n>Branches\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
    );
    for branch in refs.heads {
        out.push_str(&format!(
            "- {} `F666{}`f\n",
            m_link_raw(
                &branch.name,
                PATH_TREE,
                &[("g", &group), ("r", &repo), ("ref", &branch.name)]
            ),
            &branch.sha[..8]
        ));
    }
    out.push_str("\n>Tags\n");
    for tag in refs.tags {
        out.push_str(&format!(
            "- {} `F666{}`f\n",
            m_link_raw(
                &tag.name,
                PATH_TREE,
                &[("g", &group), ("r", &repo), ("ref", &tag.name)]
            ),
            &tag.sha[..8]
        ));
    }
    Ok(out)
}

fn render_stats_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, _repository) = accessible_repository(config, access, remote, vars)?;
    if !access.allows(Operation::Stats, &format!("{group}/{repo}"), remote)? {
        return Ok(">>\n>Error\n\nThe requested repository was not found.\n".to_string());
    }
    let Some(stats) = crate::stats::repository_stats(config, access, remote, &group, &repo, 90)?
    else {
        return Ok(
            ">>\n>Stats Unavailable\n\nCould not retrieve statistics for this repository.\n"
                .to_string(),
        );
    };

    let mut out = format!(
        ">>\n{} / {} / {} / stats\n\n>Stats for {}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(&stats.repository)
    );
    out.push_str(&format!(
        "`FT{RCLR_FETCH}Fetches`f   : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.fetches.total,
        stats.fetches.daily.last().copied().unwrap_or(0),
        stats.fetches.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_PUSH}Pushes`f    : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.pushes.total,
        stats.pushes.daily.last().copied().unwrap_or(0),
        stats.pushes.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_VIEW}Views`f     : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.views.total,
        stats.views.daily.last().copied().unwrap_or(0),
        stats.views.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_DOWNLOAD}Downloads`f : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.downloads_combined.total,
        stats.downloads_combined.daily.last().copied().unwrap_or(0),
        stats.downloads_combined.peak
    ));
    out.push_str(&format!(
        "`F0aaActivity`f  : {:>5} points\n\n",
        stats.activity_score
    ));
    out.push_str(&format!(
        "{}{}`f over the last {} days ({})\n\n",
        stats.activity_level.color(),
        stats.activity_level.label(),
        stats.actual_days,
        stats.date_range
    ));

    if stats.fetches.total > 0 {
        out.push_str(">Fetches\n\n");
        out.push_str(&render_chart(
            &stats.fetches.daily,
            &stats.timeline_labels,
            RCLR_FETCH,
            Some(RCLR_FETCH_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.pushes.total > 0 {
        out.push_str(">Pushes\n\n");
        out.push_str(&render_chart(
            &stats.pushes.daily,
            &stats.timeline_labels,
            RCLR_PUSH,
            Some(RCLR_PUSH_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.views.total > 0 {
        out.push_str(">Views\n\n");
        out.push_str(&render_chart(
            &stats.views.daily,
            &stats.timeline_labels,
            RCLR_VIEW,
            Some(RCLR_VIEW_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.downloads_combined.total > 0 {
        out.push_str(">Downloads\n\n");
        out.push_str(&render_chart(
            &stats.downloads_combined.daily,
            &stats.timeline_labels,
            RCLR_DOWNLOAD,
            Some(RCLR_DOWNLOAD_G),
            1.7,
            10,
        ));
        out.push('\n');
    }
    if stats.activity_score > 0 {
        out.push_str(">Combined Activity\n\n");
        out.push_str(&render_combined_chart(
            &stats.views.daily,
            &stats.fetches.daily,
            &stats.pushes.daily,
            &stats.downloads_combined.daily,
            &stats.timeline_labels,
            6,
        ));
    } else {
        out.push_str(
            "`*\nNo development activity recorded for this repository in the selected time period.\n\n`*",
        );
    }
    Ok(out)
}

fn render_releases_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let releases: Vec<_> = crate::release::list_releases(&releases_path)?
        .into_iter()
        .filter(|release| release.status == "published")
        .collect();
    let latest_release = crate::release::configured_latest_tag(&releases_path)?;
    let mut out = format!(
        ">>\n{} / {} / {} / releases\n\n>Releases ({})\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        releases.len()
    );
    if releases.is_empty() {
        out.push_str("No releases available for this repository.\n");
        return Ok(out);
    }
    for release in releases {
        let latest = if latest_release.as_deref() == Some(release.tag.as_str()) {
            format!(" {} `FT537855`*Latest`*`f", icon_sep(config))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "{} `F666{} artifacts{}`f\n",
            m_link(
                &release.tag,
                PATH_RELEASE,
                &[("g", &group), ("r", &repo), ("tag", &release.tag)]
            ),
            release.artifacts,
            latest
        ));
        if !release.preview.is_empty() {
            append_release_preview(&mut out, &release.preview_format, &release.preview);
        }
        out.push('\n');
    }
    Ok(out)
}

fn append_release_preview(out: &mut String, format: &str, preview: &str) {
    match format {
        "markdown" => out.push_str(&markdown_to_micron(preview)),
        "micron" => {
            out.push_str(preview);
            if !preview.ends_with('\n') {
                out.push('\n');
            }
        }
        _ => {
            out.push_str(&m_escape_line_start_controls(preview));
            out.push('\n');
        }
    }
}

fn render_release_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let requested_tag = var(vars, "tag").unwrap_or("latest");
    let tag = if requested_tag == "latest" {
        let Some(tag) = crate::release::latest_published_tag(&releases_path)? else {
            return Ok(">Release Not Found\n\nNo latest release exists.\n".to_string());
        };
        tag
    } else {
        requested_tag.to_string()
    };
    let Some(release) = crate::release::release_data(&releases_path, &tag)? else {
        return Ok(">Release Not Found\n\nThe requested release was not found.\n".to_string());
    };
    if release.status != "published" {
        return Ok(">Release Not Found\n\nThe requested release was not found.\n".to_string());
    }
    let release_dir = releases_path.join(&release.tag);
    let thanks = crate::release::release_thanks(&release_dir, var(vars, "thanks").is_some())?;
    let mut out = format!(
        ">>\n{} / {} / {} / {} / {}\n\n>Release {}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_link("releases", PATH_RELEASES, &[("g", &group), ("r", &repo)]),
        m_escape(&release.tag),
        m_escape(&release.tag)
    );
    out.push_str(&format!(
        "{}\n\n",
        m_link(
            &icon_label(config, "heart", &format!("Thanks ({thanks})")),
            PATH_RELEASE,
            &[
                ("g", &group),
                ("r", &repo),
                ("tag", &release.tag),
                ("thanks", "y")
            ]
        )
    ));
    if !release.notes.is_empty() {
        match release.notes_format.as_str() {
            "markdown" => out.push_str(&markdown_to_micron(&release.notes)),
            "micron" => out.push_str(&release.notes),
            _ => out.push_str(&m_escape(&release.notes)),
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(">Artifacts\n\n");
    if release.artifacts.is_empty() {
        out.push_str("`*No artifacts for this release`*\n");
    } else {
        for artifact in release.artifacts {
            out.push_str(&format!(
                "{} ({})\n",
                m_link(
                    &artifact.name,
                    PATH_DOWNLOAD,
                    &[
                        ("g", &group),
                        ("r", &repo),
                        ("tag", &release.tag),
                        ("artifact", &artifact.name)
                    ]
                ),
                format_size(artifact.size)
            ));
        }
    }
    Ok(out)
}

fn render_work_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let scope = var(vars, "scope").unwrap_or("active");
    let list_scope =
        crate::work::WorkListScope::parse(scope).ok_or_else(|| Error::msg("invalid scope"))?;
    let lists =
        crate::work::list_documents(&crate::work::work_sidecar_path(&repository), list_scope)?;
    let mut out = format!(
        ">>\n{} / {} / {} / work\n\n>Work Documents\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
    );
    let tabs = [
        m_link_raw(
            "Active",
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "active")],
        ),
        m_link_raw(
            "Completed",
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "completed")],
        ),
        m_link_raw(
            "Proposed",
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "proposed")],
        ),
        m_link_raw(
            "All",
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "all")],
        ),
    ];
    out.push_str(&format!(
        "{}\n\n",
        tabs.join(&format!(" {} ", icon_sep(config)))
    ));
    if matches!(
        list_scope,
        crate::work::WorkListScope::Active | crate::work::WorkListScope::All
    ) {
        append_work_section(
            &mut out,
            &group,
            &repo,
            crate::work::WorkScope::Active,
            &lists.active,
        );
    }
    if matches!(
        list_scope,
        crate::work::WorkListScope::Completed | crate::work::WorkListScope::All
    ) {
        append_work_section(
            &mut out,
            &group,
            &repo,
            crate::work::WorkScope::Completed,
            &lists.completed,
        );
    }
    if matches!(
        list_scope,
        crate::work::WorkListScope::Proposed | crate::work::WorkListScope::All
    ) {
        append_work_section(
            &mut out,
            &group,
            &repo,
            crate::work::WorkScope::Proposed,
            &lists.proposed,
        );
    }
    Ok(out)
}

fn append_work_section(
    out: &mut String,
    group: &str,
    repo: &str,
    scope: crate::work::WorkScope,
    docs: &[crate::work::WorkSummary],
) {
    let title = match scope {
        crate::work::WorkScope::Active => "Active Work Documents",
        crate::work::WorkScope::Completed => "Completed Work Documents",
        crate::work::WorkScope::Proposed => "Proposed Work Documents",
    };
    out.push_str(&format!(">{title} ({})\n\n", docs.len()));
    if docs.is_empty() {
        out.push_str("No work documents found.\n\n");
        return;
    }
    for doc in docs {
        let doc_id = doc.id.to_string();
        out.push_str(&format!(
            "{} `F666{} updates`f\n",
            m_link(
                &format!("#{} {}", doc.id, doc.title),
                PATH_WORK_DOC,
                &[
                    ("g", group),
                    ("r", repo),
                    ("scope", scope.as_str()),
                    ("id", &doc_id)
                ]
            ),
            doc.comments
        ));
        out.push_str(&format!(
            "`F666{} by {}`f\n\n",
            format_unix_time(doc.created as i64),
            m_escape(&doc.author)
        ));
    }
}

fn render_work_doc_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let id = required_var(vars, "id")?
        .parse::<u64>()
        .map_err(|_| Error::msg("invalid work document ID"))?;
    let work_path = crate::work::work_sidecar_path(&repository);
    let (scope, document) =
        resolve_work_document(&work_path, var(vars, "scope").unwrap_or("all"), id)?;
    let Some(document) = document else {
        return Ok(
            ">Work Document Not Found\n\nThe requested work document was not found.\n".into(),
        );
    };
    let mut out = format!(
        ">>\n{} / {} / {} / {} / #{}\n\n>{}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_link(
            "work",
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", scope.as_str())]
        ),
        document.id,
        m_escape(&document.title)
    );
    out.push_str(&format!(
        "`F666Status: {} | Author: {} | Signature: {} | Created: {} | Edited: {}`f\n\n",
        scope.as_str(),
        m_escape(&document.author),
        work_signature_status(&document),
        format_unix_time(document.created as i64),
        format_unix_time(document.edited as i64)
    ));
    let doc_id = document.id.to_string();
    out.push_str(&format!(
        "{}\n\n",
        m_link(
            "Download",
            PATH_WORK_DOC_DOWNLOAD,
            &[
                ("g", &group),
                ("r", &repo),
                ("scope", scope.as_str()),
                ("id", &doc_id)
            ]
        )
    ));
    append_formatted_content(&mut out, &document.format, &document.content);
    out.push_str(&format!("\n>Updates ({})\n\n", document.comments.len()));
    if document.comments.is_empty() {
        out.push_str("No updates for this work document.\n");
    } else {
        for comment in document.comments {
            out.push_str(&format!(
                ">#{} by {} at {}\n\n",
                comment.id,
                m_escape(&comment.author),
                format_unix_time(comment.created as i64)
            ));
            append_formatted_content(&mut out, &comment.format, &comment.content);
            out.push('\n');
        }
    }
    Ok(out)
}

fn work_signature_status(document: &crate::work::WorkDocument) -> &'static str {
    let Some(signature) = document.signature.as_deref() else {
        return "Document not signed";
    };
    if signature.len() != 64 {
        return "Not valid";
    }
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return "Not valid";
    };
    let Some(identity_bytes) = document.identity.as_deref() else {
        return "Not valid";
    };
    let Ok(public_key) = <[u8; 64]>::try_from(identity_bytes) else {
        return "Not valid";
    };
    let identity = Identity::from_public_key(&public_key);
    if identity.verify(signature, document.content.as_bytes()) {
        "Valid"
    } else {
        "Not valid"
    }
}

fn resolve_work_document(
    work_path: &Path,
    requested_scope: &str,
    id: u64,
) -> Result<(crate::work::WorkScope, Option<crate::work::WorkDocument>)> {
    let requested_scope = if matches!(requested_scope, "active" | "completed" | "proposed" | "all")
    {
        requested_scope
    } else {
        "active"
    };
    match requested_scope {
        "active" | "completed" | "proposed" => {
            let scope = crate::work::WorkScope::parse(requested_scope).unwrap();
            Ok((scope, crate::work::view_document(work_path, scope, id)?))
        }
        "all" => {
            if let Some(document) =
                crate::work::view_document(work_path, crate::work::WorkScope::Active, id)?
            {
                Ok((crate::work::WorkScope::Active, Some(document)))
            } else if let Some(document) =
                crate::work::view_document(work_path, crate::work::WorkScope::Completed, id)?
            {
                Ok((crate::work::WorkScope::Completed, Some(document)))
            } else {
                Ok((
                    crate::work::WorkScope::Proposed,
                    crate::work::view_document(work_path, crate::work::WorkScope::Proposed, id)?,
                ))
            }
        }
        _ => unreachable!(),
    }
}

fn append_formatted_content(out: &mut String, format: &str, content: &str) {
    match format {
        "micron" => out.push_str(content),
        "markdown" => out.push_str(&markdown_to_micron(content)),
        _ => out.push_str(&m_escape(content)),
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
}

pub fn download_work_document(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&[u8; 16]>,
) -> Result<RequestResponse> {
    let vars = parse_page_vars(data)?;
    let (group, repo, repository) = match accessible_repository(config, access, remote, &vars) {
        Ok(repo) => repo,
        Err(_) => {
            return Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_NOT_FOUND,
                b"repository not found",
            )));
        }
    };
    let id = required_var(&vars, "id")?
        .parse::<u64>()
        .map_err(|_| Error::msg("invalid work document ID"))?;
    let work_path = crate::work::work_sidecar_path(&repository);
    let Some(document) =
        resolve_work_document(&work_path, var(&vars, "scope").unwrap_or("all"), id)?.1
    else {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"work document not found",
        )));
    };
    crate::stats::record_download(config, &format!("{group}/{repo}"), remote);
    Ok(RequestResponse::Resource {
        data: document.content.into_bytes(),
        metadata: Some(protocol::metadata_status(protocol::RES_OK)),
        auto_compress: true,
    })
}

pub fn download_file(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&[u8; 16]>,
) -> Result<RequestResponse> {
    let vars = parse_page_vars(data)?;
    let (group, repo, repository) = match accessible_repository(config, access, remote, &vars) {
        Ok(repo) => repo,
        Err(_) => {
            return Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_NOT_FOUND,
                b"repository not found",
            )));
        }
    };
    if let Some(artifact) = var(&vars, "artifact") {
        let artifact = decode_url_component(artifact);
        let tag = var(&vars, "tag").unwrap_or("latest");
        let releases_path = crate::release::release_sidecar_path(&repository);
        let Some(path) = crate::release::artifact_path(&releases_path, tag, &artifact)? else {
            return Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_NOT_FOUND,
                b"file not found",
            )));
        };
        let data = fs::read(path)?;
        crate::stats::record_release_download(config, &format!("{group}/{repo}"), remote);
        return Ok(RequestResponse::Resource {
            data,
            metadata: Some(protocol::metadata_status(protocol::RES_OK)),
            auto_compress: true,
        });
    }

    let reference = var(&vars, "ref").unwrap_or("HEAD");
    let path = required_var(&vars, "path")?;
    validate_git_path(path)?;
    let resolved = resolve_ref(&repository, reference)?;
    let spec = format!("{resolved}:{path}");
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repository)
            .arg("show")
            .arg(spec),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"file not found",
        )));
    }
    crate::stats::record_download(config, &format!("{group}/{repo}"), remote);
    Ok(RequestResponse::Resource {
        data: output.stdout,
        metadata: Some(protocol::metadata_status(protocol::RES_OK)),
        auto_compress: true,
    })
}

fn render_chart(
    data: &[u64],
    labels: &[String; 2],
    color: &str,
    secondary_color: Option<&str>,
    gradient_factor: f64,
    height: u64,
) -> String {
    if data.is_empty() || data.iter().all(|value| *value == 0) {
        return "No data available\n".to_string();
    }
    let max = data.iter().copied().max().unwrap_or(1).max(1) as f64;
    let primary = expand_chart_color(color);
    let secondary = secondary_color
        .map(expand_chart_color)
        .unwrap_or_else(|| dim_chart_color(&primary));
    let mut out = format!("`FT{primary}Peak: {}`f\n", max as u64);
    for row in (1..=height).rev() {
        let row_top = row as f64 / height as f64 * max;
        let row_mid = (row as f64 - 0.5) / height as f64 * max;
        let grad_top = row as f64 / height as f64;
        let grad_mid = (row as f64 - 0.5) / height as f64;
        let top_color = gradient_chart_color(&primary, &secondary, grad_top, gradient_factor);
        let mid_color = gradient_chart_color(&primary, &secondary, grad_mid, gradient_factor);
        out.push('│');
        for value in data {
            let value = *value as f64;
            if value >= row_top {
                out.push_str(&format!("`FT{top_color}`BT{mid_color}▀`f`b"));
            } else if value >= row_mid || (row == 1 && value > 0.0) {
                out.push_str(&format!("`FT{mid_color}▄`f"));
            } else {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out.push('└');
    for _ in data {
        out.push('─');
    }
    out.push_str("┘\n");
    out.push_str(&format!("`F666{:<12}`f", labels[0]));
    let chart_width = data.len() + 2;
    let spacing = chart_width.saturating_sub(24);
    out.push_str(&" ".repeat(spacing));
    out.push_str(&format!("`F666{:>12}`f\n", labels[1]));
    out
}

fn expand_chart_color(color: &str) -> String {
    let color = color.trim_start_matches('#');
    if color.len() == 3 {
        color.chars().flat_map(|ch| [ch, ch]).collect()
    } else {
        color.chars().take(6).collect()
    }
}

fn dim_chart_color(primary: &str) -> String {
    let rgb = chart_rgb(primary);
    format!(
        "{:02x}{:02x}{:02x}",
        (rgb[0] as f64 * 0.42) as u8,
        (rgb[1] as f64 * 0.42) as u8,
        (rgb[2] as f64 * 0.42) as u8
    )
}

fn gradient_chart_color(primary: &str, secondary: &str, t: f64, factor: f64) -> String {
    let primary = chart_rgb(primary);
    let secondary = chart_rgb(secondary);
    let t = (t * factor).min(1.0);
    format!(
        "{:02x}{:02x}{:02x}",
        (secondary[0] as f64 + (primary[0] as f64 - secondary[0] as f64) * t) as u8,
        (secondary[1] as f64 + (primary[1] as f64 - secondary[1] as f64) * t) as u8,
        (secondary[2] as f64 + (primary[2] as f64 - secondary[2] as f64) * t) as u8
    )
}

fn chart_rgb(color: &str) -> [u8; 3] {
    let color = expand_chart_color(color);
    [
        u8::from_str_radix(color.get(0..2).unwrap_or("00"), 16).unwrap_or(0),
        u8::from_str_radix(color.get(2..4).unwrap_or("00"), 16).unwrap_or(0),
        u8::from_str_radix(color.get(4..6).unwrap_or("00"), 16).unwrap_or(0),
    ]
}

fn render_combined_chart(
    views: &[u64],
    fetches: &[u64],
    pushes: &[u64],
    downloads: &[u64],
    labels: &[String; 2],
    height: u64,
) -> String {
    if views.is_empty() || fetches.is_empty() || pushes.is_empty() || downloads.is_empty() {
        return "No data available\n".to_string();
    }

    let categories = [
        ("Pushes", dim_to_black(RCLR_PUSH, 0.87), pushes),
        ("Fetches", dim_to_black(RCLR_FETCH, 0.87), fetches),
        ("Views", dim_to_black(RCLR_VIEW, 0.87), views),
        ("Downloads", dim_to_black(RCLR_DOWNLOAD, 0.87), downloads),
    ];
    let mut out = categories
        .iter()
        .map(|(label, color, _)| format!("`FT{color}`BT{color}██`f`b {label}"))
        .collect::<Vec<_>>()
        .join("  ");
    out.push_str("\n\n");
    let num_points = views.len();

    for row in (1..=height).rev() {
        let lower_min = (row as f64 - 1.0) / height as f64;
        let lower_max = (row as f64 - 0.5) / height as f64;
        let upper_min = (row as f64 - 0.5) / height as f64;
        let upper_max = row as f64 / height as f64;
        out.push('│');
        for index in 0..num_points {
            let total: u64 = categories
                .iter()
                .map(|(_, _, data)| data.get(index).copied().unwrap_or(0))
                .sum();
            if total == 0 {
                out.push(' ');
                continue;
            }

            let upper_cat = stacked_pixel_category(&categories, index, total, upper_min, upper_max);
            let lower_cat = stacked_pixel_category(&categories, index, total, lower_min, lower_max);
            match (upper_cat, lower_cat) {
                (Some(upper), Some(lower)) if upper == lower => {
                    let color = &categories[upper].1;
                    out.push_str(&format!("`FT{color}`BT{color}█`f`b"));
                }
                (Some(upper), Some(lower)) => {
                    let upper_color = &categories[upper].1;
                    let lower_color = &categories[lower].1;
                    out.push_str(&format!("`FT{upper_color}`BT{lower_color}▀`f`b"));
                }
                (Some(upper), None) => {
                    let color = &categories[upper].1;
                    out.push_str(&format!("`FT{color}▀`f"));
                }
                (None, Some(lower)) => {
                    let color = &categories[lower].1;
                    out.push_str(&format!("`FT{color}▄`f"));
                }
                (None, None) => out.push(' '),
            }
        }
        out.push('\n');
    }
    out.push('└');
    for _ in 0..num_points {
        out.push('─');
    }
    out.push_str("┘\n");
    out.push_str(&format!(
        "`F666{:<12}`f",
        labels[0].chars().take(12).collect::<String>()
    ));
    let chart_width = num_points + 2;
    let spacing = chart_width.saturating_sub(24);
    out.push_str(&" ".repeat(spacing));
    out.push_str(&format!(
        "`F666{:>12}`f\n",
        labels[1].chars().take(12).collect::<String>()
    ));
    out
}

fn stacked_pixel_category(
    categories: &[(&str, String, &[u64])],
    index: usize,
    total: u64,
    pixel_min: f64,
    pixel_max: f64,
) -> Option<usize> {
    let mut cumulative = 0u64;
    for (category_index, (_, _, data)) in categories.iter().enumerate() {
        let value = data.get(index).copied().unwrap_or(0);
        if value == 0 {
            continue;
        }
        let start = cumulative as f64 / total as f64;
        cumulative += value;
        let end = cumulative as f64 / total as f64;
        if pixel_min < end && pixel_max > start {
            return Some(category_index);
        }
    }
    None
}

fn dim_to_black(color: &str, dim: f64) -> String {
    gradient_chart_color(&expand_chart_color(color), "000000", dim, 1.0)
}

fn accessible_groups(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut groups = BTreeMap::new();
    if !config.repositories_dir.exists() {
        return Ok(groups);
    }
    for group_entry in fs::read_dir(&config.repositories_dir)? {
        let group_entry = group_entry?;
        if !group_entry.file_type()?.is_dir() {
            continue;
        }
        let group = group_entry.file_name().to_string_lossy().to_string();
        if validate_group_name(&group).is_err() {
            continue;
        }
        let repos = accessible_repositories(config, access, remote, &group)?;
        if !repos.is_empty() {
            groups.insert(group, repos);
        }
    }
    Ok(groups)
}

fn accessible_repositories(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    group: &str,
) -> Result<Vec<String>> {
    validate_group_name(group)?;
    let group_dir = config.repositories_dir.join(group);
    let mut repos = Vec::new();
    if !group_dir.exists() {
        return Ok(repos);
    }
    for repo_entry in fs::read_dir(group_dir)? {
        let repo_entry = repo_entry?;
        if !repo_entry.file_type()?.is_dir() {
            continue;
        }
        let repo = repo_entry.file_name().to_string_lossy().to_string();
        let Ok(name) = repository_name(group, &repo) else {
            continue;
        };
        if crate::git::is_bare_repository(&config.repositories_dir.join(&name))
            && access.allows(Operation::Read, &name, remote)?
        {
            repos.push(repo);
        }
    }
    repos.sort();
    Ok(repos)
}

fn accessible_repository(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<(String, String, PathBuf)> {
    let group = required_var(vars, "g")?;
    let repo = required_var(vars, "r")?;
    let name = repository_name(group, repo)?;
    let path = config.repositories_dir.join(&name);
    if !crate::git::is_bare_repository(&path) || !access.allows(Operation::Read, &name, remote)? {
        return Err(Error::msg("repository not found"));
    }
    Ok((group.to_string(), repo.to_string(), path))
}

fn required_var<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    var(vars, key).ok_or_else(|| Error::msg(format!("missing page variable {key}")))
}

fn decode_url_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
                {
                    out.push((high << 4) | low);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn var<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    vars.get(&format!("var_{key}"))
        .or_else(|| vars.get(key))
        .map(String::as_str)
}

fn repository_name(group: &str, repo: &str) -> Result<String> {
    validate_group_name(group)?;
    validate_repo_component(repo)?;
    let name = format!("{group}/{repo}");
    validate_repo_name(&name)?;
    Ok(name)
}

fn validate_group_name(group: &str) -> Result<()> {
    validate_repo_component(group)
}

fn validate_repo_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.len() > 256
    {
        Err(Error::msg("invalid repository name"))
    } else {
        Ok(())
    }
}

fn validate_git_path(path: &str) -> Result<()> {
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::msg("invalid repository path"));
    }
    for component in path.split('/') {
        if component == "." || component == ".." {
            return Err(Error::msg("invalid repository path"));
        }
    }
    Ok(())
}

fn normalize_blob_path(path: &str) -> String {
    path.trim_start_matches(['.', '/'])
        .split('/')
        .filter(|component| *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_refish(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains("..")
        || value.contains('\\')
        || value.contains(' ')
        || value.contains('~')
        || value.contains('^')
        || value.contains(':')
    {
        Err(Error::msg("invalid git ref"))
    } else {
        Ok(())
    }
}

fn repository_description(repo: &Path) -> Result<String> {
    let path = repo.join("description");
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(path)?.trim().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryOrigin {
    kind: RepositoryOriginKind,
    source: String,
    synced_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RepositoryOriginKind {
    Fork,
    Mirror,
}

impl RepositoryOrigin {
    fn label(&self) -> &'static str {
        match self.kind {
            RepositoryOriginKind::Fork => "Forked",
            RepositoryOriginKind::Mirror => "Mirrored",
        }
    }
}

fn repository_origin(repo: &Path) -> Result<Option<RepositoryOrigin>> {
    let kind_output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.type"),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !kind_output.status.success() {
        return Ok(None);
    }
    let kind = match String::from_utf8_lossy(&kind_output.stdout).trim() {
        "fork" => RepositoryOriginKind::Fork,
        "mirror" => RepositoryOriginKind::Mirror,
        _ => return Ok(None),
    };
    let source_output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.upstream.source"),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !source_output.status.success() {
        return Ok(None);
    }
    let source = String::from_utf8_lossy(&source_output.stdout)
        .trim()
        .to_string();
    if source.is_empty() {
        return Ok(None);
    }
    let synced_at = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.upstream.sync"),
        GIT_COMMAND_TIMEOUT,
    )
    .ok()
    .and_then(|output| output.status.success().then_some(output))
    .and_then(|output| {
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
    });

    Ok(Some(RepositoryOrigin {
        kind,
        source,
        synced_at,
    }))
}

fn format_sync_age(synced_at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds = now.saturating_sub(synced_at);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn repository_thanks(repo: &Path, add: bool) -> Result<u64> {
    let path = repo.with_extension("thanks");
    let mut count = if path.exists() {
        fs::read_to_string(&path)?
            .trim()
            .parse::<u64>()
            .unwrap_or(0)
    } else {
        0
    };
    if add {
        count = count.saturating_add(1);
        fs::write(path, format!("{count}\n"))?;
    }
    Ok(count)
}

#[derive(Debug)]
struct ReadmeContent {
    content: String,
    markdown: bool,
}

fn readme_content(repo: &Path) -> Result<Option<ReadmeContent>> {
    const NAMES: &[&str] = &[
        "README.mu",
        "Readme.mu",
        "readme.mu",
        "README",
        "readme",
        "README.md",
        "readme.md",
        "README.rst",
        "README.txt",
        "readme.rst",
        "readme.txt",
    ];
    for name in NAMES {
        match run_git_output(
            Command::new("git")
                .arg("--git-dir")
                .arg(repo)
                .arg("show")
                .arg(format!("HEAD:{name}")),
            GIT_COMMAND_TIMEOUT,
        ) {
            Ok(output) if output.status.success() => {
                let content = String::from_utf8_lossy(&output.stdout).into_owned();
                let markdown = name.ends_with(".md");
                let content = if markdown || name.ends_with(".mu") {
                    content
                } else {
                    m_escape(&content)
                };
                return Ok(Some(ReadmeContent { content, markdown }));
            }
            Ok(_) => {}
            Err(err) => {
                log::warn!("Git command execution failed while reading README: {err}");
            }
        }
    }
    Ok(None)
}

fn markdown_to_micron(input: &str) -> String {
    markdown_to_micron_scoped(input, None)
}

fn markdown_to_micron_scoped(input: &str, url_scope: Option<&str>) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut out = String::new();
    let mut code_block: Option<(Option<String>, String)> = None;
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if let Some((language, content)) = code_block.take() {
                out.push_str(&markdown_code_block_to_micron(
                    language.as_deref(),
                    &content,
                ));
            } else {
                code_block = Some((markdown_fence_language(trimmed), String::new()));
            }
            index += 1;
            continue;
        }
        if let Some((_, content)) = code_block.as_mut() {
            content.push_str(line);
            content.push('\n');
            index += 1;
            continue;
        }
        if let Some(quote) = markdown_quote(line) {
            let mut parts = vec![quote.to_string()];
            index += 1;
            while index < lines.len() {
                if let Some(quote) = markdown_quote(lines[index]) {
                    parts.push(quote.to_string());
                    index += 1;
                } else {
                    break;
                }
            }
            let formatted = format_markdown_inline_scoped(&parts.join(" "), url_scope);
            for wrapped in markdown_wrap_text(&formatted, 77) {
                out.push_str(" │ ");
                out.push_str(&wrapped);
                out.push('\n');
            }
            continue;
        }
        if is_table_start(&lines, index) {
            let mut table = Vec::new();
            while index < lines.len() && lines[index].contains('|') {
                table.push(lines[index]);
                index += 1;
            }
            out.push_str(&format_markdown_table(&table, url_scope));
            continue;
        }
        if let Some((level, text)) = markdown_heading(line) {
            out.push_str(&">".repeat(level));
            out.push_str(&format_markdown_inline_scoped(text.trim(), url_scope));
            out.push('\n');
        } else if is_markdown_rule(trimmed) {
            out.push_str("-\n");
        } else if let Some((indent, text)) = unordered_list_item(line) {
            out.push_str(indent);
            out.push_str(" • ");
            out.push_str(&format_markdown_inline_scoped(text, url_scope));
            out.push('\n');
        } else if let Some((indent, number, text)) = ordered_list_item(line) {
            out.push_str(indent);
            out.push_str(number);
            out.push_str(". ");
            out.push_str(&format_markdown_inline_scoped(text, url_scope));
            out.push('\n');
        } else {
            out.push_str(&format_markdown_line(line, url_scope));
            out.push('\n');
        }
        index += 1;
    }
    if let Some((language, content)) = code_block {
        out.push_str(&markdown_code_block_to_micron(
            language.as_deref(),
            &content,
        ));
    }

    out
}

fn markdown_code_block_to_micron(language: Option<&str>, content: &str) -> String {
    if language.is_some_and(|language| language.eq_ignore_ascii_case("rawmu")) {
        return content.to_string();
    }
    crate::highlight::literal_block(content, None, language)
}

fn markdown_fence_language(trimmed: &str) -> Option<String> {
    trimmed
        .strip_prefix("```")
        .and_then(|info| info.split_whitespace().next())
        .filter(|language| !language.is_empty())
        .map(str::to_string)
}

fn markdown_quote(line: &str) -> Option<&str> {
    line.strip_prefix('>')
        .map(|quote| quote.strip_prefix(' ').unwrap_or(quote))
}

fn markdown_heading(line: &str) -> Option<(usize, &str)> {
    let level = line.chars().take_while(|ch| *ch == '#').count();
    if (1..=6).contains(&level) && line.as_bytes().get(level) == Some(&b' ') {
        Some((level, &line[level + 1..]))
    } else {
        None
    }
}

fn is_markdown_rule(trimmed: &str) -> bool {
    trimmed.len() >= 3
        && ["-", "*", "_", "="]
            .iter()
            .any(|marker| trimmed.chars().all(|ch| ch.to_string() == *marker))
}

fn unordered_list_item(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    for marker in ["- ", "* ", "+ "] {
        if let Some(text) = trimmed.strip_prefix(marker) {
            return Some((indent, text));
        }
    }
    None
}

fn ordered_list_item(line: &str) -> Option<(&str, &str, &str)> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let Some((number, text)) = trimmed.split_once(". ") else {
        return None;
    };
    if !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit()) {
        Some((indent, number, text))
    } else {
        None
    }
}

fn format_markdown_line(line: &str, url_scope: Option<&str>) -> String {
    let formatted = format_markdown_inline_scoped(line, url_scope);
    if (line.starts_with('-') && !line.starts_with("---") && !line.starts_with("- "))
        || line.starts_with('<')
    {
        format!("\\{formatted}")
    } else {
        formatted
    }
}

fn is_table_start(lines: &[&str], index: usize) -> bool {
    index + 1 < lines.len()
        && lines[index].contains('|')
        && lines[index + 1].contains('|')
        && is_table_separator(lines[index + 1])
}

fn is_table_separator(line: &str) -> bool {
    parse_table_row(line)
        .iter()
        .all(|cell| !cell.is_empty() && cell.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
}

#[derive(Clone, Copy)]
enum TableAlign {
    Left,
    Right,
    Center,
}

fn format_markdown_table(lines: &[&str], url_scope: Option<&str>) -> String {
    if lines.len() < 2 {
        return String::new();
    }
    let header: Vec<String> = parse_table_row(lines[0])
        .into_iter()
        .map(|cell| format_markdown_inline_scoped(cell.trim(), url_scope))
        .collect();
    if header.is_empty() {
        return String::new();
    }
    let columns = header.len();
    let mut alignments = parse_table_alignments(lines[1]);
    while alignments.len() < columns {
        alignments.push(TableAlign::Left);
    }
    alignments.truncate(columns);

    let rows: Vec<Vec<String>> = lines
        .iter()
        .skip(2)
        .map(|line| {
            let mut row: Vec<String> = parse_table_row(line)
                .into_iter()
                .map(|cell| format_markdown_inline_scoped(cell.trim(), url_scope))
                .collect();
            while row.len() < columns {
                row.push(String::new());
            }
            row.truncate(columns);
            row
        })
        .collect();

    let mut widths = vec![3; columns];
    for (index, cell) in header.iter().enumerate() {
        widths[index] = widths[index].max(markdown_visible_width(cell));
    }
    for row in &rows {
        for (index, cell) in row.iter().enumerate().take(columns) {
            widths[index] = widths[index].max(markdown_visible_width(cell));
        }
    }

    let mut out = String::new();
    out.push_str(&table_border('┌', '┬', '┐', &widths));
    out.push_str(&table_row(
        &header,
        &widths,
        &vec![TableAlign::Left; columns],
    ));
    out.push_str(&table_border('├', '┼', '┤', &widths));
    for row in rows {
        out.push_str(&table_row(&row, &widths, &alignments));
    }
    out.push_str(&table_border('└', '┴', '┘', &widths));
    out
}

fn parse_table_row(line: &str) -> Vec<String> {
    let mut trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix('|') {
        trimmed = rest;
    }
    if let Some(rest) = trimmed.strip_suffix('|') {
        trimmed = rest;
    }
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in trimmed.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            cells.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    cells.push(current.trim().to_string());
    cells
}

fn parse_table_alignments(line: &str) -> Vec<TableAlign> {
    parse_table_row(line)
        .into_iter()
        .map(|cell| {
            let cell = cell.trim();
            if cell.starts_with(':') && cell.ends_with(':') {
                TableAlign::Center
            } else if cell.ends_with(':') {
                TableAlign::Right
            } else {
                TableAlign::Left
            }
        })
        .collect()
}

fn table_border(left: char, middle: char, right: char, widths: &[usize]) -> String {
    let mut out = String::new();
    out.push(left);
    for (index, width) in widths.iter().enumerate() {
        out.push_str(&"─".repeat(width + 2));
        if index + 1 == widths.len() {
            out.push(right);
        } else {
            out.push(middle);
        }
    }
    out.push('\n');
    out
}

fn table_row(cells: &[String], widths: &[usize], alignments: &[TableAlign]) -> String {
    let mut out = String::from("│");
    for (index, width) in widths.iter().enumerate() {
        let cell = cells.get(index).map(String::as_str).unwrap_or("");
        out.push(' ');
        out.push_str(&pad_table_cell(
            cell,
            *width,
            alignments.get(index).copied().unwrap_or(TableAlign::Left),
        ));
        out.push(' ');
        out.push('│');
    }
    out.push('\n');
    out
}

fn pad_table_cell(cell: &str, width: usize, alignment: TableAlign) -> String {
    let visible = markdown_visible_width(cell);
    let padding = width.saturating_sub(visible);
    match alignment {
        TableAlign::Left => format!("{cell}{}", " ".repeat(padding)),
        TableAlign::Right => format!("{}{cell}", " ".repeat(padding)),
        TableAlign::Center => {
            let left = padding / 2;
            let right = padding - left;
            format!("{}{cell}{}", " ".repeat(left), " ".repeat(right))
        }
    }
}

fn markdown_visible_width(value: &str) -> usize {
    let mut width = 0;
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '`' {
            if matches!(chars.peek(), Some('F') | Some('B')) {
                chars.next();
                if matches!(chars.peek(), Some('T')) {
                    chars.next();
                    for _ in 0..6 {
                        chars.next();
                    }
                } else {
                    for _ in 0..3 {
                        chars.next();
                    }
                }
                continue;
            }
            if matches!(chars.peek(), Some('!') | Some('*') | Some('_') | Some('=')) {
                chars.next();
                continue;
            }
            if matches!(chars.peek(), Some('f') | Some('b') | Some('a')) {
                chars.next();
                continue;
            }
            if matches!(chars.peek(), Some('[')) {
                let mut label_width = 0;
                for link_ch in chars.by_ref() {
                    if link_ch == '`' {
                        for target_ch in chars.by_ref() {
                            if target_ch == ']' {
                                break;
                            }
                        }
                        break;
                    }
                    label_width += 1;
                }
                width += label_width;
                continue;
            }
        }
        width += 1;
    }
    width
}

fn markdown_wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    for word in text.split_whitespace() {
        let word_width = markdown_visible_width(word);
        if !current.is_empty() && current_width + 1 + word_width > width {
            lines.push(current);
            current = String::new();
            current_width = 0;
        }
        if !current.is_empty() {
            current.push(' ');
            current_width += 1;
        }
        current.push_str(word);
        current_width += word_width;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[derive(Debug)]
enum InlineToken {
    Link { label: String, target: String },
    Code(String),
}

#[derive(Debug, Clone, Copy)]
struct MarkdownLinkStyle<'a> {
    bold: bool,
    underline: bool,
    color: Option<&'a str>,
}

impl Default for MarkdownLinkStyle<'_> {
    fn default() -> Self {
        Self {
            bold: true,
            underline: true,
            color: None,
        }
    }
}

fn format_markdown_inline_scoped(input: &str, url_scope: Option<&str>) -> String {
    let (with_placeholders, tokens) = extract_markdown_inline_tokens(input);
    let escaped = m_escape(&with_placeholders);
    let styled = apply_markdown_style(&escaped, "**", "`!", "`!");
    let styled = apply_markdown_style(&styled, "__", "`!", "`!");
    let styled = apply_markdown_style(&styled, "*", "`*", "`*");
    let styled = apply_markdown_style(&styled, "_", "`*", "`*");
    restore_markdown_inline_tokens(&styled, &tokens, url_scope)
}

fn extract_markdown_inline_tokens(input: &str) -> (String, Vec<InlineToken>) {
    let mut out = String::new();
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < input.len() {
        let rest = &input[index..];
        if rest.starts_with('`') {
            if let Some(end) = rest[1..].find('`') {
                let content = &rest[1..1 + end];
                if is_markdown_inline_code(content) {
                    tokens.push(InlineToken::Code(content.to_string()));
                    out.push_str(&markdown_token_placeholder(tokens.len() - 1));
                    index += end + 2;
                    continue;
                }
            }
        }
        if rest.starts_with('[') {
            if let Some((consumed, label, target)) = parse_markdown_link(rest) {
                tokens.push(InlineToken::Link { label, target });
                out.push_str(&markdown_token_placeholder(tokens.len() - 1));
                index += consumed;
                continue;
            }
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        out.push(ch);
        index += ch.len_utf8();
    }

    (out, tokens)
}

fn is_markdown_inline_code(content: &str) -> bool {
    !content.is_empty()
        && !content
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '!' | '*' | '_' | '=' | 'F' | 'B' | 'f' | 'b' | 'a'))
}

fn parse_markdown_link(input: &str) -> Option<(usize, String, String)> {
    let label_end = input[1..].find(']')? + 1;
    if !input[label_end + 1..].starts_with('(') {
        return None;
    }
    let target_start = label_end + 2;
    let target_end = input[target_start..].find(')')? + target_start;
    Some((
        target_end + 1,
        input[1..label_end].replace('`', ""),
        input[target_start..target_end].to_string(),
    ))
}

fn markdown_token_placeholder(index: usize) -> String {
    format!("\u{1f}{index}\u{1f}")
}

fn restore_markdown_inline_tokens(
    input: &str,
    tokens: &[InlineToken],
    url_scope: Option<&str>,
) -> String {
    let mut out = input.to_string();
    for (index, token) in tokens.iter().enumerate() {
        let replacement = match token {
            InlineToken::Link { label, target } => {
                format_markdown_link(label, target, url_scope, MarkdownLinkStyle::default())
            }
            InlineToken::Code(value) => format!("`BT383838`Fddd{}`f`b", m_escape(value)),
        };
        out = out.replace(&markdown_token_placeholder(index), &replacement);
    }
    out
}

fn format_markdown_link(
    label: &str,
    target: &str,
    url_scope: Option<&str>,
    style: MarkdownLinkStyle<'_>,
) -> String {
    let mut link = String::new();
    if style.underline {
        link.push_str("`_");
    }
    if style.bold {
        link.push_str("`!");
    }
    link.push_str("`[");
    link.push_str(sanitize_label(label).trim());
    link.push('`');
    link.push_str(&markdown_link_target(target, url_scope));
    link.push(']');
    if style.bold {
        link.push_str("`!");
    }
    if style.underline {
        link.push_str("`_");
    }

    match style.color {
        Some(color) if color.len() == 3 => format!("`F{color}{link}`f"),
        Some(color) if color.len() == 6 => format!("`FT{color}{link}`f"),
        _ => link,
    }
}

fn markdown_link_target(value: &str, url_scope: Option<&str>) -> String {
    if let Some(scope) = url_scope {
        if !value.contains(":/") {
            let (path, anchor) = value
                .split_once('#')
                .map(|(path, anchor)| (path, Some(anchor)))
                .unwrap_or((value, None));
            let mut out = format!("{scope}{}", sanitize_field(path));
            if let Some(anchor) = anchor.filter(|anchor| !anchor.is_empty()) {
                out.push_str("|anchor=");
                out.push_str(&sanitize_field(anchor));
            }
            return out;
        }
    }
    sanitize_markdown_link_target(value)
}

fn sanitize_markdown_link_target(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '[' && *ch != ']' && *ch != '`')
        .collect()
}

fn apply_markdown_style(input: &str, marker: &str, open: &str, close: &str) -> String {
    let mut out = String::new();
    let mut rest = input;

    while let Some(start) = rest.find(marker) {
        let content_start = start + marker.len();
        let Some(end) = rest[content_start..].find(marker) else {
            out.push_str(rest);
            return out;
        };
        let content_end = content_start + end;
        out.push_str(&rest[..start]);
        out.push_str(open);
        out.push_str(&rest[content_start..content_end]);
        out.push_str(close);
        rest = &rest[content_end + marker.len()..];
    }
    out.push_str(rest);
    out
}

#[derive(Debug)]
struct Refs {
    heads: Vec<RefInfo>,
    tags: Vec<RefInfo>,
}

#[derive(Debug)]
struct RefInfo {
    sha: String,
    name: String,
}

fn git_refs(repo: &Path) -> Result<Refs> {
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .args(["for-each-ref", "--format=%(objectname) %(refname)"]),
    )?;
    let mut refs = Refs {
        heads: Vec::new(),
        tags: Vec::new(),
    };
    for line in output.lines() {
        let Some((sha, name)) = line.split_once(' ') else {
            continue;
        };
        if let Some(short) = name.strip_prefix("refs/heads/") {
            refs.heads.push(RefInfo {
                sha: sha.to_string(),
                name: short.to_string(),
            });
        } else if let Some(short) = name.strip_prefix("refs/tags/") {
            refs.tags.push(RefInfo {
                sha: sha.to_string(),
                name: short.to_string(),
            });
        }
    }
    Ok(refs)
}

fn resolve_ref(repo: &Path, reference: &str) -> Result<String> {
    validate_refish(reference)?;
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("rev-parse")
            .arg("--verify")
            .arg(format!("{reference}^{{commit}}")),
    )?;
    Ok(output.trim().to_string())
}

#[derive(Debug)]
struct TreeEntry {
    kind: String,
    name: String,
    size: Option<u64>,
}

impl TreeEntry {
    fn size_label(&self) -> String {
        self.size
            .map(|size| format!(" ({size} bytes)"))
            .unwrap_or_default()
    }
}

fn tree_entries(repo: &Path, reference: &str, path: &str) -> Result<Vec<TreeEntry>> {
    validate_git_path(path)?;
    let spec = if path.is_empty() {
        reference.to_string()
    } else {
        format!("{reference}:{path}")
    };
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("ls-tree")
            .arg("-l")
            .arg(spec),
    )?;
    let mut entries = Vec::new();
    for line in output.lines() {
        let Some((meta, name)) = line.split_once('\t') else {
            continue;
        };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let size = parts[3].parse::<u64>().ok();
        entries.push(TreeEntry {
            kind: parts[1].to_string(),
            name: name.to_string(),
            size,
        });
    }
    entries.sort_by_key(|entry| (entry.kind != "tree", entry.name.to_ascii_lowercase()));
    Ok(entries)
}

fn git_object_kind(repo: &Path, reference: &str, path: &str) -> Result<String> {
    validate_git_path(path)?;
    let spec = if path.is_empty() {
        reference.to_string()
    } else {
        format!("{reference}:{path}")
    };
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-t")
            .arg(spec),
    )?;
    Ok(output.trim().to_string())
}

struct BlobInfo {
    content: String,
    size: u64,
    binary: bool,
    displayable: bool,
}

fn blob_info(repo: &Path, reference: &str, path: &str) -> Result<BlobInfo> {
    validate_git_path(path)?;
    let spec = format!("{reference}:{path}");
    let size = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-s")
            .arg(&spec),
    )?
    .trim()
    .parse::<u64>()
    .unwrap_or(0);
    if size > 256 * 1024 {
        return Ok(BlobInfo {
            content: format!("File is too large to display ({size} bytes)."),
            size,
            binary: false,
            displayable: false,
        });
    }
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("show")
            .arg(spec),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    let binary = output.stdout.contains(&0);
    Ok(BlobInfo {
        content: if binary {
            "Binary file is not displayed.".to_string()
        } else {
            String::from_utf8_lossy(&output.stdout).into_owned()
        },
        size,
        binary,
        displayable: !binary,
    })
}

#[derive(Debug)]
struct CommitSummary {
    hash: String,
    subject: String,
    author: String,
    timestamp: i64,
}

fn commits(repo: &Path, reference: &str, limit: usize) -> Result<Vec<CommitSummary>> {
    let format = "%H%x1f%s%x1f%an%x1f%at";
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("log")
            .arg(format!("--format={format}"))
            .arg("-n")
            .arg(limit.to_string())
            .arg(reference),
    )?;
    let mut commits = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\x1f').collect();
        if parts.len() == 4 {
            commits.push(CommitSummary {
                hash: parts[0].to_string(),
                subject: parts[1].to_string(),
                author: parts[2].to_string(),
                timestamp: parts[3].parse().unwrap_or_default(),
            });
        }
    }
    Ok(commits)
}

#[derive(Debug)]
struct CommitInfo {
    hash: String,
    subject: String,
    body: String,
    author: String,
    email: String,
    timestamp: i64,
    files: Vec<CommitFile>,
}

#[derive(Debug)]
struct CommitFile {
    status: String,
    path: String,
}

fn commit_info(repo: &Path, hash: &str) -> Result<CommitInfo> {
    validate_refish(hash)?;
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("show")
            .arg("--no-patch")
            .arg("--format=%H%x1f%s%x1f%an%x1f%ae%x1f%at%x1f%B")
            .arg(hash),
    )?;
    let parts: Vec<&str> = output.splitn(6, '\x1f').collect();
    if parts.len() != 6 {
        return Err(Error::msg("invalid commit output"));
    }
    let files_output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("diff-tree")
            .arg("--root")
            .arg("--no-commit-id")
            .arg("--name-status")
            .arg("-r")
            .arg(hash),
    )?;
    let mut files = Vec::new();
    for line in files_output.lines() {
        let Some((status, path)) = line.split_once('\t') else {
            continue;
        };
        files.push(CommitFile {
            status: status.to_string(),
            path: path.to_string(),
        });
    }
    Ok(CommitInfo {
        hash: parts[0].trim().to_string(),
        subject: parts[1].trim().to_string(),
        author: parts[2].trim().to_string(),
        email: parts[3].trim().to_string(),
        timestamp: parts[4].trim().parse().unwrap_or_default(),
        body: parts[5].trim().to_string(),
        files,
    })
}

fn raw_commit_object(repo: &Path, hash: &str) -> Result<Vec<u8>> {
    validate_refish(hash)?;
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-p")
            .arg(hash),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    Ok(output.stdout)
}

fn run_git(cmd: &mut Command) -> Result<String> {
    let output = run_git_output(cmd, GIT_COMMAND_TIMEOUT)?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_git_output(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let deadline = Instant::now() + timeout;

    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map_err(Error::from);
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            log::warn!("Git command execution timed out");
            return Err(Error::msg("Git command execution timed out"));
        }

        let sleep_for = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Access;
    use crate::config::ServerConfig;
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
        run_git(Command::new("git").arg("--git-dir").arg(&repo).args([
            "tag",
            "v1",
            "refs/heads/main",
        ]));
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
        #[cfg(feature = "syntax-highlighting")]
        assert!(blob.contains("`FT"));
        #[cfg(not(feature = "syntax-highlighting"))]
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
        let armored =
            crate::commitsigs::sign_message(&identity, signed_content.as_bytes()).unwrap();
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
        let out =
            markdown_to_micron("literal `!not bold`! and [bad`label](rns://abc`def) plus `raw`");
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
        #[cfg(feature = "syntax-highlighting")]
        assert!(out.contains("`FT"));
        #[cfg(not(feature = "syntax-highlighting"))]
        assert!(out.contains("`=\n**not bold** and \\`not inline\\`\n`=\n"));
        assert!(!out.contains("`!not bold`!"));
        assert!(out.contains("Unmatched * marker"));
        assert!(out.contains("1. numbered"));
    }

    #[cfg(feature = "syntax-highlighting")]
    #[test]
    fn rust_blob_page_uses_syntax_highlighting_and_escapes_source() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        create_repo(
            config.repositories_dir.join("public/highlighted"),
            "src/lib.rs",
            "pub fn `answer`() -> u8 { 42 }\n",
        );
        let access = access(&config);

        let blob = render_page(
            PATH_BLOB,
            &config,
            &access,
            &page_request(&[
                ("var_g", "public"),
                ("var_r", "highlighted"),
                ("var_path", "src/lib.rs"),
            ]),
            None,
        )
        .unwrap();

        assert!(blob.contains("`FT"));
        assert!(blob.contains("\\`"));
        assert!(blob.contains("answer"));
    }

    #[cfg(feature = "syntax-highlighting")]
    #[test]
    fn markdown_readme_rust_fence_uses_syntax_highlighting() {
        let tmp = tempfile::tempdir().unwrap();
        let config = cfg(tmp.path());
        create_repo(
            config.repositories_dir.join("public/readme-code"),
            "README.md",
            "# Example\n\n```rust\npub fn `answer`() -> u8 { 42 }\n```\n",
        );
        let access = access(&config);

        let page = render_page(
            PATH_REPO,
            &config,
            &access,
            &page_request(&[("var_g", "public"), ("var_r", "readme-code")]),
            None,
        )
        .unwrap();

        assert!(page.contains("`FT"));
        assert!(page.contains("\\`"));
        assert!(page.contains("answer"));
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

    #[cfg(not(feature = "syntax-highlighting"))]
    #[test]
    fn feature_off_renders_plain_literal_blocks() {
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
        assert!(active.contains(">Active Work Documents (1)"));
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
        assert!(completed_page.contains(">Completed Work Documents (1)"));
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
        }
    }

    fn create_repo(path: std::path::PathBuf, file: &str, content: &str) -> std::path::PathBuf {
        create_repo_bytes(path, file, content.as_bytes())
    }

    fn create_repo_bytes(
        path: std::path::PathBuf,
        file: &str,
        content: &[u8],
    ) -> std::path::PathBuf {
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
}
