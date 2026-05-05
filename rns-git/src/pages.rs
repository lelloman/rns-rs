use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rns_core::msgpack::{self, Value};
use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{Destination, RnsNode};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
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

    let access = Access::new(
        &config.allow_read,
        &config.allow_write,
        &config.allow_create,
        &config.allow_stats,
        config.repositories_dir.clone(),
    )?;
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
    let content = match path {
        PATH_INDEX => render_front_page(config, access, remote)?,
        PATH_GROUP => render_group_page(config, access, remote, &vars)?,
        PATH_REPO => render_repo_page(config, access, remote, &vars)?,
        PATH_TREE => render_tree_page(config, access, remote, &vars)?,
        PATH_BLOB => render_blob_page(config, access, remote, &vars)?,
        PATH_COMMITS => render_commits_page(config, access, remote, &vars)?,
        PATH_COMMIT => render_commit_page(config, access, remote, &vars)?,
        PATH_REFS => render_refs_page(config, access, remote, &vars)?,
        PATH_STATS => render_stats_page(config, access, remote, &vars)?,
        _ => return Err(Error::msg("unknown page path")),
    };
    record_page_view(path, config, &vars, remote);
    Ok(render_template(&config.node_name, &content))
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
        PATH_REPO | PATH_TREE | PATH_BLOB | PATH_COMMITS | PATH_COMMIT | PATH_REFS => {
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

fn render_template(node_name: &str, content: &str) -> String {
    format!(
        "#!c=0\n>{}\n\n{}\n<\n-\n`a`F666{} - Generated by rngit`f\n",
        m_escape(node_name),
        content,
        m_link_raw("Served by rngit", PATH_INDEX, &[])
    )
}

fn error_page(node_name: &str, message: &str) -> Vec<u8> {
    render_template(node_name, &format!(">Error\n\n{message}\n")).into_bytes()
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
    value.replace('`', "\\`")
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
    let refs = git_refs(&repository)?;
    let readme = readme_content(&repository)?;
    let repo_url = format!("rns://<repository-destination>/{group}/{repo}");

    let branch_count = refs.heads.len().to_string();
    let tag_count = refs.tags.len().to_string();
    let mut out = format!(
        ">>\n{} / {} / {} `F666{}`f\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_escape(&repo),
        m_escape(&repo_url)
    );
    if !description.is_empty() {
        out.push_str(&format!("{}\n\n", m_escape(&description)));
    }
    let mut nav_links = vec![
        m_link_raw(
            "Files",
            PATH_TREE,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            "Commits",
            PATH_COMMITS,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            &format!("Branches ({branch_count})"),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "heads")],
        ),
        m_link_raw(
            &format!("Tags ({tag_count})"),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "tags")],
        ),
    ];
    if access.allows(Operation::Stats, &format!("{group}/{repo}"), remote)? {
        nav_links.push(m_link_raw(
            "Stats",
            PATH_STATS,
            &[("g", &group), ("r", &repo)],
        ));
    }
    out.push_str(&format!("{}\n\n", nav_links.join(" • ")));
    if let Some(readme) = readme {
        if !readme.content.trim_start().starts_with('>') {
            out.push_str("-\n");
        }
        if readme.markdown {
            out.push_str(&markdown_to_micron(&readme.content));
        } else {
            out.push_str(&readme.content);
        }
        if !out.ends_with('\n') {
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
                let label = format!("{}/", entry.name);
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
                out.push_str(&format!(
                    "{} {}\n",
                    m_link_raw(
                        &entry.name,
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
    let path = required_var(vars, "path")?;
    validate_git_path(path)?;
    let resolved = resolve_ref(&repository, reference)?;
    let blob = blob_info(&repository, &resolved, path)?;
    let renderable = renderable_blob(path);
    let raw_requested = var(vars, "raw").is_some();
    let render_requested = var(vars, "render").is_some();
    let render =
        renderable.is_some() && !raw_requested && (render_requested || render_by_default(path));
    let controls = renderable.map(|_| {
        let render_link = m_link(
            "View rendered",
            PATH_BLOB,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path),
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
                ("path", path),
                ("raw", "y"),
            ],
        );
        if render {
            format!("Displaying Rendered • {raw_link}")
        } else {
            format!("Displaying Raw • {render_link}")
        }
    });
    let content = if !blob.displayable {
        crate::highlight::plain_literal_block(&blob.content)
    } else if render {
        match renderable {
            Some(RenderableBlob::Markdown) => markdown_to_micron(&blob.content),
            Some(RenderableBlob::Micron) => {
                let mut out = blob.content.clone();
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out
            }
            None => crate::highlight::literal_block(&blob.content, Some(path), None),
        }
    } else {
        crate::highlight::literal_block(&blob.content, Some(path), None)
    };
    let controls = controls
        .map(|controls| format!("{controls}\n\n"))
        .unwrap_or_default();
    Ok(format!(
        ">>\n{} / {} / {} / {}\n\n>{} `F666{} ({}, {})`f\n\n{}{}",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(path),
        m_escape(path),
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
                    &[("g", &group), ("r", &repo), ("h", &commit.hash)]
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
    let hash = required_var(vars, "h")?;
    validate_refish(hash)?;
    let commit = commit_info(&repository, hash)?;
    let mut out = format!(
        ">>\n{} / {} / {} / commit {}\n\n>Commit {}\n\n{}\nAuthor: {} <{}>\nDate: {}\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        &commit.hash[..7],
        commit.hash,
        m_escape(&commit.subject),
        m_escape(&commit.author),
        m_escape(&commit.email),
        format_unix_time(commit.timestamp)
    );
    if !commit.body.is_empty() {
        out.push_str(&format!("\n{}\n", m_escape(&commit.body)));
    }
    out.push_str("\n>Files changed\n\n");
    for file in commit.files {
        out.push_str(&format!("{} {}\n", file.status, m_escape(&file.path)));
    }
    Ok(out)
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
        ">>\n{} / {} / {}\n\n>Stats for {}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(&stats.repository)
    );
    out.push_str(&format!(
        "`F66dViews`f    : {:>5}  total `F666(peak: {:>3})`f\n",
        stats.views.total, stats.views.peak
    ));
    out.push_str(&format!(
        "`F0a0Fetches`f  : {:>5}  total `F666(peak: {:>3})`f\n",
        stats.fetches.total, stats.fetches.peak
    ));
    out.push_str(&format!(
        "`Faa0Pushes`f   : {:>5}  total `F666(peak: {:>3})`f\n",
        stats.pushes.total, stats.pushes.peak
    ));
    out.push_str(&format!(
        "`F0aaActivity`f : {:>5} points\n\n",
        stats.activity_score
    ));
    out.push_str(&format!(
        "{}{}`f over the last {} days ({})\n\n",
        stats.activity_level.color(),
        stats.activity_level.label(),
        stats.actual_days,
        stats.date_range
    ));

    if stats.views.total > 0 {
        out.push_str(">Views\n\n");
        out.push_str(&render_chart(
            &stats.views.daily,
            &stats.timeline_labels,
            "66d",
            10,
        ));
        out.push('\n');
    }
    if stats.fetches.total > 0 {
        out.push_str(">Fetches\n\n");
        out.push_str(&render_chart(
            &stats.fetches.daily,
            &stats.timeline_labels,
            "0a0",
            10,
        ));
        out.push('\n');
    }
    if stats.pushes.total > 0 {
        out.push_str(">Pushes\n\n");
        out.push_str(&render_chart(
            &stats.pushes.daily,
            &stats.timeline_labels,
            "aa0",
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
            &stats.timeline_labels,
            4,
        ));
    } else {
        out.push_str(
            "`*\nNo activity recorded for this repository in the selected time period.\n\n`*",
        );
    }
    Ok(out)
}

fn render_chart(data: &[u64], labels: &[String; 2], color: &str, height: u64) -> String {
    if data.is_empty() || data.iter().all(|value| *value == 0) {
        return "No data available\n".to_string();
    }
    let max = data.iter().copied().max().unwrap_or(1).max(1);
    let mut out = format!("`F{color}Peak: {max}`f\n");
    for row in (1..=height).rev() {
        let threshold = (row - 1) as f64 / height as f64 * max as f64;
        out.push('│');
        for value in data {
            if *value as f64 > threshold {
                let block = if row as f64 >= height as f64 * 0.875 {
                    '█'
                } else if row as f64 >= height as f64 * 0.625 {
                    '▓'
                } else if row as f64 >= height as f64 * 0.375 {
                    '▒'
                } else {
                    '░'
                };
                out.push_str(&format!("`F{color}{block}`f"));
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

fn render_combined_chart(
    views: &[u64],
    fetches: &[u64],
    pushes: &[u64],
    labels: &[String; 2],
    height: u64,
) -> String {
    if views.is_empty() {
        return "No data available\n".to_string();
    }
    let totals: Vec<u64> = views
        .iter()
        .zip(fetches.iter())
        .zip(pushes.iter())
        .map(|((view, fetch), push)| view + fetch + push)
        .collect();
    let max = totals.iter().copied().max().unwrap_or(1).max(1);
    let mut out = String::from("`F66d██`f Views  `F0a0██`f Fetches  `Faa0██`f Pushes\n\n");
    for row in (1..=height).rev() {
        let threshold = (row - 1) as f64 / height as f64 * max as f64;
        out.push('│');
        for i in 0..views.len() {
            let view = views[i] as f64;
            let fetch = fetches.get(i).copied().unwrap_or(0) as f64;
            let push = pushes.get(i).copied().unwrap_or(0) as f64;
            let total = view + fetch + push;
            if total > threshold {
                if push > 0.0 && threshold >= view + fetch {
                    out.push_str("`Faa0█`f");
                } else if fetch > 0.0 && threshold >= view {
                    out.push_str("`F0a0▓`f");
                } else if view > 0.0 {
                    out.push_str("`F66d░`f");
                } else {
                    out.push_str("`F666▒`f");
                }
            } else {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out.push('└');
    for _ in views {
        out.push('─');
    }
    out.push_str("┘\n");
    out.push_str(&format!("`F666{:<12}`f", labels[0]));
    let chart_width = views.len() + 2;
    let spacing = chart_width.saturating_sub(24);
    out.push_str(&" ".repeat(spacing));
    out.push_str(&format!("`F666{:>12}`f\n", labels[1]));
    out
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
        let output = Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("show")
            .arg(format!("HEAD:{name}"))
            .output()?;
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout).into_owned();
            let markdown = name.ends_with(".md");
            let content = if markdown || name.ends_with(".mu") {
                content
            } else {
                m_escape(&content)
            };
            return Ok(Some(ReadmeContent { content, markdown }));
        }
    }
    Ok(None)
}

fn markdown_to_micron(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut out = String::new();
    let mut code_block: Option<(Option<String>, String)> = None;
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if let Some((language, content)) = code_block.take() {
                out.push_str(&crate::highlight::literal_block(
                    &content,
                    None,
                    language.as_deref(),
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
        if is_table_start(&lines, index) {
            let mut table = Vec::new();
            while index < lines.len() && lines[index].contains('|') {
                table.push(lines[index]);
                index += 1;
            }
            out.push_str(&format_markdown_table(&table));
            continue;
        }
        if let Some((level, text)) = markdown_heading(line) {
            out.push_str(&">".repeat(level));
            out.push_str(&format_markdown_inline(text.trim()));
            out.push('\n');
        } else if is_markdown_rule(trimmed) {
            out.push_str("-\n");
        } else if let Some((indent, text)) = unordered_list_item(line) {
            out.push_str(indent);
            out.push_str(" • ");
            out.push_str(&format_markdown_inline(text));
            out.push('\n');
        } else if let Some((indent, number, text)) = ordered_list_item(line) {
            out.push_str(indent);
            out.push_str(number);
            out.push_str(". ");
            out.push_str(&format_markdown_inline(text));
            out.push('\n');
        } else {
            out.push_str(&format_markdown_inline(line));
            out.push('\n');
        }
        index += 1;
    }
    if let Some((language, content)) = code_block {
        out.push_str(&crate::highlight::literal_block(
            &content,
            None,
            language.as_deref(),
        ));
    }

    out
}

fn markdown_fence_language(trimmed: &str) -> Option<String> {
    trimmed
        .strip_prefix("```")
        .and_then(|info| info.split_whitespace().next())
        .filter(|language| !language.is_empty())
        .map(str::to_string)
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

fn format_markdown_table(lines: &[&str]) -> String {
    let rows: Vec<Vec<String>> = lines
        .iter()
        .map(|line| parse_table_row(line))
        .filter(|row| {
            !row.is_empty()
                && !row
                    .iter()
                    .all(|cell| cell.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
        })
        .map(|row| {
            row.into_iter()
                .map(|cell| format_markdown_inline(cell.trim()))
                .collect()
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }

    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0; columns];
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    for row in rows {
        out.push('│');
        for index in 0..columns {
            let cell = row.get(index).map(String::as_str).unwrap_or("");
            out.push(' ');
            out.push_str(cell);
            for _ in cell.chars().count()..widths[index] {
                out.push(' ');
            }
            out.push(' ');
            out.push('│');
        }
        out.push('\n');
    }
    out
}

fn parse_table_row(line: &str) -> Vec<String> {
    let trimmed = line.trim().trim_matches('|');
    trimmed
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

#[derive(Debug)]
enum InlineToken {
    Link { label: String, target: String },
    Code(String),
}

fn format_markdown_inline(input: &str) -> String {
    let (with_placeholders, tokens) = extract_markdown_inline_tokens(input);
    let escaped = m_escape(&with_placeholders);
    let styled = apply_markdown_style(&escaped, "**", "`!", "`!");
    let styled = apply_markdown_style(&styled, "__", "`!", "`!");
    let styled = apply_markdown_style(&styled, "*", "`*", "`*");
    let styled = apply_markdown_style(&styled, "_", "`*", "`*");
    restore_markdown_inline_tokens(&styled, &tokens)
}

fn extract_markdown_inline_tokens(input: &str) -> (String, Vec<InlineToken>) {
    let mut out = String::new();
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < input.len() {
        let rest = &input[index..];
        if rest.starts_with('`') {
            if let Some(end) = rest[1..].find('`') {
                tokens.push(InlineToken::Code(rest[1..1 + end].to_string()));
                out.push_str(&markdown_token_placeholder(tokens.len() - 1));
                index += end + 2;
                continue;
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

fn restore_markdown_inline_tokens(input: &str, tokens: &[InlineToken]) -> String {
    let mut out = input.to_string();
    for (index, token) in tokens.iter().enumerate() {
        let replacement = match token {
            InlineToken::Link { label, target } => format!(
                "`!`[{}{}{}]`!",
                sanitize_label(label).trim(),
                "`",
                sanitize_markdown_link_target(target)
            ),
            InlineToken::Code(value) => format!("`BT383838`Fddd{}`f`b", m_escape(value)),
        };
        out = out.replace(&markdown_token_placeholder(index), &replacement);
    }
    out
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
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .arg("show")
        .arg(spec)
        .output()?;
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

fn run_git(cmd: &mut Command) -> Result<String> {
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
        assert!(commit.contains("initial"));
        assert!(commit.contains("src/lib.rs"));

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
        assert!(out.contains("`!`[the docs`https://example.invalid/a_b]`!"));
        assert!(out.contains("`BT383838`Fdddliteral *code*`f`b"));
        assert!(out.contains(" • `!bold`! and `*italic`*"));
        assert!(out.contains("\n-\n"));
        assert!(out.contains("│ Name"));
        assert!(out.contains("`!`[go`rns://abc]`!"));
    }

    #[test]
    fn markdown_link_conversion_is_isolated_from_later_substitutions() {
        let out = markdown_to_micron("[**bold** `code`](https://example.invalid?q=*x*)");
        assert!(out.contains("`!`[**bold** code`https://example.invalid?q=*x*]`!"));
        assert!(!out.contains("`!`!"));
        assert!(!out.contains("`*x`*"));
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
            "# Title\n\nSee [docs](https://example.invalid) and `tick`.\n",
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
        assert!(rendered.contains("`!`[docs`https://example.invalid]`!"));
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
        assert!(!raw.contains("`!`[docs`https://example.invalid]`!"));
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
            "# Not a heading\n`literal`\n",
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
        assert!(page.contains("Not a heading"));
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
            "# Markdown\n\nSee [docs](https://example.invalid).\n",
        );
        create_repo(
            config.repositories_dir.join("public/micron"),
            "README.mu",
            ">Micron\n\n`!Already formatted`!\n",
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
        assert!(markdown.contains("`!`[docs`https://example.invalid]`!"));

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
            record_stats: false,
            stats_ignore_identities: Vec::new(),
            allow_read: vec!["all".into()],
            allow_write: vec!["none".into()],
            allow_create: vec!["none".into()],
            allow_stats: vec!["none".into()],
            log_level: logging::DEFAULT_LOG_LEVEL,
        }
    }

    fn access(config: &ServerConfig) -> Access {
        Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
            &config.allow_stats,
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
