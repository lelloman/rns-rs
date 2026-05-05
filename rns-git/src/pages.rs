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
        PATH_STATS => "Stats pages are not implemented yet.\n".to_string(),
        _ => return Err(Error::msg("unknown page path")),
    };
    Ok(render_template(&config.node_name, &content))
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
    format!("#!c=0\n>{node_name}\n\n{content}\n<\n-\nServed by rngit\n")
}

fn error_page(node_name: &str, message: &str) -> Vec<u8> {
    render_template(node_name, &format!(">Error\n\n{message}\n")).into_bytes()
}

fn render_front_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
) -> Result<String> {
    let groups = accessible_groups(config, access, remote)?;
    let mut out = String::from(">Groups\n\n");
    if groups.is_empty() {
        out.push_str("No repository groups available.\n");
        return Ok(out);
    }
    for (group, repos) in groups {
        out.push_str(&format!("{group} ({} repositories)\n", repos.len()));
        for repo in repos {
            out.push_str(&format!("  - {repo}\n"));
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

    let mut out = format!(">Group: {group}\n\n");
    for repo in repos {
        let repo_path = config.repositories_dir.join(group).join(&repo);
        let description = repository_description(&repo_path)?;
        out.push_str(&format!("- {repo}"));
        if !description.is_empty() {
            out.push_str(&format!(" - {description}"));
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
    let readme = readme_name(&repository)?;
    let repo_url = format!("rns://<repository-destination>/{group}/{repo}");

    let mut out = format!(">Repository: {group}/{repo}\n\n{repo_url}\n");
    if !description.is_empty() {
        out.push_str(&format!("\n{description}\n"));
    }
    out.push_str(&format!(
        "\nFiles | Commits | Branches ({}) | Tags ({})\n",
        refs.heads.len(),
        refs.tags.len()
    ));
    if let Some(readme) = readme {
        out.push_str(&format!("\nREADME: {readme}\n"));
    } else {
        out.push_str("\nNo README file found in this repository.\n");
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

    let mut out = format!(">Tree: {group}/{repo} {title_path}\n\n");
    if entries.is_empty() {
        out.push_str("Empty directory.\n");
    } else {
        for entry in entries {
            let suffix = if entry.kind == "tree" { "/" } else { "" };
            out.push_str(&format!("{}{}{}\n", entry.name, suffix, entry.size_label()));
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
    let content = blob_content(&repository, &resolved, path)?;
    Ok(format!(">Blob: {group}/{repo}/{path}\n\n{content}\n"))
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

    let mut out = format!(">Commits: {group}/{repo}\n\n");
    if commits.is_empty() {
        out.push_str("No commits found.\n");
    } else {
        for commit in commits {
            out.push_str(&format!(
                "{} {} {}\n",
                &commit.hash[..7],
                commit.author,
                commit.subject
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
        ">Commit: {group}/{repo}\n\n{}\n{}\n",
        commit.hash, commit.subject
    );
    if !commit.body.is_empty() {
        out.push_str(&format!("\n{}\n", commit.body));
    }
    for file in commit.files {
        out.push_str(&format!("{} {}\n", file.status, file.path));
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
    let mut out = format!(">Refs: {group}/{repo}\n\nBranches\n");
    for branch in refs.heads {
        out.push_str(&format!("- {} {}\n", branch.name, branch.sha));
    }
    out.push_str("\nTags\n");
    for tag in refs.tags {
        out.push_str(&format!("- {} {}\n", tag.name, tag.sha));
    }
    Ok(out)
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

fn readme_name(repo: &Path) -> Result<Option<String>> {
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
        if git_success(
            Command::new("git")
                .arg("--git-dir")
                .arg(repo)
                .arg("cat-file")
                .arg("-e")
                .arg(format!("HEAD:{name}")),
        ) {
            return Ok(Some((*name).to_string()));
        }
    }
    Ok(None)
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

fn blob_content(repo: &Path, reference: &str, path: &str) -> Result<String> {
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
    .parse::<usize>()
    .unwrap_or(0);
    if size > 256 * 1024 {
        return Ok(format!("File is too large to display ({size} bytes)."));
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Debug)]
struct CommitSummary {
    hash: String,
    subject: String,
    author: String,
}

fn commits(repo: &Path, reference: &str, limit: usize) -> Result<Vec<CommitSummary>> {
    let format = "%H%x1f%s%x1f%an";
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
        if parts.len() == 3 {
            commits.push(CommitSummary {
                hash: parts[0].to_string(),
                subject: parts[1].to_string(),
                author: parts[2].to_string(),
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
            .arg("--format=%H%x1f%s%x1f%B")
            .arg(hash),
    )?;
    let parts: Vec<&str> = output.splitn(3, '\x1f').collect();
    if parts.len() != 3 {
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
        body: parts[2].trim().to_string(),
        files,
    })
}

fn git_success(cmd: &mut Command) -> bool {
    cmd.output()
        .map(|output| output.status.success())
        .unwrap_or(false)
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
        assert!(repo.contains("README.md"));
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
            allow_read: vec!["all".into()],
            allow_write: vec!["none".into()],
            allow_create: vec!["none".into()],
            log_level: logging::DEFAULT_LOG_LEVEL,
        }
    }

    fn access(config: &ServerConfig) -> Access {
        Access::new(
            &config.allow_read,
            &config.allow_write,
            &config.allow_create,
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
