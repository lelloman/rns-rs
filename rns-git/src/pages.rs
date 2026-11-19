mod access;
mod downloads;
mod git_data;
mod markdown;
mod micron;
mod release_pages;
mod repo_info;
mod repo_pages;
mod stats_page;
mod templates;
#[cfg(test)]
mod tests;
mod work_pages;

use access::*;
pub use downloads::*;
use git_data::*;
use markdown::*;
use micron::*;
use release_pages::*;
use repo_info::*;
use repo_pages::*;
use stats_page::*;
use templates::*;
pub use work_pages::*;

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
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
pub const PATH_MEDIA: &str = "/media";
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
const NULL_IDENTITY_HASH: [u8; 16] = [
    0xd7, 0xdb, 0x22, 0xf6, 0x3b, 0x45, 0x3c, 0x23, 0xbb, 0x06, 0x88, 0xdd, 0xe5, 0x65, 0xb7, 0xc1,
];

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
    let (_, sig_prv) = rns_crypto::identity::split_key(&private_key);
    let (_, sig_pub) = rns_crypto::identity::split_key(&public_key);

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
    let media_config = config.clone();
    let media_access = access.clone();
    node.register_request_handler_response(PATH_MEDIA, None, move |_link, _path, data, remote| {
        Some(
            serve_media(
                &media_config,
                &media_access,
                data,
                remote.map(|(hash, _)| hash),
            )
            .unwrap_or_else(|_| RequestResponse::Bytes(msgpack::pack(&Value::Bool(false)))),
        )
    })
    .map_err(|_| Error::msg("failed to register media handler"))?;
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
    if PAGE_PATHS.contains(&path)
        && remote.is_none()
        && config
            .blocked_identities
            .iter()
            .any(|identity| identity == &NULL_IDENTITY_HASH)
    {
        record_page_view(path, config, &vars, remote);
        return Ok(render_template(config, "no_ident", ""));
    }
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
