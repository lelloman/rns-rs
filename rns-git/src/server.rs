use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use rns_core::display::prettyb256rep;
use rns_core::msgpack::{self, Value};
use rns_core::types::IdentityHash;
use rns_crypto::identity::Identity;
use rns_net::link_manager::ResourceStrategy;
use rns_net::{
    AnnouncedIdentity, Callbacks, DestHash, Destination, PacketHash, RequestResponse, RnsNode,
};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::logging;
use crate::pages;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, hex, load_or_create_identity};
use crate::{git, Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = ServerOptions::parse(args)?;
    git::check_git_available()?;

    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (config, created) = ServerConfig::load_or_create(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("server_log"), config.log_level)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run rngit again",
            config.dir.join("server_config").display()
        )));
    }

    let identity = load_or_create_identity(&config.identity_path)?;
    if options.print_identity {
        let client = load_or_create_identity(&config.client_identity_path)?;
        print_identity(&identity, &client, options.base256, config.serve_nomadnet);
        return Ok(());
    }

    run_server(config, identity)
}

pub fn run_server(config: ServerConfig, identity: Identity) -> Result<()> {
    let node = RnsNode::from_config(
        config.reticulum_dir.as_deref(),
        Box::<ServerCallbacks>::default(),
    )?;

    let announce_interval = Duration::from_secs(config.announce_interval_secs);
    let destinations = register_server_destinations(&node, config.clone(), &identity)?;

    loop {
        thread::sleep(announce_interval);
        let _ = node.announce(&destinations.repositories, &identity, None);
        if let Some(page_destination) = destinations.nomadnet.as_ref() {
            let _ = node.announce(
                page_destination,
                &identity,
                Some(config.node_name.as_bytes()),
            );
        }
    }
}

#[derive(Debug)]
pub struct ServerDestinations {
    pub repositories: Destination,
    pub nomadnet: Option<Destination>,
}

pub fn register_server_destinations(
    node: &RnsNode,
    config: ServerConfig,
    identity: &Identity,
) -> Result<ServerDestinations> {
    let repositories = register_repository_destination(node, config.clone(), identity)?;
    let nomadnet = if config.serve_nomadnet {
        Some(pages::register_nomadnet_destination(
            node, &config, identity,
        )?)
    } else {
        None
    };
    Ok(ServerDestinations {
        repositories,
        nomadnet,
    })
}

pub fn register_repository_destination(
    node: &RnsNode,
    config: ServerConfig,
    identity: &Identity,
) -> Result<Destination> {
    crate::util::ensure_dir(&config.repositories_dir)?;
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
    let destination = Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    );
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
    .map_err(|_| Error::msg("failed to register link destination"))?;
    register_handlers(node, config, access)?;
    node.announce(&destination, identity, None)
        .map_err(|_| Error::msg("failed to announce rngit destination"))?;
    Ok(destination)
}

fn register_handlers(node: &RnsNode, config: ServerConfig, access: Access) -> Result<()> {
    let list_config = config.clone();
    let list_access = access.clone();
    node.register_request_handler(
        protocol::PATH_LIST,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_list(&list_config, &list_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register list handler"))?;

    let fetch_config = config.clone();
    let fetch_access = access.clone();
    node.register_request_handler_response(
        protocol::PATH_FETCH,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_fetch(&fetch_config, &fetch_access, data, remote)
                    .unwrap_or_else(|err| RequestResponse::Bytes(error_response(err))),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register fetch handler"))?;

    let push_config = config.clone();
    let push_access = access.clone();
    node.register_request_handler(
        protocol::PATH_PUSH,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_push(&push_config, &push_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register push handler"))?;

    let create_config = config.clone();
    let create_access = access.clone();
    node.register_request_handler(
        protocol::PATH_CREATE,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_create(&create_config, &create_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register create handler"))?;

    let fork_config = config.clone();
    let fork_access = access.clone();
    node.register_request_handler(
        protocol::PATH_FORK,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_fork(&fork_config, &fork_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register fork handler"))?;

    let sync_config = config.clone();
    let sync_access = access.clone();
    node.register_request_handler(
        protocol::PATH_SYNC,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_sync(&sync_config, &sync_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register sync handler"))?;

    let mirror_config = config.clone();
    let mirror_access = access.clone();
    node.register_request_handler(
        protocol::PATH_MIRROR,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_mirror(&mirror_config, &mirror_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register mirror handler"))?;

    let release_config = config.clone();
    let release_access = access.clone();
    node.register_request_handler_response(
        protocol::PATH_RELEASE,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_release_response(&release_config, &release_access, data, remote)
                    .unwrap_or_else(|err| RequestResponse::Bytes(error_response(err))),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register release handler"))?;

    let work_config = config.clone();
    let work_access = access.clone();
    node.register_request_handler(
        protocol::PATH_WORK,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_work(&work_config, &work_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register work handler"))?;

    let perms_config = config.clone();
    let perms_access = access.clone();
    node.register_request_handler(
        protocol::PATH_PERMS,
        None,
        move |_link, _path, data, remote| {
            Some(
                handle_perms(&perms_config, &perms_access, data, remote)
                    .unwrap_or_else(error_response),
            )
        },
    )
    .map_err(|_| Error::msg("failed to register permissions handler"))?;

    node.register_request_handler(
        protocol::PATH_DELETE,
        None,
        move |_link, _path, data, remote| {
            Some(handle_delete(&config, &access, data, remote).unwrap_or_else(error_response))
        },
    )
    .map_err(|_| Error::msg("failed to register delete handler"))?;

    Ok(())
}

pub fn handle_list(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let repo = protocol::repository_from_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Read, &repo, remote_hash)? {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"read denied",
        ));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::list_refs_text(&path) {
        Ok(refs) => Ok(protocol::status_bytes(protocol::RES_OK, refs)),
        Err(err) if err.to_string() == "repository not found" => Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        )),
        Err(err) => Ok(remote_error_response("list", &repo, err)),
    }
}

pub fn handle_fetch(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<RequestResponse> {
    let (repo, have) = protocol::parse_fetch_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Read, &repo, remote_hash)? {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"read denied",
        )));
    }
    if let Err(err) = git::validate_shas(&have) {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            err.to_string(),
        )));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::create_bundle(&path, &have) {
        Ok(bundle) if bundle.is_empty() => {
            crate::stats::record_fetch(config, &repo, remote_hash);
            Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_OK,
                Vec::new(),
            )))
        }
        Ok(bundle) => {
            crate::stats::record_fetch(config, &repo, remote_hash);
            Ok(RequestResponse::Resource {
                data: bundle,
                metadata: Some(protocol::metadata_status(protocol::RES_OK)),
                auto_compress: true,
            })
        }
        Err(err) if err.to_string() == "repository not found" => Ok(RequestResponse::Bytes(
            protocol::status_bytes(protocol::RES_NOT_FOUND, b"repository not found"),
        )),
        Err(err) => Ok(RequestResponse::Bytes(remote_error_response(
            "fetch", &repo, err,
        ))),
    }
}

pub fn handle_push(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let (repo, bundle, updates) = protocol::parse_push_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    if let Err(err) = git::validate_ref_updates(&updates) {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            err.to_string(),
        ));
    }
    let op = if git::is_bare_repository(&path) {
        Operation::Write
    } else {
        Operation::Create
    };
    if !access.allows(op, &repo, remote_hash)? {
        let message = match op {
            Operation::Create => b"create denied".as_slice(),
            Operation::Write => b"write denied".as_slice(),
            Operation::Read => b"read denied".as_slice(),
            Operation::Stats => b"stats denied".as_slice(),
            Operation::Release => b"release denied".as_slice(),
            Operation::Interact => b"interact denied".as_slice(),
            Operation::Propose => b"propose denied".as_slice(),
            Operation::Admin => b"admin denied".as_slice(),
        };
        return Ok(protocol::status_bytes(protocol::RES_DISALLOWED, message));
    }
    match git::apply_push(&path, &bundle, &updates) {
        Ok(()) => {
            crate::stats::record_push(config, &repo, remote_hash);
            Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
        }
        Err(err) => Ok(remote_error_response("push", &repo, err)),
    }
}

pub fn handle_create(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let Some((remote_hash, _)) = remote else {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        ));
    };
    let repo = protocol::repository_from_request(data)?;
    let Some((group, name)) = repo.split_once('/') else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        ));
    };
    if group.is_empty() || name.is_empty() || name.contains('/') {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        ));
    }

    let group_path = config.repositories_dir.join(group);
    if !group_path.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }

    let read_access = access.allows(Operation::Read, &repo, Some(remote_hash))?;
    let create_access = access.allows(Operation::Create, &repo, Some(remote_hash))?;
    if !create_access {
        let (code, message) = if read_access {
            (protocol::RES_DISALLOWED, b"not allowed".as_slice())
        } else {
            (protocol::RES_NOT_FOUND, b"not found".as_slice())
        };
        return Ok(protocol::status_bytes(code, message));
    }

    let repository_path = git::repository_path(&config.repositories_dir, &repo)?;
    if repository_path.exists() {
        let (code, message) = if read_access {
            (
                protocol::RES_DISALLOWED,
                b"repository already exists".as_slice(),
            )
        } else {
            (protocol::RES_NOT_FOUND, b"not found".as_slice())
        };
        return Ok(protocol::status_bytes(code, message));
    }

    if let Err(err) = git::ensure_bare_repository(&repository_path) {
        let _ = std::fs::remove_dir_all(&repository_path);
        return Ok(remote_error_response("create", &repo, err));
    }

    let allowed_path = config.repositories_dir.join(format!("{repo}.allowed"));
    let permissions = format!("adm:{}\n", hex(remote_hash));
    if let Err(err) = std::fs::write(&allowed_path, permissions) {
        let _ = std::fs::remove_dir_all(&repository_path);
        return Ok(remote_error_response("create", &repo, err));
    }

    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn handle_fork(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    handle_remote_clone(config, access, data, remote, "fork")
}

pub fn handle_mirror(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    handle_remote_clone(config, access, data, remote, "mirror")
}

fn handle_remote_clone(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
    repository_type: &str,
) -> Result<Vec<u8>> {
    let Some((remote_hash, _)) = remote else {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        ));
    };
    let (repo, source) = match protocol::parse_remote_clone_request(data) {
        Ok(request) => request,
        Err(err) => {
            return Ok(protocol::status_bytes(
                protocol::RES_INVALID_REQ,
                err.to_string(),
            ));
        }
    };
    let Some((group, name)) = repo.split_once('/') else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        ));
    };
    if group.is_empty() || name.is_empty() || name.contains('/') {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        ));
    }

    let group_path = config.repositories_dir.join(group);
    if !group_path.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }

    let read_access = access.allows(Operation::Read, &repo, Some(remote_hash))?;
    let create_access = access.allows(Operation::Create, &repo, Some(remote_hash))?;
    if !create_access {
        let (code, message) = if read_access {
            (protocol::RES_DISALLOWED, b"not allowed".as_slice())
        } else {
            (protocol::RES_NOT_FOUND, b"not found".as_slice())
        };
        return Ok(protocol::status_bytes(code, message));
    }

    let repository_path = git::repository_path(&config.repositories_dir, &repo)?;
    if repository_path.exists() {
        let (code, message) = if read_access {
            (
                protocol::RES_DISALLOWED,
                b"repository already exists".as_slice(),
            )
        } else {
            (protocol::RES_NOT_FOUND, b"not found".as_slice())
        };
        return Ok(protocol::status_bytes(code, message));
    }

    if let Err(err) = git::clone_remote_bare(&source, &repository_path, repository_type) {
        let _ = std::fs::remove_dir_all(&repository_path);
        return Ok(remote_error_response(repository_type, &repo, err));
    }

    let allowed_path = config.repositories_dir.join(format!("{repo}.allowed"));
    let permissions = format!("adm:{}\n", hex(remote_hash));
    if let Err(err) = std::fs::write(&allowed_path, permissions) {
        let _ = std::fs::remove_dir_all(&repository_path);
        return Ok(remote_error_response(repository_type, &repo, err));
    }

    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn handle_sync(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let Some((remote_hash, _)) = remote else {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        ));
    };
    let repo = protocol::repository_from_request(data)?;
    let remote_hash = Some(remote_hash);
    let read_access = access.allows(Operation::Read, &repo, remote_hash)?;
    let write_access = access.allows(Operation::Write, &repo, remote_hash)?;
    if !read_access {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    if !write_access {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not allowed",
        ));
    }

    let repository_path = git::repository_path(&config.repositories_dir, &repo)?;
    if !git::is_bare_repository(&repository_path) {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    let repository_type = git::repository_config(&repository_path, "repository.rngit.type")?;
    if !matches!(repository_type.as_deref(), Some("fork" | "mirror")) {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"repository is neither fork nor mirror",
        ));
    }
    if let Err(_err) = git::sync_upstream(&repository_path) {
        let message = match repository_type.as_deref() {
            Some("mirror") => b"mirror sync failed".as_slice(),
            Some("fork") => b"fork sync failed".as_slice(),
            _ => b"sync failed".as_slice(),
        };
        return Ok(protocol::status_bytes(protocol::RES_REMOTE_FAIL, message));
    }

    if let Some(kind) = repository_type.as_deref() {
        log::info!("rngit {kind} {repo} synced successfully");
    }

    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn handle_delete(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let repo = protocol::repository_from_request(data)?;
    let remote_hash = remote.map(|(hash, _)| hash);
    if !access.allows(Operation::Write, &repo, remote_hash)? {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"write denied",
        ));
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    if !path.exists() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        ));
    }
    if let Err(err) = std::fs::remove_dir_all(path) {
        return Ok(remote_error_response("delete", &repo, err));
    }
    Ok(protocol::status_bytes(protocol::RES_OK, b"deleted"))
}

pub fn handle_release(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    match handle_release_response(config, access, data, remote)? {
        RequestResponse::Bytes(data) => Ok(data),
        RequestResponse::Resource { data, .. } => {
            Ok(protocol::status_bytes(protocol::RES_OK, data))
        }
    }
}

pub fn handle_release_response(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<RequestResponse> {
    let Some((remote_hash, _)) = remote else {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        )));
    };
    let request = crate::release::parse_request(data)?;
    let repo = request.repository.as_str();
    if !access.allows(Operation::Read, repo, Some(remote_hash))? {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        )));
    }
    let release_access = access.allows(Operation::Release, repo, Some(remote_hash))?;
    let permitted = match request.operation.as_str() {
        "list" | "view" | "fetch" => true,
        "create" | "delete" | "latest" => release_access,
        _ => false,
    };
    if !permitted {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not allowed",
        )));
    }

    let repository_path = git::repository_path(&config.repositories_dir, repo)?;
    if !git::is_bare_repository(&repository_path) {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        )));
    }
    let releases_path = crate::release::release_sidecar_path(&repository_path);
    let response = match request.operation.as_str() {
        "list" => RequestResponse::Bytes(crate::release::list_response(&releases_path)?),
        "view" => {
            let Some(tag) = request.tag.as_deref() else {
                return Ok(RequestResponse::Bytes(protocol::status_bytes(
                    protocol::RES_INVALID_REQ,
                    b"no tag specified",
                )));
            };
            RequestResponse::Bytes(crate::release::view_response(&releases_path, tag)?)
        }
        "fetch" => crate::release::fetch_response(&releases_path, &request)?,
        "create" => match request.step.as_deref() {
            Some("init") => RequestResponse::Bytes(crate::release::create_init(
                &releases_path,
                &repository_path,
                &request,
                remote_hash,
            )?),
            Some("artifact") => {
                RequestResponse::Bytes(crate::release::create_artifact(&releases_path, &request)?)
            }
            Some("finalize") => {
                RequestResponse::Bytes(crate::release::create_finalize(&releases_path, &request)?)
            }
            _ => RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_INVALID_REQ,
                b"invalid request",
            )),
        },
        "delete" => {
            RequestResponse::Bytes(crate::release::delete_release(&releases_path, &request)?)
        }
        "latest" => RequestResponse::Bytes(crate::release::set_latest_release(
            &releases_path,
            &request,
        )?),
        _ => RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        )),
    };
    Ok(response)
}

pub fn handle_perms(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let Some((remote_hash, _)) = remote else {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        ));
    };
    let value =
        msgpack::unpack_exact(data).map_err(|err| Error::msg(format!("invalid msgpack: {err}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let operation = map_get_str(map, "operation").unwrap_or("");
    match operation {
        "gperms" => {
            let group = map_get_index_str(map, protocol::IDX_GROUP).unwrap_or("");
            handle_group_permissions(config, access, group, map, remote_hash)
        }
        "rperms" => {
            let repo = map_get_index_str(map, protocol::IDX_REPOSITORY).unwrap_or("");
            handle_repository_permissions(config, access, repo, map, remote_hash)
        }
        _ => Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        )),
    }
}

fn handle_group_permissions(
    config: &ServerConfig,
    access: &Access,
    group: &str,
    map: &[(Value, Value)],
    remote_hash: &[u8; 16],
) -> Result<Vec<u8>> {
    if !valid_group_name(group) {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid group",
        ));
    }
    let group_dir = config.repositories_dir.join(group);
    if !group_dir.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    let synthetic_repo = format!("{group}/__group__");
    let read_access = access.allows(Operation::Read, &synthetic_repo, Some(remote_hash))?;
    let admin_access = access.allows(Operation::Admin, &synthetic_repo, Some(remote_hash))?;
    if !read_access {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    if !admin_access {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not allowed",
        ));
    }
    let allowed_path = config.repositories_dir.join(format!("{group}.allowed"));
    handle_permissions_step(config, map, &allowed_path)
}

fn handle_repository_permissions(
    config: &ServerConfig,
    access: &Access,
    repo: &str,
    map: &[(Value, Value)],
    remote_hash: &[u8; 16],
) -> Result<Vec<u8>> {
    if let Err(err) = crate::util::validate_repo_name(repo) {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            err.to_string(),
        ));
    }
    let read_access = access.allows(Operation::Read, repo, Some(remote_hash))?;
    let admin_access = access.allows(Operation::Admin, repo, Some(remote_hash))?;
    let repo_path = git::repository_path(&config.repositories_dir, repo)?;
    if !git::is_bare_repository(&repo_path) {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    if !read_access {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    if !admin_access {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not allowed",
        ));
    }
    let allowed_path = config.repositories_dir.join(format!("{repo}.allowed"));
    handle_permissions_step(config, map, &allowed_path)
}

fn handle_permissions_step(
    config: &ServerConfig,
    map: &[(Value, Value)],
    allowed_path: &std::path::Path,
) -> Result<Vec<u8>> {
    match map_get_str(map, "step") {
        Some("get") => {
            let content = match std::fs::read_to_string(allowed_path) {
                Ok(content) => content,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(err) => return Err(err.into()),
            };
            Ok(protocol::status_bytes(
                protocol::RES_OK,
                msgpack::pack(&Value::Map(vec![(
                    Value::Str("content".into()),
                    Value::Str(content),
                )])),
            ))
        }
        Some("set") => {
            let content = map_get_str(map, "content").unwrap_or("");
            if let Err(err) =
                crate::acl::validate_allowed_input_with_aliases(content, &config.identity_aliases)
            {
                return Ok(protocol::status_bytes(
                    protocol::RES_INVALID_REQ,
                    format!("invalid permissions: {err}"),
                ));
            }
            write_permissions_file(allowed_path, content)?;
            Ok(protocol::status_bytes(protocol::RES_OK, b""))
        }
        Some(_) => Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid step",
        )),
        None => Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        )),
    }
}

fn write_permissions_file(path: &std::path::Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("allowed.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn valid_group_name(group: &str) -> bool {
    !group.is_empty() && !group.contains('/') && crate::util::validate_repo_name(group).is_ok()
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(candidate, value)| match candidate {
        Value::Str(candidate) if candidate == key => value.as_str(),
        _ => None,
    })
}

fn map_get_index_str<'a>(map: &'a [(Value, Value)], key: u64) -> Option<&'a str> {
    map.iter().find_map(|(candidate, value)| match candidate {
        Value::UInt(candidate) if *candidate == key => value.as_str(),
        _ => None,
    })
}

pub fn handle_work(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    let Some((remote_hash, remote_pubkey)) = remote else {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not identified",
        ));
    };
    let request = crate::work::parse_request(data)?;
    let repo = request.repository.as_str();
    if !access.allows(Operation::Read, repo, Some(remote_hash))? {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"not found",
        ));
    }
    let repository_path = git::repository_path(&config.repositories_dir, repo)?;
    if !git::is_bare_repository(&repository_path) {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        ));
    }
    let work_path = crate::work::work_sidecar_path(&repository_path);
    let mut interact_access = access.allows(Operation::Interact, repo, Some(remote_hash))?;
    let propose_access = access.allows(Operation::Propose, repo, Some(remote_hash))?;
    if request.operation == "comment" {
        if let Some(doc_id) = request.doc_id {
            interact_access |= crate::work::document_permission_allows(
                &work_path,
                doc_id,
                Operation::Interact,
                Some(remote_hash),
            )?;
        }
    }
    let mut write_access = access.allows(Operation::Write, repo, Some(remote_hash))?;
    if request.operation == "edit" {
        if let Some(doc_id) = request.doc_id {
            interact_access |= crate::work::document_permission_allows(
                &work_path,
                doc_id,
                Operation::Interact,
                Some(remote_hash),
            )?;
            write_access |= crate::work::document_permission_allows(
                &work_path,
                doc_id,
                Operation::Write,
                Some(remote_hash),
            )?;
        }
    }
    let manage_access = interact_access && write_access;
    let permitted = match request.operation.as_str() {
        "list" | "view" => true,
        "comment" => interact_access,
        "propose" => propose_access,
        "create" | "edit" | "delete" | "complete" | "activate" => manage_access,
        "perms" => true,
        _ => false,
    };
    if !permitted {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"not allowed",
        ));
    }

    match request.operation.as_str() {
        "list" => {
            let scope = request
                .scope
                .as_deref()
                .map(crate::work::WorkListScope::parse)
                .unwrap_or(Some(crate::work::WorkListScope::Active))
                .ok_or_else(|| Error::msg("invalid scope"))?;
            crate::work::list_response(&work_path, scope)
        }
        "view" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let scope = work_scope(request.scope.as_deref())?;
            crate::work::view_response(&work_path, scope, doc_id)
        }
        "create" => {
            let content = request.content.unwrap_or_default();
            let signature = request.signature;
            let identity =
                match validate_work_signature(&content, signature.as_deref(), remote_pubkey) {
                    Ok(identity) => identity,
                    Err(err) => return Ok(work_error_response(err)),
                };
            work_status_result(
                crate::work::create_document(
                    &work_path,
                    crate::work::WorkInput {
                        title: request.title.unwrap_or_default(),
                        content,
                        format: request.format.unwrap_or_else(|| "markdown".into()),
                        signature,
                        identity,
                        author: *remote_hash,
                    },
                )
                .map(crate::work::created_response),
            )
        }
        "propose" => {
            let content = request.content.unwrap_or_default();
            let signature = request.signature;
            let identity =
                match validate_work_signature(&content, signature.as_deref(), remote_pubkey) {
                    Ok(Some(identity)) => Some(identity),
                    Ok(None) => {
                        return Ok(work_error_response(Error::msg("no signature provided")))
                    }
                    Err(err) => return Ok(work_error_response(err)),
                };
            work_status_result(
                crate::work::propose_document(
                    &work_path,
                    crate::work::WorkInput {
                        title: request.title.unwrap_or_default(),
                        content,
                        format: request.format.unwrap_or_else(|| "markdown".into()),
                        signature,
                        identity,
                        author: *remote_hash,
                    },
                )
                .map(crate::work::created_response),
            )
        }
        "edit" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let scope = work_scope(request.scope.as_deref())?;
            let signature = request.signature;
            let identity = if let Some(content) = request.content.as_deref() {
                match validate_work_signature(content, signature.as_deref(), remote_pubkey) {
                    Ok(identity) => identity,
                    Err(err) => return Ok(work_error_response(err)),
                }
            } else {
                None
            };
            work_status_result(
                crate::work::edit_document(
                    &work_path,
                    scope,
                    doc_id,
                    remote_hash,
                    crate::work::WorkEdit {
                        title: request.title,
                        content: request.content,
                        signature,
                        identity,
                    },
                )
                .map(|_| protocol::status_bytes(protocol::RES_OK, b"")),
            )
        }
        "delete" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let scope = work_scope(request.scope.as_deref())?;
            work_status_result(
                crate::work::delete_document(&work_path, scope, doc_id, remote_hash)
                    .map(|_| protocol::status_bytes(protocol::RES_OK, b"")),
            )
        }
        "comment" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let scope = work_scope(request.scope.as_deref())?;
            work_status_result(
                crate::work::add_comment(
                    &work_path,
                    scope,
                    doc_id,
                    crate::work::WorkCommentInput {
                        content: request.content.unwrap_or_default(),
                        format: request.format.unwrap_or_else(|| "markdown".into()),
                        signature: request.signature,
                        author: *remote_hash,
                    },
                )
                .map(crate::work::comment_response),
            )
        }
        "complete" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            work_status_result(
                crate::work::complete_document(&work_path, doc_id, remote_hash).map(|_| {
                    crate::work::transition_response(doc_id, crate::work::WorkScope::Completed)
                }),
            )
        }
        "activate" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            work_status_result(
                crate::work::activate_document(&work_path, doc_id, remote_hash).map(|_| {
                    crate::work::transition_response(doc_id, crate::work::WorkScope::Active)
                }),
            )
        }
        "perms" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let allowed =
                match work_permissions_allowed(&work_path, doc_id, remote_hash, manage_access) {
                    Ok(allowed) => allowed,
                    Err(err) => return Ok(work_error_response(err)),
                };
            if !allowed {
                return Ok(protocol::status_bytes(
                    protocol::RES_DISALLOWED,
                    b"not allowed",
                ));
            }
            match request.step.as_deref() {
                Some("get") => work_status_result(
                    crate::work::get_document_permissions(&work_path, doc_id)
                        .map(crate::work::permissions_response),
                ),
                Some("set") => work_status_result(
                    crate::work::set_document_permissions(
                        &work_path,
                        doc_id,
                        request.content.as_deref().unwrap_or(""),
                    )
                    .map(|_| protocol::status_bytes(protocol::RES_OK, b"")),
                ),
                Some(_) => Ok(protocol::status_bytes(
                    protocol::RES_INVALID_REQ,
                    b"invalid step",
                )),
                None => Ok(protocol::status_bytes(
                    protocol::RES_INVALID_REQ,
                    b"invalid request",
                )),
            }
        }
        _ => Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid request",
        )),
    }
}

fn work_permissions_allowed(
    work_path: &std::path::Path,
    doc_id: u64,
    remote_hash: &[u8; 16],
    manage_access: bool,
) -> Result<bool> {
    let is_author = crate::work::document_author(work_path, doc_id)? == *remote_hash;
    let doc_admin = crate::work::document_permission_allows(
        work_path,
        doc_id,
        Operation::Admin,
        Some(remote_hash),
    )?;
    Ok((is_author && manage_access) || doc_admin)
}

fn validate_work_signature(
    content: &str,
    signature: Option<&[u8]>,
    remote_pubkey: &[u8; 64],
) -> Result<Option<Vec<u8>>> {
    let Some(signature) = signature else {
        return Ok(None);
    };
    if signature.len() != 64 {
        return Err(Error::msg("invalid signature"));
    }
    let signature: &[u8; 64] = signature.try_into().unwrap();
    let identity = Identity::from_public_key(remote_pubkey);
    if !identity.verify(signature, content.trim().as_bytes()) {
        return Err(Error::msg("invalid signature"));
    }
    Ok(Some(remote_pubkey.to_vec()))
}

fn work_scope(scope: Option<&str>) -> Result<crate::work::WorkScope> {
    scope
        .map(crate::work::WorkScope::parse)
        .unwrap_or(Some(crate::work::WorkScope::Active))
        .ok_or_else(|| Error::msg("invalid scope"))
}

fn work_status_result(result: Result<Vec<u8>>) -> Result<Vec<u8>> {
    match result {
        Ok(response) => Ok(response),
        Err(err) => Ok(work_error_response(err)),
    }
}

fn work_error_response(err: Error) -> Vec<u8> {
    let message = err.to_string();
    let code = if message.starts_with("invalid permission")
        || message.starts_with("invalid hex")
        || message.starts_with("expected 32 hex characters")
    {
        protocol::RES_INVALID_REQ
    } else {
        match message.as_str() {
            "document not found" => protocol::RES_NOT_FOUND,
            "no access, not author" => {
                return protocol::status_bytes(protocol::RES_DISALLOWED, b"not allowed");
            }
            "title is required"
            | "content is required"
            | "no signature provided"
            | "invalid signature"
            | "content limit exceeded"
            | "no changes specified" => protocol::RES_INVALID_REQ,
            _ => protocol::RES_REMOTE_FAIL,
        }
    };
    protocol::status_bytes(code, message)
}

fn error_response(err: Error) -> Vec<u8> {
    protocol::status_bytes(protocol::RES_INVALID_REQ, err.to_string())
}

fn remote_error_response(context: &str, repository: &str, err: impl std::fmt::Display) -> Vec<u8> {
    log::error!("rngit {context} failed for {repository}: {err}");
    protocol::status_bytes(protocol::RES_REMOTE_FAIL, b"Remote error")
}

fn repository_destination(identity: &Identity) -> Destination {
    Destination::single_in(
        protocol::APP_NAME,
        &[protocol::ASPECT_REPOSITORIES],
        IdentityHash(*identity.hash()),
    )
}

fn identity_report(
    identity: &Identity,
    client: &Identity,
    base256: bool,
    serve_nomadnet: bool,
) -> String {
    let destination = repository_destination(identity);
    let mut out = String::new();
    out.push_str(&format!("client_identity = {}\n", hex(client.hash())));
    if base256 {
        out.push_str(&format!(
            "client_identity_b256 = {}\n",
            prettyb256rep(client.hash())
        ));
    }
    out.push_str(&format!("repository_identity = {}\n", hex(identity.hash())));
    if base256 {
        out.push_str(&format!(
            "repository_identity_b256 = {}",
            prettyb256rep(identity.hash())
        ));
        out.push('\n');
    }
    out.push_str(&format!("destination = {}\n", hex(&destination.hash.0)));
    if base256 {
        out.push_str(&format!(
            "destination_b256 = {}\n",
            prettyb256rep(&destination.hash.0)
        ));
    }
    if serve_nomadnet {
        let page_destination = pages::destination_for_identity(identity);
        out.push_str(&format!(
            "nomadnet_destination = {}\n",
            hex(&page_destination.hash.0)
        ));
        if base256 {
            out.push_str(&format!(
                "nomadnet_destination_b256 = {}\n",
                prettyb256rep(&page_destination.hash.0)
            ));
        }
    }
    out
}

fn print_identity(identity: &Identity, client: &Identity, base256: bool, serve_nomadnet: bool) {
    print!(
        "{}",
        identity_report(identity, client, base256, serve_nomadnet)
    );
}

#[derive(Default)]
struct ServerCallbacks;

impl Callbacks for ServerCallbacks {
    fn on_announce(&mut self, _announced: AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }
}

#[derive(Debug, Default)]
struct ServerOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    print_identity: bool,
    base256: bool,
}

impl ServerOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut options = ServerOptions::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    options.config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing config path"))?,
                    ));
                }
                "--rnsconfig" => {
                    options.rns_config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing RNS config path"))?,
                    ));
                }
                "--print-identity" => options.print_identity = true,
                "-Z" | "--base256" => options.base256 = true,
                "--service" | "--interactive" => {
                    return Err(Error::msg(format!(
                        "{arg} is not supported by this rngit binary\n{}",
                        usage()
                    )))
                }
                "-h" | "--help" => return Err(Error::msg(usage())),
                other => {
                    return Err(Error::msg(format!(
                        "unknown argument: {other}\n{}",
                        usage()
                    )))
                }
            }
        }
        Ok(options)
    }
}

fn usage() -> &'static str {
    "usage: rngit [--config DIR] [--rnsconfig DIR] [--print-identity] [-Z|--base256]"
}

#[cfg(test)]
mod tests {
    use super::*;
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
            serve_nomadnet: false,
            templates_dir: root.join("templates"),
            unicode_icons: false,
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
        let expected =
            Destination::single_in("git", &["repositories"], IdentityHash(*identity.hash()));
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
        let source = create_source_repo(tmp.path());
        let mut config = cfg(tmp.path());
        config.allow_create = vec!["all".into()];
        std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
        let access = make_access(&config);
        let remote = ([0x22; 16], [0u8; 64]);
        let req =
            protocol::remote_clone_request("group/forked", source.to_str().expect("utf-8 path"));

        let resp = handle_fork(&config, &access, &req, Some(&remote)).unwrap();

        let target = config.repositories_dir.join("group/forked");
        assert_eq!(resp[0], protocol::RES_OK);
        assert!(git::is_bare_repository(&target));
        assert!(!git::list_refs(&target).unwrap().is_empty());
        assert_eq!(git_config(&target, "repository.rngit.type"), "fork");
        assert_eq!(
            git_config(&target, "repository.rngit.upstream.source"),
            source.to_string_lossy()
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
        let source = create_source_repo(tmp.path());
        let mut config = cfg(tmp.path());
        config.allow_create = vec!["all".into()];
        std::fs::create_dir_all(config.repositories_dir.join("group")).unwrap();
        let access = make_access(&config);
        let remote = ([0x22; 16], [0u8; 64]);
        let req =
            protocol::remote_clone_request("group/mirrored", source.to_str().expect("utf-8 path"));

        let resp = handle_mirror(&config, &access, &req, Some(&remote)).unwrap();

        let target = config.repositories_dir.join("group/mirrored");
        assert_eq!(resp[0], protocol::RES_OK);
        assert_eq!(git_config(&target, "repository.rngit.type"), "mirror");
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

        let existing = handle_fork(
            &config,
            &access,
            &protocol::remote_clone_request("group/existing", "unused"),
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
        let fork_req =
            protocol::remote_clone_request("group/forked", source.to_str().expect("utf-8 path"));
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
        let remote_pubkey: [u8; 64] = identity.get_public_key().unwrap().try_into().unwrap();
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
        let remote_pubkey: [u8; 64] = identity.get_public_key().unwrap().try_into().unwrap();
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
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        run_git(&source, &["init"]);
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
}
