//! Repository request handlers: list, fetch, push, create, fork, mirror,
//! sync and delete.

use rns_net::RequestResponse;

use super::remote_error_response;
use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::util::hex;
use crate::{git, Result};

pub(crate) fn handle_list(
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

/// Handles a [`protocol::PATH_FETCH`] request from `remote` (identity hash and
/// public key, `None` if unidentified). On success the response is a resource
/// carrying a git bundle, or an empty `RES_OK` status when there is nothing to
/// send; refusals and invalid requests are status responses.
///
/// # Errors
/// The request is not a valid fetch request, or the access rules cannot be read.
pub fn handle_fetch(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<RequestResponse> {
    let (repo, have, requested_refs) = protocol::parse_fetch_request(data)?;
    let requested_refnames = requested_refs
        .iter()
        .map(|(_, refname)| refname.clone())
        .collect::<Vec<_>>();
    let requested_shas = requested_refs
        .iter()
        .map(|(sha, _)| sha.clone())
        .collect::<Vec<_>>();
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
    if let Err(err) = git::validate_shas(&requested_shas) {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            err.to_string(),
        )));
    }
    for refname in &requested_refnames {
        if let Err(err) = git::validate_namespaced_ref(refname) {
            return Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_INVALID_REQ,
                err.to_string(),
            )));
        }
    }
    let path = git::repository_path(&config.repositories_dir, &repo)?;
    match git::create_bundle_for_refs(&path, &have, &requested_refnames) {
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

/// Handles a [`protocol::PATH_PUSH`] request and returns the status response.
/// Pushing to a repository that does not exist creates it, which needs create
/// access; otherwise write access is needed.
///
/// # Errors
/// The request is not a valid push request, the repository name is invalid, or
/// the access rules cannot be read.
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

pub(crate) fn handle_create(
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

pub(crate) fn handle_fork(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    handle_remote_clone(config, access, data, remote, "fork")
}

pub(crate) fn handle_mirror(
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

pub(crate) fn handle_sync(
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

pub(crate) fn handle_delete(
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
