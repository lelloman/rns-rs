//! Release request handlers.

use rns_net::RequestResponse;

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::{git, Result};

/// Handles a [`protocol::PATH_RELEASE`] request like
/// [`handle_release_response`], but always returns status bytes: a resource
/// response is returned as its data behind a `RES_OK` code.
pub fn handle_release(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&([u8; 16], [u8; 64])>,
) -> Result<Vec<u8>> {
    match handle_release_response(config, access, data, remote)? {
        RequestResponse::Bytes(data) => Ok(data),
        RequestResponse::Resource { data, .. } | RequestResponse::File { data, .. } => {
            Ok(protocol::status_bytes(protocol::RES_OK, data))
        }
    }
}

/// Handles a [`protocol::PATH_RELEASE`] request. Unidentified peers are refused.
/// `list`, `view` and `fetch` need read access; `create`, `delete` and `latest`
/// also need release access. A `fetch` of an artifact may be answered with a resource.
///
/// # Errors
/// The request does not parse, or the access rules cannot be read.
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
