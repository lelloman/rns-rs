//! Work document requests.

use rns_crypto::identity::Identity;

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::{git, Error, Result};

pub(crate) fn handle_work(
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
            match work_scope_for_document(&work_path, request.scope.as_deref(), doc_id)? {
                Some(scope) => crate::work::view_response(&work_path, scope, doc_id),
                None => Ok(protocol::status_bytes(
                    protocol::RES_NOT_FOUND,
                    b"not found",
                )),
            }
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
            let signature = request.signature;
            let identity = if let Some(content) = request.content.as_deref() {
                match validate_work_signature(content, signature.as_deref(), remote_pubkey) {
                    Ok(identity) => identity,
                    Err(err) => return Ok(work_error_response(err)),
                }
            } else {
                None
            };
            match work_scope_for_document(&work_path, request.scope.as_deref(), doc_id)? {
                Some(scope) => work_status_result(
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
                ),
                None => Ok(protocol::status_bytes(
                    protocol::RES_NOT_FOUND,
                    b"not found",
                )),
            }
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
            let admin =
                !crate::work::document_permission_denies(&work_path, doc_id, Operation::Admin)?
                    && (access.allows(Operation::Admin, repo, Some(remote_hash))?
                        || crate::work::document_permission_allows(
                            &work_path,
                            doc_id,
                            Operation::Admin,
                            Some(remote_hash),
                        )?);
            work_status_result(
                crate::work::complete_document_authorized(&work_path, doc_id, remote_hash, admin)
                    .map(|_| {
                        crate::work::transition_response(doc_id, crate::work::WorkScope::Completed)
                    }),
            )
        }
        "activate" => {
            let doc_id = request
                .doc_id
                .ok_or_else(|| Error::msg("no document ID specified"))?;
            let admin =
                !crate::work::document_permission_denies(&work_path, doc_id, Operation::Admin)?
                    && (access.allows(Operation::Admin, repo, Some(remote_hash))?
                        || crate::work::document_permission_allows(
                            &work_path,
                            doc_id,
                            Operation::Admin,
                            Some(remote_hash),
                        )?);
            work_status_result(
                crate::work::activate_document_authorized(&work_path, doc_id, remote_hash, admin)
                    .map(|_| {
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
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return Err(Error::msg("invalid signature"));
    };
    let identity =
        Identity::from_public_key(remote_pubkey).map_err(|_| Error::msg("invalid signature"))?;
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

fn work_scope_for_document(
    work_path: &std::path::Path,
    scope: Option<&str>,
    doc_id: u64,
) -> Result<Option<crate::work::WorkScope>> {
    match scope.unwrap_or("active") {
        "all" => crate::work::find_document_scope(work_path, doc_id),
        value => crate::work::WorkScope::parse(value)
            .map(Some)
            .ok_or_else(|| Error::msg("invalid scope")),
    }
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
