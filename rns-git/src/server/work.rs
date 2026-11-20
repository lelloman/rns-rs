//! Work document requests.

use std::path::Path;

use rns_crypto::identity::Identity;

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::work::{WorkRequest, WorkScope};
use crate::{git, Error, Result};

/// The identified peer a work request comes from.
#[derive(Clone, Copy)]
struct WorkPeer<'a> {
    hash: &'a [u8; 16],
    pubkey: &'a [u8; 64],
}

/// What the peer may do with work documents in one repository, after
/// per-document grants for the requested document are applied.
struct WorkRights {
    interact: bool,
    propose: bool,
    write: bool,
}

impl WorkRights {
    fn resolve(
        access: &Access,
        repo: &str,
        work_path: &Path,
        request: &WorkRequest,
        remote_hash: &[u8; 16],
    ) -> Result<Self> {
        let doc_allows = |doc_id, operation| {
            crate::work::document_permission_allows(work_path, doc_id, operation, Some(remote_hash))
        };
        let mut interact = access.allows(Operation::Interact, repo, Some(remote_hash))?;
        let propose = access.allows(Operation::Propose, repo, Some(remote_hash))?;
        if request.operation == "comment" {
            if let Some(doc_id) = request.doc_id {
                interact |= doc_allows(doc_id, Operation::Interact)?;
            }
        }
        let mut write = access.allows(Operation::Write, repo, Some(remote_hash))?;
        if request.operation == "edit" {
            if let Some(doc_id) = request.doc_id {
                interact |= doc_allows(doc_id, Operation::Interact)?;
                write |= doc_allows(doc_id, Operation::Write)?;
            }
        }
        Ok(Self {
            interact,
            propose,
            write,
        })
    }

    fn manage(&self) -> bool {
        self.interact && self.write
    }

    fn permits(&self, operation: &str) -> bool {
        match operation {
            "list" | "view" => true,
            "comment" => self.interact,
            "propose" => self.propose,
            "create" | "edit" | "delete" | "complete" | "activate" => self.manage(),
            "perms" => true,
            _ => false,
        }
    }
}

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
    let peer = WorkPeer {
        hash: remote_hash,
        pubkey: remote_pubkey,
    };
    let request = crate::work::parse_request(data)?;
    let repo = request.repository.as_str();
    if !access.allows(Operation::Read, repo, Some(remote_hash))? {
        return Ok(not_found());
    }
    let repository_path = git::repository_path(&config.repositories_dir, repo)?;
    if !git::is_bare_repository(&repository_path) {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"repository not found",
        ));
    }
    let work_path = crate::work::work_sidecar_path(&repository_path);
    let rights = WorkRights::resolve(access, repo, &work_path, &request, remote_hash)?;
    if !rights.permits(&request.operation) {
        return Ok(not_allowed());
    }

    match request.operation.as_str() {
        "list" => work_list(&work_path, &request),
        "view" => work_view(&work_path, &request),
        "create" => work_create(&work_path, request, peer),
        "propose" => work_propose(&work_path, request, peer),
        "edit" => work_edit(&work_path, request, peer),
        "delete" => work_delete(&work_path, &request, remote_hash),
        "comment" => work_comment(&work_path, request, remote_hash),
        "complete" => {
            let doc_id = required_doc_id(&request)?;
            let admin = work_document_admin(access, repo, &work_path, doc_id, remote_hash)?;
            work_status_result(
                crate::work::complete_document_authorized(&work_path, doc_id, remote_hash, admin)
                    .map(|_| crate::work::transition_response(doc_id, WorkScope::Completed)),
            )
        }
        "activate" => {
            let doc_id = required_doc_id(&request)?;
            let admin = work_document_admin(access, repo, &work_path, doc_id, remote_hash)?;
            work_status_result(
                crate::work::activate_document_authorized(&work_path, doc_id, remote_hash, admin)
                    .map(|_| crate::work::transition_response(doc_id, WorkScope::Active)),
            )
        }
        "perms" => work_perms(&work_path, &request, remote_hash, rights.manage()),
        _ => Ok(invalid_request()),
    }
}

fn work_list(work_path: &Path, request: &WorkRequest) -> Result<Vec<u8>> {
    let scope = request
        .scope
        .as_deref()
        .map(crate::work::WorkListScope::parse)
        .unwrap_or(Some(crate::work::WorkListScope::Active))
        .ok_or_else(|| Error::msg("invalid scope"))?;
    crate::work::list_response(work_path, scope)
}

fn work_view(work_path: &Path, request: &WorkRequest) -> Result<Vec<u8>> {
    let doc_id = required_doc_id(request)?;
    match work_scope_for_document(work_path, request.scope.as_deref(), doc_id)? {
        Some(scope) => crate::work::view_response(work_path, scope, doc_id),
        None => Ok(not_found()),
    }
}

fn work_create(work_path: &Path, request: WorkRequest, peer: WorkPeer<'_>) -> Result<Vec<u8>> {
    work_status_result(
        new_document_input(request, peer, false)
            .and_then(|input| crate::work::create_document(work_path, input))
            .map(crate::work::created_response),
    )
}

fn work_propose(work_path: &Path, request: WorkRequest, peer: WorkPeer<'_>) -> Result<Vec<u8>> {
    work_status_result(
        new_document_input(request, peer, true)
            .and_then(|input| crate::work::propose_document(work_path, input))
            .map(crate::work::created_response),
    )
}

/// Builds the input for a new document from `request`, checking its
/// signature against the peer's key. Proposals must be signed.
fn new_document_input(
    request: WorkRequest,
    peer: WorkPeer<'_>,
    signature_required: bool,
) -> Result<crate::work::WorkInput> {
    let content = request.content.unwrap_or_default();
    let signature = request.signature;
    let identity = validate_work_signature(&content, signature.as_deref(), peer.pubkey)?;
    if signature_required && identity.is_none() {
        return Err(Error::msg("no signature provided"));
    }
    Ok(crate::work::WorkInput {
        title: request.title.unwrap_or_default(),
        content,
        format: request.format.unwrap_or_else(|| "markdown".into()),
        signature,
        identity,
        author: *peer.hash,
    })
}

fn work_edit(work_path: &Path, request: WorkRequest, peer: WorkPeer<'_>) -> Result<Vec<u8>> {
    let doc_id = required_doc_id(&request)?;
    let signature = request.signature;
    let identity = if let Some(content) = request.content.as_deref() {
        match validate_work_signature(content, signature.as_deref(), peer.pubkey) {
            Ok(identity) => identity,
            Err(err) => return Ok(work_error_response(err)),
        }
    } else {
        None
    };
    let Some(scope) = work_scope_for_document(work_path, request.scope.as_deref(), doc_id)? else {
        return Ok(not_found());
    };
    work_status_result(
        crate::work::edit_document(
            work_path,
            scope,
            doc_id,
            peer.hash,
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

fn work_delete(work_path: &Path, request: &WorkRequest, remote_hash: &[u8; 16]) -> Result<Vec<u8>> {
    let doc_id = required_doc_id(request)?;
    let scope = work_scope(request.scope.as_deref())?;
    work_status_result(
        crate::work::delete_document(work_path, scope, doc_id, remote_hash)
            .map(|_| protocol::status_bytes(protocol::RES_OK, b"")),
    )
}

fn work_comment(work_path: &Path, request: WorkRequest, remote_hash: &[u8; 16]) -> Result<Vec<u8>> {
    let doc_id = required_doc_id(&request)?;
    let scope = work_scope(request.scope.as_deref())?;
    work_status_result(
        crate::work::add_comment(
            work_path,
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

/// Whether the peer administers document `doc_id`: through the repository
/// or the document's own grants, unless the document denies admin outright.
fn work_document_admin(
    access: &Access,
    repo: &str,
    work_path: &Path,
    doc_id: u64,
    remote_hash: &[u8; 16],
) -> Result<bool> {
    Ok(
        !crate::work::document_permission_denies(work_path, doc_id, Operation::Admin)?
            && (access.allows(Operation::Admin, repo, Some(remote_hash))?
                || crate::work::document_permission_allows(
                    work_path,
                    doc_id,
                    Operation::Admin,
                    Some(remote_hash),
                )?),
    )
}

fn work_perms(
    work_path: &Path,
    request: &WorkRequest,
    remote_hash: &[u8; 16],
    manage_access: bool,
) -> Result<Vec<u8>> {
    let doc_id = required_doc_id(request)?;
    let allowed = match work_permissions_allowed(work_path, doc_id, remote_hash, manage_access) {
        Ok(allowed) => allowed,
        Err(err) => return Ok(work_error_response(err)),
    };
    if !allowed {
        return Ok(not_allowed());
    }
    match request.step.as_deref() {
        Some("get") => work_status_result(
            crate::work::get_document_permissions(work_path, doc_id)
                .map(crate::work::permissions_response),
        ),
        Some("set") => work_status_result(
            crate::work::set_document_permissions(
                work_path,
                doc_id,
                request.content.as_deref().unwrap_or(""),
            )
            .map(|_| protocol::status_bytes(protocol::RES_OK, b"")),
        ),
        Some(_) => Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid step",
        )),
        None => Ok(invalid_request()),
    }
}

fn required_doc_id(request: &WorkRequest) -> Result<u64> {
    request
        .doc_id
        .ok_or_else(|| Error::msg("no document ID specified"))
}

fn not_found() -> Vec<u8> {
    protocol::status_bytes(protocol::RES_NOT_FOUND, b"not found")
}

fn not_allowed() -> Vec<u8> {
    protocol::status_bytes(protocol::RES_DISALLOWED, b"not allowed")
}

fn invalid_request() -> Vec<u8> {
    protocol::status_bytes(protocol::RES_INVALID_REQ, b"invalid request")
}

fn work_permissions_allowed(
    work_path: &Path,
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
    work_path: &Path,
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
