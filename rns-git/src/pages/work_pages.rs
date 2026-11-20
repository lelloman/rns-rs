//! Work document pages and downloads.

use super::*;

pub(super) fn render_work_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let scope = var(vars, "scope").unwrap_or("active");
    let list_scope =
        crate::work::WorkListScope::parse(scope).ok_or_else(|| Error::msg("invalid scope"))?;
    let work_path = crate::work::work_sidecar_path(&repository);
    let mut lists = crate::work::list_documents(&work_path, crate::work::WorkListScope::All)?;
    retain_readable_work_documents(&work_path, &mut lists.active)?;
    retain_readable_work_documents(&work_path, &mut lists.completed)?;
    retain_readable_work_documents(&work_path, &mut lists.proposed)?;
    let total = lists.active.len() + lists.completed.len() + lists.proposed.len();
    let mut out = format!(
        ">>\n{} / {} / {} / work\n\n>Work Documents\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
    );
    let tabs = [
        m_link_raw(
            &format!("Active ({})", lists.active.len()),
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "active")],
        ),
        m_link_raw(
            &format!("Completed ({})", lists.completed.len()),
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "completed")],
        ),
        m_link_raw(
            &format!("Proposed ({})", lists.proposed.len()),
            PATH_WORK,
            &[("g", &group), ("r", &repo), ("scope", "proposed")],
        ),
        m_link_raw(
            &format!("All ({total})"),
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

pub(super) fn retain_readable_work_documents(
    work_path: &Path,
    docs: &mut Vec<crate::work::WorkSummary>,
) -> Result<()> {
    let mut readable = Vec::with_capacity(docs.len());
    for doc in docs.drain(..) {
        if !crate::work::document_permission_denies(work_path, doc.id, Operation::Read)? {
            readable.push(doc);
        }
    }
    *docs = readable;
    Ok(())
}

pub(super) fn append_work_section(
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
    out.push_str(&format!(">{title}\n\n"));
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

pub(super) fn render_work_doc_page(
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
    if crate::work::document_permission_denies(&work_path, id, Operation::Read)? {
        return Ok(
            ">Work Document Not Found\n\nThe requested work document was not found.\n".into(),
        );
    }
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

pub(super) fn work_signature_status(document: &crate::work::WorkDocument) -> &'static str {
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
    let Ok(identity) = Identity::from_public_key(&public_key) else {
        return "Not valid";
    };
    if identity.verify(signature, document.content.as_bytes()) {
        "Valid"
    } else {
        "Not valid"
    }
}

pub(super) fn resolve_work_document(
    work_path: &Path,
    requested_scope: &str,
    id: u64,
) -> Result<(crate::work::WorkScope, Option<crate::work::WorkDocument>)> {
    if requested_scope != "all" {
        // One list; a scope it does not know reads as the active one.
        let scope = crate::work::WorkScope::parse(requested_scope)
            .unwrap_or(crate::work::WorkScope::Active);
        return Ok((scope, crate::work::view_document(work_path, scope, id)?));
    }
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

pub(super) fn append_formatted_content(out: &mut String, format: &str, content: &str) {
    match format {
        "micron" => out.push_str(content),
        "markdown" => out.push_str(&markdown_to_micron(content)),
        _ => out.push_str(&m_escape(content)),
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
}

pub(crate) fn download_work_document(
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
    if crate::work::document_permission_denies(&work_path, id, Operation::Read)? {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"work document not found",
        )));
    }
    crate::stats::record_download(config, &format!("{group}/{repo}"), remote);
    Ok(RequestResponse::Resource {
        data: document.content.into_bytes(),
        metadata: Some(protocol::metadata_status(protocol::RES_OK)),
        auto_compress: true,
    })
}
