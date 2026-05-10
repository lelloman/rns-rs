use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};

use crate::acl::Operation;
use crate::protocol;
use crate::util::validate_repo_name;
use crate::util::{hex, parse_hex_16};
use crate::{Error, Result};

pub const WORK_DOC_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkScope {
    Active,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkListScope {
    Active,
    Completed,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkInput {
    pub title: String,
    pub content: String,
    pub format: String,
    pub signature: Option<Vec<u8>>,
    pub author: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkEdit {
    pub title: Option<String>,
    pub content: Option<String>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCommentInput {
    pub content: String,
    pub format: String,
    pub signature: Option<Vec<u8>>,
    pub author: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCreated {
    pub id: u64,
    pub scope: WorkScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkSummary {
    pub id: u64,
    pub title: String,
    pub created: u64,
    pub edited: u64,
    pub author: String,
    pub format: String,
    pub comments: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkLists {
    pub active: Vec<WorkSummary>,
    pub completed: Vec<WorkSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDocument {
    pub id: u64,
    pub scope: WorkScope,
    pub title: String,
    pub content: String,
    pub created: u64,
    pub edited: u64,
    pub author: String,
    pub author_hash: [u8; 16],
    pub format: String,
    pub signature: Option<Vec<u8>>,
    pub comments: Vec<WorkComment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkComment {
    pub id: u64,
    pub content: String,
    pub created: u64,
    pub edited: u64,
    pub author: String,
    pub author_hash: [u8; 16],
    pub format: String,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRequest {
    pub repository: String,
    pub operation: String,
    pub step: Option<String>,
    pub scope: Option<String>,
    pub doc_id: Option<u64>,
    pub title: Option<String>,
    pub content: Option<String>,
    pub format: Option<String>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct StoredDocument {
    content: String,
    title: Option<String>,
    format: String,
    created: u64,
    edited: u64,
    author: [u8; 16],
    signature: Option<Vec<u8>>,
}

pub fn work_sidecar_path(repo: &Path) -> PathBuf {
    let mut name = repo.as_os_str().to_os_string();
    name.push(".work");
    PathBuf::from(name)
}

pub fn parse_request(data: &[u8]) -> Result<WorkRequest> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let repository = map_get_repository(map)
        .ok_or_else(|| Error::msg("request missing repository"))?
        .to_string();
    validate_repo_name(&repository)?;
    let operation = map_get(map, "operation")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg("request missing operation"))?
        .to_string();
    Ok(WorkRequest {
        repository,
        operation,
        step: map_get(map, "step")
            .and_then(Value::as_str)
            .map(str::to_string),
        scope: map_get(map, "scope")
            .and_then(Value::as_str)
            .map(str::to_string),
        doc_id: map_get(map, "doc_id")
            .and_then(Value::as_integer)
            .filter(|value| *value >= 0)
            .map(|value| value as u64),
        title: map_get(map, "title")
            .and_then(Value::as_str)
            .map(str::to_string),
        content: map_get(map, "content")
            .and_then(Value::as_str)
            .map(str::to_string),
        format: map_get(map, "format")
            .and_then(Value::as_str)
            .map(str::to_string),
        signature: map_get(map, "signature").and_then(value_to_signature),
    })
}

pub fn list_response(work_path: &Path, scope: WorkListScope) -> Result<Vec<u8>> {
    Ok(protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&lists_value(list_documents(work_path, scope)?)),
    ))
}

pub fn view_response(work_path: &Path, scope: WorkScope, doc_id: u64) -> Result<Vec<u8>> {
    match view_document(work_path, scope, doc_id)? {
        Some(document) => Ok(protocol::status_bytes(
            protocol::RES_OK,
            msgpack::pack(&document_value_response(document)),
        )),
        None => Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"document not found",
        )),
    }
}

pub fn created_response(created: WorkCreated) -> Vec<u8> {
    protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&Value::Map(vec![
            (Value::Str("id".into()), Value::UInt(created.id)),
            (
                Value::Str("scope".into()),
                Value::Str(created.scope.as_str().into()),
            ),
        ])),
    )
}

pub fn comment_response(comment_id: u64) -> Vec<u8> {
    protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&Value::Map(vec![(
            Value::Str("id".into()),
            Value::UInt(comment_id),
        )])),
    )
}

pub fn transition_response(doc_id: u64, scope: WorkScope) -> Vec<u8> {
    protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&Value::Map(vec![
            (Value::Str("id".into()), Value::UInt(doc_id)),
            (
                Value::Str("scope".into()),
                Value::Str(scope.as_str().into()),
            ),
        ])),
    )
}

pub fn permissions_response(content: String) -> Vec<u8> {
    protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&Value::Map(vec![(
            Value::Str("content".into()),
            Value::Str(content),
        )])),
    )
}

pub fn create_document(work_path: &Path, input: WorkInput) -> Result<WorkCreated> {
    let title = non_empty_trimmed(&input.title, "title is required")?;
    let content = non_empty_trimmed(&input.content, "content is required")?;
    let format = normalize_format(&input.format);
    validate_signature(input.signature.as_deref())?;
    validate_limit(title.len() + content.len() + format.len())?;

    let id = next_document_id(work_path)?;
    let now = unix_time();
    let document = StoredDocument {
        content,
        title: Some(title),
        format,
        created: now,
        edited: now,
        author: input.author,
        signature: input.signature,
    };
    let doc_dir = scope_dir(work_path, WorkScope::Active).join(id.to_string());
    write_document(&doc_dir.join("root"), &document)?;
    Ok(WorkCreated {
        id,
        scope: WorkScope::Active,
    })
}

pub fn list_documents(work_path: &Path, scope: WorkListScope) -> Result<WorkLists> {
    let mut lists = WorkLists::default();
    if matches!(scope, WorkListScope::Active | WorkListScope::All) {
        lists.active = list_scope(work_path, WorkScope::Active)?;
    }
    if matches!(scope, WorkListScope::Completed | WorkListScope::All) {
        lists.completed = list_scope(work_path, WorkScope::Completed)?;
    }
    Ok(lists)
}

pub fn view_document(
    work_path: &Path,
    scope: WorkScope,
    doc_id: u64,
) -> Result<Option<WorkDocument>> {
    let doc_dir = scope_dir(work_path, scope).join(doc_id.to_string());
    let root_path = doc_dir.join("root");
    if !root_path.is_file() {
        return Ok(None);
    }
    let doc = read_document(&root_path)?;
    Ok(Some(WorkDocument {
        id: doc_id,
        scope,
        title: doc.title.unwrap_or_else(|| "Untitled".to_string()),
        content: doc.content,
        created: doc.created,
        edited: doc.edited,
        author: hex(&doc.author),
        author_hash: doc.author,
        format: doc.format,
        signature: doc.signature,
        comments: list_comments(&doc_dir)?,
    }))
}

pub fn edit_document(
    work_path: &Path,
    scope: WorkScope,
    doc_id: u64,
    author: &[u8; 16],
    edit: WorkEdit,
) -> Result<()> {
    if edit.title.is_none() && edit.content.is_none() {
        return Err(Error::msg("no changes specified"));
    }
    validate_signature(edit.signature.as_deref())?;
    let size = edit.title.as_deref().map(str::len).unwrap_or(0)
        + edit.content.as_deref().map(str::len).unwrap_or(0);
    validate_limit(size)?;

    let root_path = root_path(work_path, scope, doc_id);
    let mut doc = read_existing_document(&root_path)?;
    ensure_author(&doc, author)?;
    if let Some(title) = edit.title {
        doc.title = Some(title.trim().to_string());
    }
    if let Some(content) = edit.content {
        doc.content = content.trim().to_string();
    }
    doc.edited = unix_time();
    doc.signature = edit.signature;
    write_document(&root_path, &doc)
}

pub fn delete_document(
    work_path: &Path,
    scope: WorkScope,
    doc_id: u64,
    author: &[u8; 16],
) -> Result<()> {
    let doc_dir = scope_dir(work_path, scope).join(doc_id.to_string());
    let doc = read_existing_document(&doc_dir.join("root"))?;
    ensure_author(&doc, author)?;
    fs::remove_dir_all(doc_dir)?;
    Ok(())
}

pub fn add_comment(
    work_path: &Path,
    scope: WorkScope,
    doc_id: u64,
    input: WorkCommentInput,
) -> Result<u64> {
    let content = non_empty_trimmed(&input.content, "content is required")?;
    let format = normalize_format(&input.format);
    validate_signature(input.signature.as_deref())?;
    validate_limit(content.len())?;

    let doc_dir = scope_dir(work_path, scope).join(doc_id.to_string());
    if !doc_dir.join("root").is_file() {
        return Err(Error::msg("document not found"));
    }
    let comment_id = next_numeric_child(&doc_dir)?;
    let now = unix_time();
    let comment = StoredDocument {
        content,
        title: None,
        format,
        created: now,
        edited: now,
        author: input.author,
        signature: input.signature,
    };
    write_document(&doc_dir.join(comment_id.to_string()), &comment)?;
    Ok(comment_id)
}

pub fn complete_document(work_path: &Path, doc_id: u64, author: &[u8; 16]) -> Result<()> {
    move_document(
        work_path,
        WorkScope::Active,
        WorkScope::Completed,
        doc_id,
        author,
    )
}

pub fn activate_document(work_path: &Path, doc_id: u64, author: &[u8; 16]) -> Result<()> {
    move_document(
        work_path,
        WorkScope::Completed,
        WorkScope::Active,
        doc_id,
        author,
    )
}

pub fn document_author(work_path: &Path, doc_id: u64) -> Result<[u8; 16]> {
    let doc_dir =
        find_document_dir(work_path, doc_id)?.ok_or_else(|| Error::msg("document not found"))?;
    Ok(read_existing_document(&doc_dir.join("root"))?.author)
}

pub fn document_permission_allows(
    work_path: &Path,
    doc_id: u64,
    op: Operation,
    identity: Option<&[u8; 16]>,
) -> Result<bool> {
    let path = permissions_path(work_path, doc_id);
    if !path.is_file() {
        return Ok(false);
    }
    let content = fs::read_to_string(path)?;
    if op != Operation::Admin
        && crate::acl::allowed_input_allows(&content, Operation::Admin, identity)?
    {
        return Ok(true);
    }
    crate::acl::allowed_input_allows(&content, op, identity)
}

pub fn get_document_permissions(work_path: &Path, doc_id: u64) -> Result<String> {
    find_document_dir(work_path, doc_id)?.ok_or_else(|| Error::msg("document not found"))?;
    let path = permissions_path(work_path, doc_id);
    if path.is_file() {
        Ok(fs::read_to_string(path)?)
    } else {
        Ok(String::new())
    }
}

pub fn set_document_permissions(work_path: &Path, doc_id: u64, content: &str) -> Result<()> {
    find_document_dir(work_path, doc_id)?.ok_or_else(|| Error::msg("document not found"))?;
    crate::acl::validate_allowed_input(content)?;
    fs::create_dir_all(work_path)?;
    let path = permissions_path(work_path, doc_id);
    let tmp = path.with_extension("allowed.tmp");
    fs::write(&tmp, content)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn move_document(
    work_path: &Path,
    from: WorkScope,
    to: WorkScope,
    doc_id: u64,
    author: &[u8; 16],
) -> Result<()> {
    let from_dir = scope_dir(work_path, from).join(doc_id.to_string());
    let doc = read_existing_document(&from_dir.join("root"))?;
    ensure_author(&doc, author)?;
    let to_base = scope_dir(work_path, to);
    fs::create_dir_all(&to_base)?;
    fs::rename(from_dir, to_base.join(doc_id.to_string()))?;
    Ok(())
}

fn list_scope(work_path: &Path, scope: WorkScope) -> Result<Vec<WorkSummary>> {
    let mut out = Vec::new();
    let folder = scope_dir(work_path, scope);
    if !folder.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(id) = entry.file_name().to_string_lossy().parse::<u64>().ok() else {
            continue;
        };
        let root_path = entry.path().join("root");
        if !root_path.is_file() {
            continue;
        }
        let doc = read_document(&root_path)?;
        out.push(WorkSummary {
            id,
            title: doc.title.unwrap_or_else(|| "Untitled".to_string()),
            created: doc.created,
            edited: doc.edited,
            author: hex(&doc.author),
            format: doc.format,
            comments: comment_count(&entry.path())?,
        });
    }
    out.sort_by(|a, b| {
        b.created
            .max(b.edited)
            .cmp(&a.created.max(a.edited))
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(out)
}

fn list_comments(doc_dir: &Path) -> Result<Vec<WorkComment>> {
    let mut comments = Vec::new();
    if !doc_dir.is_dir() {
        return Ok(comments);
    }
    for entry in fs::read_dir(doc_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(id) = entry.file_name().to_string_lossy().parse::<u64>().ok() else {
            continue;
        };
        let comment = read_document(&entry.path())?;
        comments.push(WorkComment {
            id,
            content: comment.content,
            created: comment.created,
            edited: comment.edited,
            author: hex(&comment.author),
            author_hash: comment.author,
            format: comment.format,
            signature: comment.signature,
        });
    }
    comments.sort_by_key(|comment| comment.id);
    Ok(comments)
}

fn comment_count(doc_dir: &Path) -> Result<u64> {
    Ok(list_comments(doc_dir)?.len() as u64)
}

fn next_document_id(work_path: &Path) -> Result<u64> {
    Ok(
        next_numeric_child(&scope_dir(work_path, WorkScope::Active))?.max(next_numeric_child(
            &scope_dir(work_path, WorkScope::Completed),
        )?),
    )
}

fn next_numeric_child(path: &Path) -> Result<u64> {
    if !path.is_dir() {
        return Ok(1);
    }
    let mut max_id = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if let Ok(id) = entry.file_name().to_string_lossy().parse::<u64>() {
            max_id = max_id.max(id);
        }
    }
    Ok(max_id + 1)
}

fn root_path(work_path: &Path, scope: WorkScope, doc_id: u64) -> PathBuf {
    scope_dir(work_path, scope)
        .join(doc_id.to_string())
        .join("root")
}

fn scope_dir(work_path: &Path, scope: WorkScope) -> PathBuf {
    work_path.join(scope.as_str())
}

fn permissions_path(work_path: &Path, doc_id: u64) -> PathBuf {
    work_path.join(format!("{doc_id}.allowed"))
}

fn find_document_dir(work_path: &Path, doc_id: u64) -> Result<Option<PathBuf>> {
    for scope in [WorkScope::Active, WorkScope::Completed] {
        let doc_dir = scope_dir(work_path, scope).join(doc_id.to_string());
        if doc_dir.join("root").is_file() {
            return Ok(Some(doc_dir));
        }
    }
    Ok(None)
}

impl WorkScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(WorkScope::Active),
            "completed" => Some(WorkScope::Completed),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WorkScope::Active => "active",
            WorkScope::Completed => "completed",
        }
    }
}

impl WorkListScope {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(WorkListScope::Active),
            "completed" => Some(WorkListScope::Completed),
            "all" => Some(WorkListScope::All),
            _ => None,
        }
    }
}

fn read_existing_document(path: &Path) -> Result<StoredDocument> {
    if !path.is_file() {
        return Err(Error::msg("document not found"));
    }
    read_document(path)
}

fn read_document(path: &Path) -> Result<StoredDocument> {
    let bytes = fs::read(path)?;
    let value =
        msgpack::unpack_exact(&bytes).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    stored_document_from_value(&value)
}

fn write_document(path: &Path, document: &StoredDocument) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::msg("document path has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, msgpack::pack(&document_value(document)))?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn document_value(document: &StoredDocument) -> Value {
    Value::Map(vec![
        (
            Value::Str("content".into()),
            Value::Str(document.content.clone()),
        ),
        (
            Value::Str("meta".into()),
            Value::Map(vec![
                (
                    Value::Str("format".into()),
                    Value::Str(document.format.clone()),
                ),
                (
                    Value::Str("title".into()),
                    document.title.clone().map(Value::Str).unwrap_or(Value::Nil),
                ),
                (Value::Str("created".into()), Value::UInt(document.created)),
                (Value::Str("edited".into()), Value::UInt(document.edited)),
                (
                    Value::Str("signature".into()),
                    document
                        .signature
                        .clone()
                        .map(Value::Bin)
                        .unwrap_or(Value::Nil),
                ),
                (
                    Value::Str("author".into()),
                    Value::Bin(document.author.to_vec()),
                ),
            ]),
        ),
    ])
}

fn lists_value(lists: WorkLists) -> Value {
    Value::Map(vec![
        (
            Value::Str("active".into()),
            Value::Array(lists.active.into_iter().map(summary_value).collect()),
        ),
        (
            Value::Str("completed".into()),
            Value::Array(lists.completed.into_iter().map(summary_value).collect()),
        ),
    ])
}

fn summary_value(summary: WorkSummary) -> Value {
    Value::Map(vec![
        (Value::Str("id".into()), Value::UInt(summary.id)),
        (Value::Str("title".into()), Value::Str(summary.title)),
        (Value::Str("created".into()), Value::UInt(summary.created)),
        (Value::Str("edited".into()), Value::UInt(summary.edited)),
        (Value::Str("author".into()), Value::Str(summary.author)),
        (Value::Str("format".into()), Value::Str(summary.format)),
        (Value::Str("comments".into()), Value::UInt(summary.comments)),
    ])
}

fn document_value_response(document: WorkDocument) -> Value {
    Value::Map(vec![
        (Value::Str("id".into()), Value::UInt(document.id)),
        (
            Value::Str("scope".into()),
            Value::Str(document.scope.as_str().into()),
        ),
        (Value::Str("content".into()), Value::Str(document.content)),
        (
            Value::Str("comments".into()),
            Value::Array(document.comments.into_iter().map(comment_value).collect()),
        ),
        (
            Value::Str("meta".into()),
            Value::Map(vec![
                (Value::Str("title".into()), Value::Str(document.title)),
                (Value::Str("created".into()), Value::UInt(document.created)),
                (Value::Str("edited".into()), Value::UInt(document.edited)),
                (Value::Str("author".into()), Value::Str(document.author)),
                (Value::Str("format".into()), Value::Str(document.format)),
            ]),
        ),
    ])
}

fn comment_value(comment: WorkComment) -> Value {
    Value::Map(vec![
        (Value::Str("id".into()), Value::UInt(comment.id)),
        (Value::Str("content".into()), Value::Str(comment.content)),
        (Value::Str("created".into()), Value::UInt(comment.created)),
        (Value::Str("edited".into()), Value::UInt(comment.edited)),
        (Value::Str("author".into()), Value::Str(comment.author)),
        (Value::Str("format".into()), Value::Str(comment.format)),
    ])
}

fn stored_document_from_value(value: &Value) -> Result<StoredDocument> {
    let content = value
        .map_get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let meta = value
        .map_get("meta")
        .and_then(Value::as_map)
        .ok_or_else(|| Error::msg("work document missing metadata"))?;
    let title = map_get(meta, "title")
        .and_then(Value::as_str)
        .map(str::to_string);
    let format = map_get(meta, "format")
        .and_then(Value::as_str)
        .map(normalize_format)
        .unwrap_or_else(|| "markdown".to_string());
    let created = map_get(meta, "created")
        .and_then(Value::as_number)
        .unwrap_or(0.0)
        .max(0.0) as u64;
    let edited = map_get(meta, "edited")
        .and_then(Value::as_number)
        .unwrap_or(0.0)
        .max(0.0) as u64;
    let author = map_get(meta, "author")
        .and_then(value_to_author)
        .unwrap_or([0; 16]);
    let signature = map_get(meta, "signature").and_then(value_to_signature);
    Ok(StoredDocument {
        content,
        title,
        format,
        created,
        edited,
        author,
        signature,
    })
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(map_key, value)| match map_key {
        Value::Str(map_key) if map_key == key => Some(value),
        _ => None,
    })
}

fn map_get_repository<'a>(map: &'a [(Value, Value)]) -> Option<&'a str> {
    map.iter().find_map(|(key, value)| match key {
        Value::UInt(v) if *v == protocol::IDX_REPOSITORY => value.as_str(),
        Value::Str(v) if v == "repository" => value.as_str(),
        _ => None,
    })
}

fn value_to_author(value: &Value) -> Option<[u8; 16]> {
    match value {
        Value::Bin(bytes) if bytes.len() == 16 => bytes.as_slice().try_into().ok(),
        Value::Str(value) => parse_hex_16(value).ok(),
        _ => None,
    }
}

fn value_to_signature(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bin(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

fn normalize_format(value: &str) -> String {
    match value {
        "micron" => "micron".to_string(),
        _ => "markdown".to_string(),
    }
}

fn non_empty_trimmed(value: &str, message: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        Err(Error::msg(message))
    } else {
        Ok(value.to_string())
    }
}

fn validate_limit(size: usize) -> Result<()> {
    if size > WORK_DOC_LIMIT {
        Err(Error::msg("content limit exceeded"))
    } else {
        Ok(())
    }
}

fn validate_signature(signature: Option<&[u8]>) -> Result<()> {
    if signature.is_some_and(|signature| signature.len() != 64) {
        Err(Error::msg("invalid signature"))
    } else {
        Ok(())
    }
}

fn ensure_author(document: &StoredDocument, author: &[u8; 16]) -> Result<()> {
    if &document.author == author {
        Ok(())
    } else {
        Err(Error::msg("no access, not author"))
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHOR: [u8; 16] = [0x11; 16];
    const OTHER: [u8; 16] = [0x22; 16];

    #[test]
    fn work_sidecar_path_appends_work_extension_to_repository_path() {
        assert_eq!(
            work_sidecar_path(Path::new("/tmp/repos/group/repo")),
            PathBuf::from("/tmp/repos/group/repo.work")
        );
    }

    #[test]
    fn create_list_and_view_document_round_trip_msgpack_storage() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");

        let created = create_document(
            &work_path,
            WorkInput {
                title: "  First task  ".into(),
                content: "  Do the thing  ".into(),
                format: "unknown".into(),
                signature: None,
                author: AUTHOR,
            },
        )
        .unwrap();
        assert_eq!(
            created,
            WorkCreated {
                id: 1,
                scope: WorkScope::Active
            }
        );
        assert!(work_path.join("active/1/root").is_file());

        let raw = fs::read(work_path.join("active/1/root")).unwrap();
        let stored = msgpack::unpack_exact(&raw).unwrap();
        assert_eq!(
            stored.map_get("content").and_then(Value::as_str),
            Some("Do the thing")
        );
        assert_eq!(
            stored
                .map_get("meta")
                .and_then(Value::as_map)
                .and_then(|meta| map_get(meta, "format"))
                .and_then(Value::as_str),
            Some("markdown")
        );

        let lists = list_documents(&work_path, WorkListScope::All).unwrap();
        assert_eq!(lists.active.len(), 1);
        assert_eq!(lists.completed.len(), 0);
        assert_eq!(lists.active[0].title, "First task");
        assert_eq!(lists.active[0].author, "11111111111111111111111111111111");
        assert_eq!(lists.active[0].comments, 0);

        let document = view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .unwrap();
        assert_eq!(document.title, "First task");
        assert_eq!(document.content, "Do the thing");
        assert_eq!(document.format, "markdown");
        assert_eq!(document.author_hash, AUTHOR);
        assert!(document.comments.is_empty());
    }

    #[test]
    fn document_ids_are_allocated_across_active_and_completed_scopes() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");

        assert_eq!(create_sample(&work_path, "one").unwrap().id, 1);
        complete_document(&work_path, 1, &AUTHOR).unwrap();
        assert_eq!(create_sample(&work_path, "two").unwrap().id, 2);

        let lists = list_documents(&work_path, WorkListScope::All).unwrap();
        assert_eq!(lists.active[0].id, 2);
        assert_eq!(lists.completed[0].id, 1);
    }

    #[test]
    fn document_lists_sort_by_latest_created_or_edited_activity() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");

        assert_eq!(create_sample(&work_path, "older edited").unwrap().id, 1);
        assert_eq!(create_sample(&work_path, "newer untouched").unwrap().id, 2);
        let mut first = read_document(&root_path(&work_path, WorkScope::Active, 1)).unwrap();
        first.edited = first.created + 10_000;
        write_document(&root_path(&work_path, WorkScope::Active, 1), &first).unwrap();

        let lists = list_documents(&work_path, WorkListScope::Active).unwrap();
        let ids: Vec<_> = lists.active.iter().map(|doc| doc.id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn comments_are_numbered_counted_and_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");
        create_sample(&work_path, "one").unwrap();

        fs::write(
            work_path.join("active/1/9"),
            fs::read(work_path.join("active/1/root")).unwrap(),
        )
        .unwrap();
        let comment_id = add_comment(
            &work_path,
            WorkScope::Active,
            1,
            WorkCommentInput {
                content: "  update  ".into(),
                format: "micron".into(),
                signature: Some(vec![0xAA; 64]),
                author: OTHER,
            },
        )
        .unwrap();
        assert_eq!(comment_id, 10);

        let lists = list_documents(&work_path, WorkListScope::Active).unwrap();
        assert_eq!(lists.active[0].comments, 2);

        let document = view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .unwrap();
        let ids: Vec<_> = document.comments.iter().map(|comment| comment.id).collect();
        assert_eq!(ids, vec![9, 10]);
        assert_eq!(document.comments[1].content, "update");
        assert_eq!(document.comments[1].format, "micron");
        assert_eq!(document.comments[1].signature, Some(vec![0xAA; 64]));
        assert_eq!(document.comments[1].author_hash, OTHER);
    }

    #[test]
    fn edit_delete_complete_and_activate_require_document_author() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");
        create_sample(&work_path, "one").unwrap();

        assert!(edit_document(
            &work_path,
            WorkScope::Active,
            1,
            &OTHER,
            WorkEdit {
                title: Some("nope".into()),
                content: None,
                signature: None,
            },
        )
        .is_err());
        edit_document(
            &work_path,
            WorkScope::Active,
            1,
            &AUTHOR,
            WorkEdit {
                title: Some("  updated title ".into()),
                content: Some(" updated content ".into()),
                signature: Some(vec![0x55; 64]),
            },
        )
        .unwrap();
        let document = view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .unwrap();
        assert_eq!(document.title, "updated title");
        assert_eq!(document.content, "updated content");
        assert_eq!(document.signature, Some(vec![0x55; 64]));

        assert!(complete_document(&work_path, 1, &OTHER).is_err());
        complete_document(&work_path, 1, &AUTHOR).unwrap();
        assert!(view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .is_none());
        assert!(view_document(&work_path, WorkScope::Completed, 1)
            .unwrap()
            .is_some());

        assert!(activate_document(&work_path, 1, &OTHER).is_err());
        activate_document(&work_path, 1, &AUTHOR).unwrap();
        assert!(view_document(&work_path, WorkScope::Completed, 1)
            .unwrap()
            .is_none());
        assert!(view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .is_some());

        assert!(delete_document(&work_path, WorkScope::Active, 1, &OTHER).is_err());
        delete_document(&work_path, WorkScope::Active, 1, &AUTHOR).unwrap();
        assert!(view_document(&work_path, WorkScope::Active, 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_invalid_document_input() {
        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");

        assert!(create_document(
            &work_path,
            WorkInput {
                title: " ".into(),
                content: "content".into(),
                format: "markdown".into(),
                signature: None,
                author: AUTHOR,
            },
        )
        .is_err());
        assert!(create_document(
            &work_path,
            WorkInput {
                title: "title".into(),
                content: " ".into(),
                format: "markdown".into(),
                signature: None,
                author: AUTHOR,
            },
        )
        .is_err());
        assert!(create_document(
            &work_path,
            WorkInput {
                title: "title".into(),
                content: "content".into(),
                format: "markdown".into(),
                signature: Some(vec![0; 63]),
                author: AUTHOR,
            },
        )
        .is_err());
    }

    #[test]
    fn document_content_limit_matches_upstream_256_kib() {
        assert_eq!(WORK_DOC_LIMIT, 256 * 1024);

        let tmp = tempfile::tempdir().unwrap();
        let work_path = tmp.path().join("repo.work");
        let title = "title";
        let format = "markdown";
        let at_limit = "x".repeat(WORK_DOC_LIMIT - title.len() - format.len());
        let over_limit = "x".repeat(WORK_DOC_LIMIT - title.len() - format.len() + 1);

        create_document(
            &work_path,
            WorkInput {
                title: title.into(),
                content: at_limit,
                format: format.into(),
                signature: None,
                author: AUTHOR,
            },
        )
        .unwrap();

        let err = create_document(
            &work_path,
            WorkInput {
                title: title.into(),
                content: over_limit,
                format: format.into(),
                signature: None,
                author: AUTHOR,
            },
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "content limit exceeded");
    }

    fn create_sample(work_path: &Path, title: &str) -> Result<WorkCreated> {
        create_document(
            work_path,
            WorkInput {
                title: title.into(),
                content: "content".into(),
                format: "markdown".into(),
                signature: None,
                author: AUTHOR,
            },
        )
    }
}
