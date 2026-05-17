use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rns_core::msgpack::{self, Value};

use crate::protocol;
use crate::util::{hex, validate_repo_name};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct ReleaseSummary {
    pub tag: String,
    pub hash: String,
    pub created: u64,
    pub status: String,
    pub created_by: String,
    pub preview: String,
    pub preview_format: String,
    pub artifacts: u64,
}

#[derive(Debug, Clone)]
pub struct ReleaseData {
    pub tag: String,
    pub hash: String,
    pub created: u64,
    pub status: String,
    pub created_by: String,
    pub notes: String,
    pub notes_format: String,
    pub artifacts: Vec<Artifact>,
    pub thanks: u64,
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ReleaseRequest {
    pub repository: String,
    pub operation: String,
    pub tag: Option<String>,
    pub step: Option<String>,
    pub hash: Option<String>,
    pub notes: Option<String>,
    pub notes_format: Option<String>,
    pub artifact_name: Option<String>,
    pub artifact_data: Option<Vec<u8>>,
}

pub fn parse_request(data: &[u8]) -> Result<ReleaseRequest> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let repository = map_get_repository(map)
        .ok_or_else(|| Error::msg("request missing repository"))?
        .to_string();
    validate_repo_name(&repository)?;
    let operation = map_get_str(map, "operation")
        .ok_or_else(|| Error::msg("request missing operation"))?
        .to_string();
    Ok(ReleaseRequest {
        repository,
        operation,
        tag: map_get_str(map, "tag").map(ToOwned::to_owned),
        step: map_get_str(map, "step").map(ToOwned::to_owned),
        hash: map_get_str(map, "hash").map(ToOwned::to_owned),
        notes: map_get_str(map, "notes").map(ToOwned::to_owned),
        notes_format: map_get_str(map, "notes_format").map(ToOwned::to_owned),
        artifact_name: map_get_str(map, "artifact_name").map(ToOwned::to_owned),
        artifact_data: map_get(map, "artifact_data").and_then(value_to_bytes),
    })
}

pub fn release_sidecar_path(repo: &Path) -> PathBuf {
    sidecar_path(repo, "releases")
}

pub fn list_releases(releases_path: &Path) -> Result<Vec<ReleaseSummary>> {
    let mut releases = Vec::new();
    if !releases_path.is_dir() {
        return Ok(releases);
    }
    for entry in fs::read_dir(releases_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let release_dir = entry.path();
        let meta_path = release_dir.join("META");
        if !meta_path.is_file() {
            continue;
        }
        let meta = read_meta(&meta_path)?;
        let tag = meta_get(&meta, "tag")
            .unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
        let (preview, preview_format) = notes_preview(&release_dir)?;
        releases.push(ReleaseSummary {
            tag,
            hash: meta_get(&meta, "hash").unwrap_or_default(),
            created: meta_get(&meta, "created")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            status: meta_get(&meta, "status").unwrap_or_else(|| "unknown".to_string()),
            created_by: meta_get(&meta, "created_by").unwrap_or_default(),
            preview,
            preview_format,
            artifacts: artifact_count(&release_dir)?,
        });
    }
    releases.sort_by(|a, b| b.created.cmp(&a.created));
    Ok(releases)
}

pub fn release_data(releases_path: &Path, tag: &str) -> Result<Option<ReleaseData>> {
    let tag = clean_tag(tag).ok_or_else(|| Error::msg("invalid tag name"))?;
    let release_dir = releases_path.join(&tag);
    if !release_dir.is_dir() {
        return Ok(None);
    }
    let meta_path = release_dir.join("META");
    if !meta_path.is_file() {
        return Ok(None);
    }
    let meta = read_meta(&meta_path)?;
    let (notes, notes_format) = read_notes(&release_dir)?;
    Ok(Some(ReleaseData {
        tag: meta_get(&meta, "tag").unwrap_or(tag),
        hash: meta_get(&meta, "hash").unwrap_or_default(),
        created: meta_get(&meta, "created")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        status: meta_get(&meta, "status").unwrap_or_else(|| "unknown".to_string()),
        created_by: meta_get(&meta, "created_by").unwrap_or_default(),
        notes,
        notes_format,
        artifacts: artifacts(&release_dir)?,
        thanks: thanks_count(&release_dir)?,
    }))
}

pub fn latest_published_tag(releases_path: &Path) -> Result<Option<String>> {
    if let Some(tag) = configured_latest_tag(releases_path)? {
        return Ok(Some(tag));
    }
    Ok(list_releases(releases_path)?
        .into_iter()
        .filter(|release| release.status == "published")
        .next()
        .map(|release| release.tag))
}

pub fn configured_latest_tag(releases_path: &Path) -> Result<Option<String>> {
    let latest_path = releases_path.join("latest");
    if !latest_path.is_file() {
        return Ok(None);
    }
    let tag = fs::read_to_string(latest_path)?.trim().to_string();
    if tag.is_empty() {
        return Ok(None);
    }
    let Some(tag) = clean_tag(&tag) else {
        return Ok(None);
    };
    let Some(release) = release_data(releases_path, &tag)? else {
        return Ok(None);
    };
    Ok((release.status == "published").then_some(release.tag))
}

pub fn create_init(
    releases_path: &Path,
    repo_path: &Path,
    request: &ReleaseRequest,
    remote: &[u8; 16],
) -> Result<Vec<u8>> {
    let Some(tag) = request.tag.as_deref().and_then(clean_tag) else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid tag name",
        ));
    };
    if let Err(err) = verify_tag(repo_path, &tag) {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            err.to_string(),
        ));
    }
    fs::create_dir_all(releases_path)?;
    let release_dir = releases_path.join(&tag);
    if release_dir.exists() {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"release already exists",
        ));
    }
    fs::create_dir_all(release_dir.join("artifacts"))?;
    let created = unix_time();
    let mut meta = vec![
        ("tag".to_string(), tag.clone()),
        ("created".to_string(), created.to_string()),
        ("status".to_string(), "draft".to_string()),
        ("created_by".to_string(), hex(remote)),
    ];
    if let Some(hash) = request.hash.as_deref().filter(|v| !v.is_empty()) {
        meta.push(("hash".to_string(), hash.to_string()));
    }
    write_meta(&release_dir.join("META"), &meta)?;
    if let Some(notes) = request.notes.as_deref().filter(|v| !v.is_empty()) {
        let notes_file = match request.notes_format.as_deref() {
            Some("micron") => "RELEASE.mu",
            Some("text") => "RELEASE.txt",
            _ => "RELEASE.md",
        };
        fs::write(release_dir.join(notes_file), notes)?;
    }
    write_thanks(&release_dir, 0)?;
    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn create_artifact(releases_path: &Path, request: &ReleaseRequest) -> Result<Vec<u8>> {
    let Some(tag) = request.tag.as_deref().and_then(clean_tag) else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid tag name",
        ));
    };
    let artifact_name = request
        .artifact_name
        .as_deref()
        .and_then(clean_component)
        .ok_or_else(|| Error::msg("invalid artifact name"))?;
    let data = request
        .artifact_data
        .as_deref()
        .ok_or_else(|| Error::msg("missing artifact data"))?;
    let release_dir = releases_path.join(&tag);
    if !release_dir.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"release not found",
        ));
    }
    let meta_path = release_dir.join("META");
    let meta = read_meta(&meta_path)?;
    if meta_get(&meta, "status").as_deref() != Some("draft") {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"release was finalized and is not writable",
        ));
    }
    let artifacts_dir = release_dir.join("artifacts");
    fs::create_dir_all(&artifacts_dir)?;
    fs::write(artifacts_dir.join(artifact_name), data)?;
    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn create_finalize(releases_path: &Path, request: &ReleaseRequest) -> Result<Vec<u8>> {
    let Some(tag) = request.tag.as_deref().and_then(clean_tag) else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid tag name",
        ));
    };
    let release_dir = releases_path.join(&tag);
    if !release_dir.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"release not found",
        ));
    }
    let meta_path = release_dir.join("META");
    let mut meta = read_meta(&meta_path)?;
    if meta_get(&meta, "status").as_deref() != Some("draft") {
        return Ok(protocol::status_bytes(
            protocol::RES_DISALLOWED,
            b"release was finalized and is not writable",
        ));
    }
    set_meta(&mut meta, "status", "published");
    set_meta(&mut meta, "published_at", &unix_time().to_string());
    write_meta(&meta_path, &meta)?;
    if let Err(err) = write_latest_marker(releases_path, &tag) {
        log::error!(
            "error setting latest release for {:?}: {}",
            releases_path,
            err
        );
    }
    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn delete_release(releases_path: &Path, request: &ReleaseRequest) -> Result<Vec<u8>> {
    let Some(tag) = request.tag.as_deref().and_then(clean_tag) else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid tag name",
        ));
    };
    let release_dir = releases_path.join(tag);
    if !release_dir.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"release not found",
        ));
    }
    fs::remove_dir_all(release_dir)?;
    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn set_latest_release(releases_path: &Path, request: &ReleaseRequest) -> Result<Vec<u8>> {
    let Some(tag) = request.tag.as_deref().and_then(clean_tag) else {
        return Ok(protocol::status_bytes(
            protocol::RES_INVALID_REQ,
            b"invalid tag name",
        ));
    };
    let release_dir = releases_path.join(&tag);
    if !release_dir.is_dir() {
        return Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"release not found",
        ));
    }
    fs::create_dir_all(releases_path)?;
    write_latest_marker(releases_path, &tag)?;
    Ok(protocol::status_bytes(protocol::RES_OK, b"ok"))
}

pub fn list_response(releases_path: &Path) -> Result<Vec<u8>> {
    let releases = Value::Array(
        list_releases(releases_path)?
            .into_iter()
            .map(summary_value)
            .collect(),
    );
    let latest = configured_latest_tag(releases_path)?
        .map(Value::Str)
        .unwrap_or(Value::Nil);
    Ok(protocol::status_bytes(
        protocol::RES_OK,
        msgpack::pack(&Value::Map(vec![
            (Value::Str("releases".into()), releases),
            (Value::Str("latest".into()), latest),
        ])),
    ))
}

pub fn view_response(releases_path: &Path, tag: &str) -> Result<Vec<u8>> {
    let resolved_tag;
    let tag = if tag == "latest" {
        let Some(tag) = latest_published_tag(releases_path)? else {
            return Ok(protocol::status_bytes(
                protocol::RES_NOT_FOUND,
                b"no latest release found",
            ));
        };
        resolved_tag = tag;
        resolved_tag.as_str()
    } else {
        tag
    };
    let release = match release_data(releases_path, tag) {
        Ok(release) => release,
        Err(err) if err.to_string() == "invalid tag name" => {
            return Ok(protocol::status_bytes(
                protocol::RES_INVALID_REQ,
                b"invalid tag name",
            ));
        }
        Err(err) => return Err(err),
    };
    match release {
        Some(release) => Ok(protocol::status_bytes(
            protocol::RES_OK,
            msgpack::pack(&data_value(release)),
        )),
        None => Ok(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"release not found",
        )),
    }
}

pub fn release_thanks(release_dir: &Path, add: bool) -> Result<u64> {
    let mut count = thanks_count(release_dir)?;
    if add {
        count = count.saturating_add(1);
        write_thanks(release_dir, count)?;
    }
    Ok(count)
}

pub fn artifact_path(releases_path: &Path, tag: &str, artifact: &str) -> Result<Option<PathBuf>> {
    let tag = if tag == "latest" {
        let Some(tag) = latest_published_tag(releases_path)? else {
            return Ok(None);
        };
        tag
    } else {
        clean_tag(tag).ok_or_else(|| Error::msg("invalid tag name"))?
    };
    let artifact = clean_component(artifact).ok_or_else(|| Error::msg("invalid artifact name"))?;
    let Some(release) = release_data(releases_path, &tag)? else {
        return Ok(None);
    };
    if release.status != "published" {
        return Ok(None);
    }
    let path = releases_path.join(tag).join("artifacts").join(artifact);
    Ok(path.is_file().then_some(path))
}

fn summary_value(release: ReleaseSummary) -> Value {
    Value::Map(vec![
        (Value::Str("tag".into()), Value::Str(release.tag)),
        (Value::Str("hash".into()), Value::Str(release.hash)),
        (Value::Str("created".into()), Value::UInt(release.created)),
        (Value::Str("status".into()), Value::Str(release.status)),
        (
            Value::Str("created_by".into()),
            Value::Str(release.created_by),
        ),
        (Value::Str("preview".into()), Value::Str(release.preview)),
        (
            Value::Str("preview_format".into()),
            Value::Str(release.preview_format),
        ),
        (
            Value::Str("artifacts".into()),
            Value::UInt(release.artifacts),
        ),
    ])
}

fn data_value(release: ReleaseData) -> Value {
    Value::Map(vec![
        (Value::Str("tag".into()), Value::Str(release.tag)),
        (Value::Str("hash".into()), Value::Str(release.hash)),
        (Value::Str("created".into()), Value::UInt(release.created)),
        (Value::Str("status".into()), Value::Str(release.status)),
        (
            Value::Str("created_by".into()),
            Value::Str(release.created_by),
        ),
        (Value::Str("notes".into()), Value::Str(release.notes)),
        (
            Value::Str("notes_format".into()),
            Value::Str(release.notes_format),
        ),
        (
            Value::Str("artifacts".into()),
            Value::Array(release.artifacts.into_iter().map(artifact_value).collect()),
        ),
        (Value::Str("thanks".into()), Value::UInt(release.thanks)),
    ])
}

fn write_latest_marker(releases_path: &Path, tag: &str) -> Result<()> {
    let latest_path = releases_path.join("latest");
    let tmp_path = releases_path.join("latest.tmp");
    fs::write(&tmp_path, tag)?;
    fs::rename(tmp_path, latest_path)?;
    Ok(())
}

fn artifact_value(artifact: Artifact) -> Value {
    Value::Map(vec![
        (Value::Str("name".into()), Value::Str(artifact.name)),
        (Value::Str("size".into()), Value::UInt(artifact.size)),
    ])
}

fn sidecar_path(repo: &Path, extension: &str) -> PathBuf {
    let mut name = repo.as_os_str().to_os_string();
    name.push(format!(".{extension}"));
    PathBuf::from(name)
}

fn read_meta(path: &Path) -> Result<Vec<(String, String)>> {
    let input = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok(out)
}

fn write_meta(path: &Path, values: &[(String, String)]) -> Result<()> {
    let mut out = String::new();
    for (key, value) in values {
        out.push_str(key);
        out.push_str(" = ");
        out.push_str(value);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

fn meta_get(values: &[(String, String)], key: &str) -> Option<String> {
    values
        .iter()
        .find_map(|(k, v)| (k == key).then(|| v.clone()))
}

fn set_meta(values: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, existing)) = values.iter_mut().find(|(k, _)| k == key) {
        *existing = value.to_string();
    } else {
        values.push((key.to_string(), value.to_string()));
    }
}

fn read_notes(release_dir: &Path) -> Result<(String, String)> {
    for (file, format) in [
        ("RELEASE.md", "markdown"),
        ("RELEASE.mu", "micron"),
        ("RELEASE.txt", "text"),
    ] {
        let path = release_dir.join(file);
        if path.is_file() {
            return Ok((fs::read_to_string(path)?, format.to_string()));
        }
    }
    Ok((String::new(), "text".to_string()))
}

fn notes_preview(release_dir: &Path) -> Result<(String, String)> {
    let (notes, format) = read_notes(release_dir)?;
    let first = notes
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('>'))
        .unwrap_or("");
    Ok((first.chars().take(256).collect(), format))
}

fn artifacts(release_dir: &Path) -> Result<Vec<Artifact>> {
    let artifacts_dir = release_dir.join("artifacts");
    let mut out = Vec::new();
    if !artifacts_dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(artifacts_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        out.push(Artifact {
            name: entry.file_name().to_string_lossy().into_owned(),
            size: entry.metadata()?.len(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn artifact_count(release_dir: &Path) -> Result<u64> {
    Ok(artifacts(release_dir)?.len() as u64)
}

fn thanks_count(release_dir: &Path) -> Result<u64> {
    let path = release_dir.join("THANKS");
    if !path.is_file() {
        return Ok(0);
    }
    let bytes = fs::read(path)?;
    if let Ok(value) = msgpack::unpack_exact(&bytes) {
        return Ok(value
            .map_get("count")
            .and_then(Value::as_integer)
            .unwrap_or(0)
            .max(0) as u64);
    }
    Ok(String::from_utf8_lossy(&bytes).trim().parse().unwrap_or(0))
}

fn write_thanks(release_dir: &Path, count: u64) -> Result<()> {
    fs::write(
        release_dir.join("THANKS"),
        msgpack::pack(&Value::Map(vec![(
            Value::Str("count".into()),
            Value::UInt(count),
        )])),
    )?;
    Ok(())
}

fn verify_tag(repo_path: &Path, tag: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo_path)
        .arg("rev-parse")
        .arg("--verify")
        .arg(format!("refs/tags/{tag}"))
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "tag '{tag}' does not exist in repository"
        )))
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn clean_component(value: &str) -> Option<String> {
    let name = Path::new(value).file_name()?.to_str()?.trim();
    (!name.is_empty() && name != "." && name != "..").then(|| name.to_string())
}

fn clean_tag(value: &str) -> Option<String> {
    if value.contains('/') || value.contains('\\') {
        return None;
    }
    clean_component(value)
}

fn map_get_repository<'a>(map: &'a [(Value, Value)]) -> Option<&'a str> {
    map.iter().find_map(|(key, value)| match key {
        Value::UInt(v) if *v == protocol::IDX_REPOSITORY => value.as_str(),
        Value::Str(v) if v == "repository" => value.as_str(),
        _ => None,
    })
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Str(s) if s == key => Some(v),
        _ => None,
    })
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map_get(map, key).and_then(Value::as_str)
}

fn value_to_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Bin(bytes) => Some(bytes.clone()),
        Value::Str(text) => Some(text.as_bytes().to_vec()),
        _ => None,
    }
}
