//! Serving media and file downloads.

use super::*;

pub(super) fn is_image_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "webp" | "png" | "jpg" | "jpeg" | "gif" | "tiff" | "tif" | "bmp"
            )
        })
}

pub(super) fn quote_media_path(path: &str) -> String {
    let mut out = String::new();
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Nomad Network media requests carry a presence-only key and an encoded blob
/// path. The repository ACL is the authority, just as for ordinary downloads.
pub fn serve_media(
    config: &ServerConfig,
    access: &Access,
    data: &[u8],
    remote: Option<&[u8; 16]>,
) -> Result<RequestResponse> {
    let rejected = || RequestResponse::Bytes(msgpack::pack(&Value::Bool(false)));
    let Ok(Value::Map(fields)) = msgpack::unpack_exact(data) else {
        return Ok(rejected());
    };
    if !fields.iter().any(|(key, _)| key.as_str() == Some("key")) {
        return Ok(rejected());
    }
    let Some(path) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("path"))
        .and_then(|(_, value)| value.as_str())
    else {
        return Ok(rejected());
    };
    let components: Vec<_> = path
        .strip_prefix("/media")
        .unwrap_or(path)
        .trim_start_matches('/')
        .splitn(4, '/')
        .collect();
    if components.len() != 4 {
        return Ok(rejected());
    }
    let vars = BTreeMap::from([
        ("g".into(), components[0].into()),
        ("r".into(), components[1].into()),
    ]);
    let Ok((_, _, repository)) = accessible_repository(config, access, remote, &vars) else {
        return Ok(rejected());
    };
    let path = decode_url_component(components[3]);
    if path.is_empty() || validate_git_path(&path).is_err() {
        return Ok(rejected());
    }
    let Ok(resolved) = resolve_ref(&repository, components[2]) else {
        return Ok(rejected());
    };
    if !matches!(
        git_object_kind(&repository, &resolved, &path).as_deref(),
        Ok("blob")
    ) {
        return Ok(rejected());
    }
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repository)
            .arg("show")
            .arg(format!("{resolved}:{path}")),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Ok(rejected());
    }
    let name = path.rsplit('/').next().unwrap_or(&path);
    let (data, name) = media_response_data(config.media_conversion, &path, name, output.stdout);
    Ok(RequestResponse::File {
        data,
        metadata: msgpack::pack(&Value::Map(vec![(
            Value::Str("name".into()),
            Value::Bin(name.as_bytes().to_vec()),
        )])),
        auto_compress: false,
    })
}

pub(super) fn media_response_data(
    enabled: bool,
    path: &str,
    name: &str,
    original: Vec<u8>,
) -> (Vec<u8>, String) {
    if enabled && is_image_path(path) && !path.to_ascii_lowercase().ends_with(".webp") {
        if let Some(converted) = crate::media::convert_to_webp(&original) {
            let stem = name.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(name);
            return (converted, format!("{stem}.webp"));
        }
    }
    (original, name.to_string())
}

pub fn download_file(
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
    if let Some(artifact) = var(&vars, "artifact") {
        let artifact = decode_url_component(artifact);
        let tag = var(&vars, "tag").unwrap_or("latest");
        let releases_path = crate::release::release_sidecar_path(&repository);
        let Some(path) = crate::release::artifact_path(&releases_path, tag, &artifact)? else {
            return Ok(RequestResponse::Bytes(protocol::status_bytes(
                protocol::RES_NOT_FOUND,
                b"file not found",
            )));
        };
        let data = fs::read(path)?;
        crate::stats::record_release_download(config, &format!("{group}/{repo}"), remote);
        return Ok(RequestResponse::Resource {
            data,
            metadata: Some(protocol::metadata_status(protocol::RES_OK)),
            auto_compress: true,
        });
    }

    let reference = var(&vars, "ref").unwrap_or("HEAD");
    let path = required_var(&vars, "path")?;
    let format = var(&vars, "fmt");
    if format.is_some() && (format != Some("mu") || !path.to_ascii_lowercase().ends_with(".md")) {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"unsupported conversion",
        )));
    }
    validate_git_path(path)?;
    let resolved = resolve_ref(&repository, reference)?;
    let spec = format!("{resolved}:{path}");
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(&repository)
            .arg("show")
            .arg(spec),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Ok(RequestResponse::Bytes(protocol::status_bytes(
            protocol::RES_NOT_FOUND,
            b"file not found",
        )));
    }
    let (data, metadata) = if format == Some("mu") {
        let markdown = String::from_utf8(output.stdout)
            .map_err(|_| Error::msg("markdown download is not UTF-8"))?;
        let converted = markdown_to_micron_scoped(
            &markdown,
            Some(&markdown_blob_url_scope(&group, &repo, reference, path)),
        );
        let filename = path.rsplit('/').next().unwrap_or(path);
        let stem = filename
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(filename);
        (
            converted.trim_end().as_bytes().to_vec(),
            msgpack::pack(&Value::Map(vec![
                (
                    Value::UInt(protocol::IDX_RESULT_CODE),
                    Value::UInt(protocol::RES_OK as u64),
                ),
                (
                    Value::Str("name".into()),
                    Value::Bin(format!("{stem}.mu").into_bytes()),
                ),
            ])),
        )
    } else {
        (output.stdout, protocol::metadata_status(protocol::RES_OK))
    };
    crate::stats::record_download(config, &format!("{group}/{repo}"), remote);
    Ok(RequestResponse::Resource {
        data,
        metadata: Some(metadata),
        auto_compress: true,
    })
}
