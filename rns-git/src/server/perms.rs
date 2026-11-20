//! Group and repository permission management requests.

use rns_core::msgpack::{self, Value};

use crate::acl::{Access, Operation};
use crate::config::ServerConfig;
use crate::protocol;
use crate::{git, Error, Result};

pub(crate) fn handle_perms(
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

pub(super) fn handle_permissions_step(
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
            if allowed_path.exists() && crate::acl::is_executable_file(allowed_path)? {
                return Ok(protocol::status_bytes(
                    protocol::RES_DISALLOWED,
                    b"Executable permission resolvers can only be modified node-side",
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

fn map_get_index_str(map: &[(Value, Value)], key: u64) -> Option<&str> {
    map.iter().find_map(|(candidate, value)| match candidate {
        Value::UInt(candidate) if *candidate == key => value.as_str(),
        _ => None,
    })
}
