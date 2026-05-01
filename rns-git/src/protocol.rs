use rns_core::msgpack::{self, Value};

use crate::{Error, Result};

pub const APP_NAME: &str = "git";
pub const ASPECT_REPOSITORIES: &str = "repositories";

pub const PATH_LIST: &str = "/git/list";
pub const PATH_FETCH: &str = "/git/fetch";
pub const PATH_PUSH: &str = "/git/push";
pub const PATH_DELETE: &str = "/git/delete";

pub const RES_OK: u8 = 0x00;
pub const RES_DISALLOWED: u8 = 0x01;
pub const RES_INVALID_REQ: u8 = 0x02;
pub const RES_NOT_FOUND: u8 = 0x03;
pub const RES_REMOTE_FAIL: u8 = 0xff;

pub const IDX_REPOSITORY: u64 = 0x00;
pub const IDX_RESULT_CODE: u64 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub refname: String,
    pub old: Option<String>,
    pub new: Option<String>,
    pub force: bool,
}

pub fn status_bytes(code: u8, body: impl AsRef<[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + body.as_ref().len());
    out.push(code);
    out.extend_from_slice(body.as_ref());
    out
}

pub fn metadata_status(code: u8) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![(
        Value::UInt(IDX_RESULT_CODE),
        Value::UInt(code as u64),
    )]))
}

pub fn repository_request(repository: &str) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![(
        Value::UInt(IDX_REPOSITORY),
        Value::Str(repository.to_string()),
    )]))
}

pub fn repository_from_request(data: &[u8]) -> Result<String> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    map_get(map, IDX_REPOSITORY)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("request missing repository"))
}

pub fn fetch_request(repository: &str, have: &[String]) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![
        (
            Value::UInt(IDX_REPOSITORY),
            Value::Str(repository.to_string()),
        ),
        (
            Value::Str("have".to_string()),
            Value::Array(have.iter().map(|v| Value::Str(v.clone())).collect()),
        ),
    ]))
}

pub fn parse_fetch_request(data: &[u8]) -> Result<(String, Vec<String>)> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let repo = map_get(map, IDX_REPOSITORY)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("request missing repository"))?;
    let have = map_get_str(map, "have")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok((repo, have))
}

pub fn push_request(repository: &str, bundle: Vec<u8>, updates: Vec<RefUpdate>) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![
        (
            Value::UInt(IDX_REPOSITORY),
            Value::Str(repository.to_string()),
        ),
        (Value::Str("bundle".to_string()), Value::Bin(bundle)),
        (
            Value::Str("updates".to_string()),
            Value::Array(updates.into_iter().map(update_to_value).collect()),
        ),
    ]))
}

pub fn parse_push_request(data: &[u8]) -> Result<(String, Vec<u8>, Vec<RefUpdate>)> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let repo = map_get(map, IDX_REPOSITORY)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("request missing repository"))?;
    let bundle = map_get_str(map, "bundle")
        .and_then(Value::as_bin)
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let updates = map_get_str(map, "updates")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(value_to_update).collect::<Result<Vec<_>>>())
        .transpose()?
        .unwrap_or_default();
    Ok((repo, bundle, updates))
}

pub fn response_bin(data: &[u8]) -> Result<Vec<u8>> {
    match msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid response: {e}")))? {
        Value::Bin(bytes) => Ok(bytes),
        other => Err(Error::msg(format!(
            "expected binary response, got {other:?}"
        ))),
    }
}

fn update_to_value(update: RefUpdate) -> Value {
    let mut items = vec![
        (Value::Str("ref".to_string()), Value::Str(update.refname)),
        (Value::Str("force".to_string()), Value::Bool(update.force)),
    ];
    items.push((
        Value::Str("old".to_string()),
        update.old.map(Value::Str).unwrap_or(Value::Nil),
    ));
    items.push((
        Value::Str("new".to_string()),
        update.new.map(Value::Str).unwrap_or(Value::Nil),
    ));
    Value::Map(items)
}

fn value_to_update(value: &Value) -> Result<RefUpdate> {
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("update must be a map"))?;
    let refname = map_get_str(map, "ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("update missing ref"))?;
    let old = map_get_str(map, "old")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let new = map_get_str(map, "new")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let force = map_get_str(map, "force")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(RefUpdate {
        refname,
        old,
        new,
        force,
    })
}

fn map_get<'a>(map: &'a [(Value, Value)], key: u64) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if matches!(k, Value::UInt(v) if *v == key) {
            Some(v)
        } else {
            None
        }
    })
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Str(s) if s == key => Some(v),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_roundtrip_uses_upstream_index() {
        assert_eq!(
            repository_from_request(&repository_request("group/repo")).unwrap(),
            "group/repo"
        );
    }

    #[test]
    fn push_roundtrip_preserves_updates() {
        let update = RefUpdate {
            refname: "refs/heads/main".to_string(),
            old: None,
            new: Some("abc".to_string()),
            force: true,
        };
        let (repo, bundle, updates) = parse_push_request(&push_request(
            "repo",
            b"bundle".to_vec(),
            vec![update.clone()],
        ))
        .unwrap();
        assert_eq!(repo, "repo");
        assert_eq!(bundle, b"bundle");
        assert_eq!(updates, vec![update]);
    }

    #[test]
    fn status_response_is_status_byte_plus_payload() {
        assert_eq!(status_bytes(RES_OK, b"ok"), b"\0ok");
    }
}
