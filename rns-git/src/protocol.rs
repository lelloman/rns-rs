use rns_core::msgpack::{self, Value};

use crate::{Error, Result};

pub const APP_NAME: &str = "git";
pub const ASPECT_REPOSITORIES: &str = "repositories";

pub const PATH_LIST: &str = "/git/list";
pub const PATH_FETCH: &str = "/git/fetch";
pub const PATH_PUSH: &str = "/git/push";
pub const PATH_CREATE: &str = "/git/create";
pub const PATH_FORK: &str = "/git/fork";
pub const PATH_SYNC: &str = "/git/sync";
pub const PATH_MIRROR: &str = "/git/mirror";
pub const PATH_DELETE: &str = "/git/delete";
pub const PATH_RELEASE: &str = "/mgmt/release";
pub const PATH_WORK: &str = "/mgmt/work";
pub const PATH_PERMS: &str = "/mgmt/perms";

pub const RES_OK: u8 = 0x00;
pub const RES_DISALLOWED: u8 = 0x01;
pub const RES_INVALID_REQ: u8 = 0x02;
pub const RES_NOT_FOUND: u8 = 0x03;
pub const RES_REMOTE_FAIL: u8 = 0xff;

pub const IDX_REPOSITORY: u64 = 0x00;
pub const IDX_RESULT_CODE: u64 = 0x01;
pub const IDX_GROUP: u64 = 0x02;

const ACTION_UPDATE_REF: &str = "update_ref";
const ACTION_DELETE_REF: &str = "delete_ref";

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

pub fn remote_clone_request(repository: &str, source: &str) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![
        (
            Value::UInt(IDX_REPOSITORY),
            Value::Str(repository.to_string()),
        ),
        (
            Value::Str("source".to_string()),
            Value::Str(source.to_string()),
        ),
    ]))
}

pub fn parse_remote_clone_request(data: &[u8]) -> Result<(String, String)> {
    let value =
        msgpack::unpack_exact(data).map_err(|e| Error::msg(format!("invalid msgpack: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("request must be a msgpack map"))?;
    let repo = map_get(map, IDX_REPOSITORY)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("request missing repository"))?;
    let source = map_get_str(map, "source")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("request missing source"))?;
    Ok((repo, source))
}

pub fn fetch_request(repository: &str, have: &[String]) -> Vec<u8> {
    fetch_request_for_refs(repository, have, &[])
}

pub fn fetch_request_for_refs(
    repository: &str,
    have: &[String],
    refs: &[(String, String)],
) -> Vec<u8> {
    msgpack::pack(&Value::Map(vec![
        (
            Value::UInt(IDX_REPOSITORY),
            Value::Str(repository.to_string()),
        ),
        (
            Value::Str("have".to_string()),
            Value::Array(have.iter().map(|v| Value::Str(v.clone())).collect()),
        ),
        (
            Value::Str("refs".to_string()),
            Value::Array(
                refs.iter()
                    .map(|(sha, refname)| {
                        Value::Map(vec![
                            (Value::Str("sha".to_string()), Value::Str(sha.clone())),
                            (Value::Str("ref".to_string()), Value::Str(refname.clone())),
                        ])
                    })
                    .collect(),
            ),
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
            Value::Str("operations".to_string()),
            Value::Array(updates.into_iter().map(update_to_operation_value).collect()),
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
    let updates = if let Some(arr) = map_get_str(map, "operations").and_then(Value::as_array) {
        arr.iter()
            .map(operation_value_to_update)
            .collect::<Result<Vec<_>>>()?
    } else {
        map_get_str(map, "updates")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().map(value_to_update).collect::<Result<Vec<_>>>())
            .transpose()?
            .unwrap_or_default()
    };
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

#[allow(dead_code)]
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

fn update_to_operation_value(update: RefUpdate) -> Value {
    let action = if update.new.is_some() {
        ACTION_UPDATE_REF
    } else {
        ACTION_DELETE_REF
    };
    let mut items = vec![
        (
            Value::Str("action".to_string()),
            Value::Str(action.to_string()),
        ),
        (Value::Str("ref".to_string()), Value::Str(update.refname)),
        (Value::Str("force".to_string()), Value::Bool(update.force)),
    ];
    if let Some(old) = update.old {
        items.push((Value::Str("old".to_string()), Value::Str(old)));
    }
    if let Some(new) = update.new {
        items.push((Value::Str("sha".to_string()), Value::Str(new)));
    }
    Value::Map(items)
}

fn operation_value_to_update(value: &Value) -> Result<RefUpdate> {
    let map = value
        .as_map()
        .ok_or_else(|| Error::msg("operation must be a map"))?;
    let action = map_get_str(map, "action")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::msg("operation missing action"))?;
    let refname = map_get_str(map, "ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::msg("operation missing ref"))?;
    let old = map_get_str(map, "old")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let force = map_get_str(map, "force")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match action {
        ACTION_UPDATE_REF => {
            let new = map_get_str(map, "sha")
                .or_else(|| map_get_str(map, "new"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::msg("update_ref operation missing sha"))?;
            Ok(RefUpdate {
                refname,
                old,
                new: Some(new),
                force,
            })
        }
        ACTION_DELETE_REF => Ok(RefUpdate {
            refname,
            old,
            new: None,
            force,
        }),
        other => Err(Error::msg(format!("unknown push operation {other}"))),
    }
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
    fn remote_clone_request_roundtrip_includes_source() {
        let req = remote_clone_request("group/repo", "https://example.invalid/repo.git");
        assert_eq!(
            parse_remote_clone_request(&req).unwrap(),
            (
                "group/repo".into(),
                "https://example.invalid/repo.git".into()
            )
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
    fn push_request_uses_operations_field() {
        let update = RefUpdate {
            refname: "refs/heads/main".to_string(),
            old: Some("old".to_string()),
            new: Some("new".to_string()),
            force: true,
        };
        let packed = push_request("repo", Vec::new(), vec![update]);
        let value = msgpack::unpack_exact(&packed).unwrap();
        let map = value.as_map().unwrap();

        assert!(map_get_str(map, "operations").is_some());
        assert!(map_get_str(map, "updates").is_none());
    }

    #[test]
    fn parse_push_request_accepts_update_and_delete_operations() {
        let request = msgpack::pack(&Value::Map(vec![
            (Value::UInt(IDX_REPOSITORY), Value::Str("repo".into())),
            (Value::Str("bundle".into()), Value::Bin(Vec::new())),
            (
                Value::Str("operations".into()),
                Value::Array(vec![
                    Value::Map(vec![
                        (
                            Value::Str("action".into()),
                            Value::Str(ACTION_UPDATE_REF.into()),
                        ),
                        (
                            Value::Str("ref".into()),
                            Value::Str("refs/heads/main".into()),
                        ),
                        (Value::Str("sha".into()), Value::Str("new".into())),
                        (Value::Str("force".into()), Value::Bool(true)),
                    ]),
                    Value::Map(vec![
                        (
                            Value::Str("action".into()),
                            Value::Str(ACTION_DELETE_REF.into()),
                        ),
                        (
                            Value::Str("ref".into()),
                            Value::Str("refs/heads/old".into()),
                        ),
                    ]),
                ]),
            ),
        ]));

        let (_, _, updates) = parse_push_request(&request).unwrap();

        assert_eq!(
            updates,
            vec![
                RefUpdate {
                    refname: "refs/heads/main".into(),
                    old: None,
                    new: Some("new".into()),
                    force: true
                },
                RefUpdate {
                    refname: "refs/heads/old".into(),
                    old: None,
                    new: None,
                    force: false
                }
            ]
        );
    }

    #[test]
    fn parse_push_request_keeps_legacy_updates_compatibility() {
        let update = RefUpdate {
            refname: "refs/heads/main".into(),
            old: Some("old".into()),
            new: Some("new".into()),
            force: false,
        };
        let request = msgpack::pack(&Value::Map(vec![
            (Value::UInt(IDX_REPOSITORY), Value::Str("repo".into())),
            (Value::Str("bundle".into()), Value::Bin(Vec::new())),
            (
                Value::Str("updates".into()),
                Value::Array(vec![update_to_value(update.clone())]),
            ),
        ]));

        let (_, _, updates) = parse_push_request(&request).unwrap();

        assert_eq!(updates, vec![update]);
    }

    #[test]
    fn status_response_is_status_byte_plus_payload() {
        assert_eq!(status_bytes(RES_OK, b"ok"), b"\0ok");
    }
}
