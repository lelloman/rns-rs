//! Request variables, path validation and what a requester may see.

use super::*;
use rns_core::encoding::hex_digit;

pub(super) fn accessible_groups(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut groups = BTreeMap::new();
    if !config.repositories_dir.exists() {
        return Ok(groups);
    }
    for group_entry in fs::read_dir(&config.repositories_dir)? {
        let group_entry = group_entry?;
        if !group_entry.file_type()?.is_dir() {
            continue;
        }
        let group = group_entry.file_name().to_string_lossy().to_string();
        if validate_group_name(&group).is_err() {
            continue;
        }
        let repos = accessible_repositories(config, access, remote, &group)?;
        if !repos.is_empty() {
            groups.insert(group, repos);
        }
    }
    Ok(groups)
}

pub(super) fn accessible_repositories(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    group: &str,
) -> Result<Vec<String>> {
    validate_group_name(group)?;
    let group_dir = config.repositories_dir.join(group);
    let mut repos = Vec::new();
    if !group_dir.exists() {
        return Ok(repos);
    }
    for repo_entry in fs::read_dir(group_dir)? {
        let repo_entry = repo_entry?;
        if !repo_entry.file_type()?.is_dir() {
            continue;
        }
        let repo = repo_entry.file_name().to_string_lossy().to_string();
        let Ok(name) = repository_name(group, &repo) else {
            continue;
        };
        if crate::git::is_bare_repository(&config.repositories_dir.join(&name))
            && access.allows(Operation::Read, &name, remote)?
        {
            repos.push(repo);
        }
    }
    repos.sort();
    Ok(repos)
}

pub(super) fn accessible_repository(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<(String, String, PathBuf)> {
    let group = required_var(vars, "g")?;
    let repo = required_var(vars, "r")?;
    let name = repository_name(group, repo)?;
    let path = config.repositories_dir.join(&name);
    if !crate::git::is_bare_repository(&path) || !access.allows(Operation::Read, &name, remote)? {
        return Err(Error::msg("repository not found"));
    }
    Ok((group.to_string(), repo.to_string(), path))
}

pub(super) fn required_var<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    var(vars, key).ok_or_else(|| Error::msg(format!("missing page variable {key}")))
}

pub(super) fn decode_url_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
                {
                    out.push((high << 4) | low);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn var<'a>(vars: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    vars.get(&format!("var_{key}"))
        .or_else(|| vars.get(key))
        .map(String::as_str)
}

pub(super) fn repository_name(group: &str, repo: &str) -> Result<String> {
    validate_group_name(group)?;
    validate_repo_component(repo)?;
    let name = format!("{group}/{repo}");
    validate_repo_name(&name)?;
    Ok(name)
}

pub(super) fn validate_group_name(group: &str) -> Result<()> {
    validate_repo_component(group)
}

pub(super) fn validate_repo_component(component: &str) -> Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.len() > 256
    {
        Err(Error::msg("invalid repository name"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_git_path(path: &str) -> Result<()> {
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::msg("invalid repository path"));
    }
    for component in path.split('/') {
        if component == "." || component == ".." {
            return Err(Error::msg("invalid repository path"));
        }
    }
    Ok(())
}

pub(super) fn normalize_blob_path(path: &str) -> String {
    path.strip_prefix("./").unwrap_or(path).replace("/./", "/")
}

pub(super) fn validate_refish(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains("..")
        || value.contains('\\')
        || value.contains(' ')
        || value.contains('~')
        || value.contains('^')
        || value.contains(':')
    {
        Err(Error::msg("invalid git ref"))
    } else {
        Ok(())
    }
}
