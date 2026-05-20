use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{parse_hex_16, validate_repo_name};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Create,
    Stats,
    Release,
    Interact,
    Propose,
    Admin,
}

#[derive(Debug, Clone)]
pub struct Access {
    read: Rule,
    write: Rule,
    create: Rule,
    stats: Rule,
    release: Rule,
    interact: Rule,
    propose: Rule,
    admin: Rule,
    aliases: BTreeMap<String, [u8; 16]>,
    repositories_dir: PathBuf,
}

#[derive(Debug, Clone)]
enum Rule {
    None,
    All,
    Identities(Vec<[u8; 16]>),
}

impl Access {
    pub fn new(
        read: &[String],
        write: &[String],
        create: &[String],
        stats: &[String],
        release: &[String],
        interact: &[String],
        admin: &[String],
        repositories_dir: PathBuf,
    ) -> Result<Self> {
        Self::new_with_aliases(
            read,
            write,
            create,
            stats,
            release,
            interact,
            admin,
            repositories_dir,
            BTreeMap::new(),
        )
    }

    pub fn new_with_aliases(
        read: &[String],
        write: &[String],
        create: &[String],
        stats: &[String],
        release: &[String],
        interact: &[String],
        admin: &[String],
        repositories_dir: PathBuf,
        aliases: BTreeMap<String, [u8; 16]>,
    ) -> Result<Self> {
        Ok(Self {
            read: Rule::parse(read, &aliases)?,
            write: Rule::parse(write, &aliases)?,
            create: Rule::parse(create, &aliases)?,
            stats: Rule::parse(stats, &aliases)?,
            release: Rule::parse(release, &aliases)?,
            interact: Rule::parse(interact, &aliases)?,
            propose: Rule::None,
            admin: Rule::parse(admin, &aliases)?,
            aliases,
            repositories_dir,
        })
    }

    pub fn with_propose(mut self, propose: &[String]) -> Result<Self> {
        self.propose = Rule::parse(propose, &self.aliases)?;
        Ok(self)
    }

    pub fn allows(
        &self,
        op: Operation,
        repository: &str,
        identity: Option<&[u8; 16]>,
    ) -> Result<bool> {
        validate_repo_name(repository)?;
        if op != Operation::Admin
            && (self.repo_allowed(Operation::Admin, repository, identity)?
                || self.admin.allows(identity))
        {
            return Ok(true);
        }
        if self.repo_allowed(op, repository, identity)? {
            return Ok(true);
        }
        Ok(match op {
            Operation::Read => self.read.allows(identity),
            Operation::Write => self.write.allows(identity),
            Operation::Create => self.create.allows(identity),
            Operation::Stats => self.stats.allows(identity),
            Operation::Release => self.release.allows(identity),
            Operation::Interact => self.interact.allows(identity),
            Operation::Propose => self.propose.allows(identity),
            Operation::Admin => self.admin.allows(identity),
        })
    }

    fn repo_allowed(
        &self,
        op: Operation,
        repository: &str,
        identity: Option<&[u8; 16]>,
    ) -> Result<bool> {
        for path in self.allowed_files(repository) {
            if !path.exists() {
                continue;
            }
            let rules = parse_allowed_file_with_aliases(&allowed_input(&path)?, &self.aliases)?;
            let Some(rule) = rules.get(operation_key(op)) else {
                continue;
            };
            if rule.allows(identity) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn allowed_files(&self, repository: &str) -> Vec<PathBuf> {
        let repo = self.repositories_dir.join(repository);
        let mut out = vec![
            repo.join(".allowed"),
            self.repositories_dir.join(format!("{repository}.allowed")),
        ];
        if let Some(group) = repository.split('/').next() {
            out.push(self.repositories_dir.join(group).join("group.allowed"));
            out.push(self.repositories_dir.join(format!("{group}.allowed")));
        }
        out
    }
}

pub(crate) fn allowed_input_allows(
    input: &str,
    op: Operation,
    identity: Option<&[u8; 16]>,
) -> Result<bool> {
    Ok(parse_allowed_file(input)?
        .get(operation_key(op))
        .is_some_and(|rule| rule.allows(identity)))
}

pub(crate) fn validate_allowed_input(input: &str) -> Result<()> {
    parse_allowed_file(input).map(|_| ())
}

fn allowed_input(path: &Path) -> Result<String> {
    if is_executable_file(path)? {
        let output = Command::new(path).output()?;
        if !output.status.success() {
            return Err(Error::msg(format!(
                "allowed file {} exited with status {}",
                path.display(),
                output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Ok(fs::read_to_string(path)?)
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    Ok(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> Result<bool> {
    Ok(fs::metadata(path)?.is_file() && false)
}

fn operation_key(op: Operation) -> &'static str {
    match op {
        Operation::Read => "read",
        Operation::Write => "write",
        Operation::Create => "create",
        Operation::Stats => "stats",
        Operation::Release => "release",
        Operation::Interact => "interact",
        Operation::Propose => "propose",
        Operation::Admin => "admin",
    }
}

impl Rule {
    fn parse(values: &[String], aliases: &BTreeMap<String, [u8; 16]>) -> Result<Self> {
        if values.iter().any(|v| v.eq_ignore_ascii_case("all")) {
            return Ok(Rule::All);
        }
        let identities: Vec<[u8; 16]> = values
            .iter()
            .filter(|v| !v.eq_ignore_ascii_case("none"))
            .map(|v| parse_identity_ref(v, aliases))
            .collect::<Result<_>>()?;
        if identities.is_empty() {
            Ok(Rule::None)
        } else {
            Ok(Rule::Identities(identities))
        }
    }

    fn allows(&self, identity: Option<&[u8; 16]>) -> bool {
        match self {
            Rule::None => false,
            Rule::All => true,
            Rule::Identities(allowed) => identity.is_some_and(|id| allowed.iter().any(|v| v == id)),
        }
    }
}

fn parse_identity_ref(value: &str, aliases: &BTreeMap<String, [u8; 16]>) -> Result<[u8; 16]> {
    aliases
        .get(value.trim())
        .copied()
        .map(Ok)
        .unwrap_or_else(|| parse_hex_16(value))
}

fn parse_allowed_file(input: &str) -> Result<HashMap<String, Rule>> {
    parse_allowed_file_with_aliases(input, &BTreeMap::new())
}

fn parse_allowed_file_with_aliases(
    input: &str,
    aliases: &BTreeMap<String, [u8; 16]>,
) -> Result<HashMap<String, Rule>> {
    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    for raw in input.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .or_else(|| line.split_once(':'))
            .unwrap_or(("read", line));
        let raw_key = key.trim().to_ascii_lowercase();
        let key = match raw_key.as_str() {
            "r" | "read" => "read",
            "w" | "write" => "write",
            "rw" | "readwrite" => "readwrite",
            "c" | "create" => "create",
            "s" | "stats" => "stats",
            "rel" | "release" => "release",
            "i" | "interact" => "interact",
            "p" | "propose" => "propose",
            "adm" | "admin" => "admin",
            _ => return Err(Error::msg(format!("invalid permission \"{raw_key}\""))),
        };
        let targets = value.split(',').map(|v| v.trim().to_string());
        if key == "readwrite" {
            values
                .entry("read".into())
                .or_default()
                .extend(targets.clone());
            values.entry("write".into()).or_default().extend(targets);
        } else {
            values.entry(key.into()).or_default().extend(targets);
        }
    }
    values
        .into_iter()
        .map(|(key, values)| Ok((key, Rule::parse(&values, aliases)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_rules_allow_all_or_none() {
        let access = Access::new(
            &["all".into()],
            &["none".into()],
            &["none".into()],
            &["all".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            PathBuf::from("."),
        )
        .unwrap();
        assert!(access.allows(Operation::Read, "group/repo", None).unwrap());
        assert!(!access.allows(Operation::Write, "group/repo", None).unwrap());
        assert!(!access
            .allows(Operation::Create, "group/repo", None)
            .unwrap());
        assert!(access.allows(Operation::Stats, "group/repo", None).unwrap());
        assert!(!access
            .allows(Operation::Release, "group/repo", None)
            .unwrap());
        assert!(!access
            .allows(Operation::Interact, "group/repo", None)
            .unwrap());
        assert!(!access.allows(Operation::Admin, "group/repo", None).unwrap());
    }

    #[test]
    fn global_permission_rules_resolve_identity_aliases() {
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "alice".into(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        );
        let access = Access::new_with_aliases(
            &["alice".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            PathBuf::from("."),
            aliases,
        )
        .unwrap();

        let alice = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert!(access
            .allows(Operation::Read, "group/repo", Some(&alice))
            .unwrap());
    }

    #[test]
    fn allowed_files_resolve_identity_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "write = alice\n").unwrap();
        let mut aliases = BTreeMap::new();
        aliases.insert(
            "alice".into(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        );
        let access = Access::new_with_aliases(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().to_path_buf(),
            aliases,
        )
        .unwrap();
        let alice = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        assert!(access
            .allows(Operation::Write, "group/repo", Some(&alice))
            .unwrap());
    }

    #[test]
    fn repo_allowed_file_can_grant_write() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "write = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access.allows(Operation::Write, "group/repo", None).unwrap());
    }

    #[test]
    fn repo_sidecar_allowed_file_can_grant_write() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("group/repo")).unwrap();
        fs::write(tmp.path().join("group/repo.allowed"), "write = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access.allows(Operation::Write, "group/repo", None).unwrap());
    }

    #[test]
    fn repo_allowed_file_can_grant_stats_with_long_or_short_key() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "stats = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access.allows(Operation::Stats, "group/repo", None).unwrap());

        fs::write(repo.join(".allowed"), "s = all\n").unwrap();
        assert!(access.allows(Operation::Stats, "group/repo", None).unwrap());
    }

    #[test]
    fn repo_allowed_file_can_grant_create_with_long_or_short_key() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "create = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Create, "group/repo", None)
            .unwrap());

        fs::write(repo.join(".allowed"), "c = all\n").unwrap();
        assert!(access
            .allows(Operation::Create, "group/repo", None)
            .unwrap());
    }

    #[test]
    fn group_allowed_file_can_grant_create() {
        let tmp = tempfile::tempdir().unwrap();
        let group = tmp.path().join("group");
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("group.allowed"), "create = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Create, "group/repo", None)
            .unwrap());
    }

    #[test]
    fn group_sidecar_allowed_file_can_grant_create() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("group")).unwrap();
        fs::write(tmp.path().join("group.allowed"), "create = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Create, "group/repo", None)
            .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn executable_allowed_file_uses_stdout_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        let allowed = tmp.path().join("group/repo.allowed");
        fs::write(&allowed, "#!/bin/sh\nprintf 'stats = all\\n'\n").unwrap();
        let mut perms = fs::metadata(&allowed).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&allowed, perms).unwrap();

        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access.allows(Operation::Stats, "group/repo", None).unwrap());
    }

    #[test]
    fn group_allowed_file_can_grant_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let group = tmp.path().join("group");
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("group.allowed"), "s = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access.allows(Operation::Stats, "group/repo", None).unwrap());
    }

    #[test]
    fn repo_allowed_file_can_grant_release_with_long_or_short_key() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "release = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Release, "group/repo", None)
            .unwrap());

        fs::write(repo.join(".allowed"), "rel = all\n").unwrap();
        assert!(access
            .allows(Operation::Release, "group/repo", None)
            .unwrap());
    }

    #[test]
    fn group_allowed_file_can_grant_release() {
        let tmp = tempfile::tempdir().unwrap();
        let group = tmp.path().join("group");
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("group.allowed"), "rel = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Release, "group/repo", None)
            .unwrap());
    }

    #[test]
    fn repo_allowed_file_can_grant_interact_and_admin_with_long_or_short_key() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".allowed"), "interact = all\nadmin = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Interact, "group/repo", None)
            .unwrap());
        assert!(access.allows(Operation::Admin, "group/repo", None).unwrap());

        fs::write(repo.join(".allowed"), "i = all\nadm = all\n").unwrap();
        assert!(access
            .allows(Operation::Interact, "group/repo", None)
            .unwrap());
        assert!(access.allows(Operation::Admin, "group/repo", None).unwrap());
    }

    #[test]
    fn group_allowed_file_can_grant_interact_and_admin() {
        let tmp = tempfile::tempdir().unwrap();
        let group = tmp.path().join("group");
        fs::create_dir_all(&group).unwrap();
        fs::write(group.join("group.allowed"), "i = all\nadm = all\n").unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();
        assert!(access
            .allows(Operation::Interact, "group/repo", None)
            .unwrap());
        assert!(access.allows(Operation::Admin, "group/repo", None).unwrap());
    }

    #[test]
    fn admin_identity_satisfies_repository_permission_checks() {
        let tmp = tempfile::tempdir().unwrap();
        let admin = [0xA5; 16];
        let other = [0x5A; 16];
        let repo = tmp.path().join("group/repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(
            repo.join(".allowed"),
            "admin = a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5\n",
        )
        .unwrap();
        let access = Access::new(
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            &["none".into()],
            tmp.path().into(),
        )
        .unwrap();

        for op in [
            Operation::Read,
            Operation::Write,
            Operation::Create,
            Operation::Stats,
            Operation::Release,
            Operation::Interact,
        ] {
            assert!(access.allows(op, "group/repo", Some(&admin)).unwrap());
            assert!(!access.allows(op, "group/repo", Some(&other)).unwrap());
        }
    }

    #[test]
    fn invalid_repository_names_are_rejected_before_acl_files() {
        let access = Access::new(
            &["all".into()],
            &["all".into()],
            &["all".into()],
            &["all".into()],
            &["all".into()],
            &["all".into()],
            &["all".into()],
            PathBuf::from("."),
        )
        .unwrap();
        assert!(access.allows(Operation::Read, "../repo", None).is_err());
        assert!(access.allows(Operation::Create, "../repo", None).is_err());
        assert!(access.allows(Operation::Stats, "../repo", None).is_err());
        assert!(access.allows(Operation::Release, "../repo", None).is_err());
        assert!(access.allows(Operation::Interact, "../repo", None).is_err());
        assert!(access.allows(Operation::Admin, "../repo", None).is_err());
    }
}
