use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::RefUpdate;
use crate::util::validate_repo_name;
use crate::{Error, Result};

pub fn check_git_available() -> Result<()> {
    run(Command::new("git").arg("--version")).map(|_| ())
}

pub fn repository_path(root: &Path, repository: &str) -> Result<PathBuf> {
    validate_repo_name(repository)?;
    Ok(root.join(repository))
}

pub fn validate_refname(refname: &str) -> Result<()> {
    if is_valid_refname(refname) {
        Ok(())
    } else {
        Err(Error::msg("invalid ref"))
    }
}

pub fn validate_namespaced_ref(refname: &str) -> Result<()> {
    validate_refname(refname)?;
    if refname.starts_with("refs/") {
        Ok(())
    } else {
        Err(Error::msg("invalid ref"))
    }
}

pub fn validate_sha(sha: &str) -> Result<()> {
    if is_valid_sha(sha) {
        Ok(())
    } else {
        Err(Error::msg("invalid SHA"))
    }
}

pub fn validate_shas<'a>(shas: impl IntoIterator<Item = &'a String>) -> Result<()> {
    for sha in shas {
        validate_sha(sha)?;
    }
    Ok(())
}

pub fn validate_ref_updates(updates: &[RefUpdate]) -> Result<()> {
    for update in updates {
        validate_namespaced_ref(&update.refname)?;
        if let Some(old) = update.old.as_deref() {
            validate_sha(old)?;
        }
        if let Some(new) = update.new.as_deref() {
            validate_sha(new)?;
        }
    }
    Ok(())
}

pub fn ensure_bare_repository(path: &Path) -> Result<()> {
    if is_bare_repository(path) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    run(Command::new("git").arg("init").arg("--bare").arg(path)).map(|_| ())
}

pub fn clone_remote_bare(source: &str, path: &Path, repository_type: &str) -> Result<()> {
    if source.trim().is_empty() {
        return Err(Error::msg("missing source"));
    }
    if path.exists() {
        return Err(Error::msg("repository already exists"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::msg("repository path has no parent"))?;
    fs::create_dir_all(parent)?;

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.clone-{suffix}"));

    let result = (|| {
        fs::create_dir_all(&temp)?;
        run(Command::new("git").arg("init").arg("--bare").arg(&temp))?;
        run(Command::new("git")
            .arg("--git-dir")
            .arg(&temp)
            .arg("fetch")
            .arg(source)
            .arg("+refs/*:refs/*"))?;
        run(Command::new("git")
            .arg("--git-dir")
            .arg(&temp)
            .arg("config")
            .arg("repository.rngit.type")
            .arg(repository_type))?;
        run(Command::new("git")
            .arg("--git-dir")
            .arg(&temp)
            .arg("config")
            .arg("repository.rngit.upstream.source")
            .arg(source))?;
        if matches!(repository_type, "fork" | "mirror") {
            run(Command::new("git")
                .arg("--git-dir")
                .arg(&temp)
                .arg("config")
                .arg("repository.rngit.upstream.sync")
                .arg(unix_timestamp().to_string()))?;
        }
        fs::rename(&temp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&temp);
    }
    result
}

pub fn repository_config(path: &Path, key: &str) -> Result<Option<String>> {
    require_repository(path)?;
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .arg("config")
        .arg("--get")
        .arg(key)
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

pub fn sync_upstream(path: &Path) -> Result<String> {
    require_repository(path)?;
    let repository_type = repository_config(path, "repository.rngit.type")?
        .ok_or_else(|| Error::msg("repository is neither fork nor mirror"))?;
    if !matches!(repository_type.as_str(), "fork" | "mirror") {
        return Err(Error::msg("repository is neither fork nor mirror"));
    }
    let source = repository_config(path, "repository.rngit.upstream.source")?
        .filter(|source| !source.is_empty())
        .ok_or_else(|| Error::msg("missing upstream source"))?;
    run(Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .arg("fetch")
        .arg(&source)
        .arg("+refs/*:refs/*"))?;
    if matches!(repository_type.as_str(), "fork" | "mirror") {
        run(Command::new("git")
            .arg("--git-dir")
            .arg(path)
            .arg("config")
            .arg("repository.rngit.upstream.sync")
            .arg(unix_timestamp().to_string()))?;
    }
    Ok(repository_type)
}

pub fn is_bare_repository(path: &Path) -> bool {
    path.join("HEAD").exists() && path.join("objects").is_dir()
}

pub fn list_refs(path: &Path) -> Result<Vec<(String, String)>> {
    require_repository(path)?;
    let output = run(Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .arg("for-each-ref")
        .arg("--format=%(objectname) %(refname)"))?;
    Ok(output
        .lines()
        .filter_map(|line| {
            let (sha, name) = line.split_once(' ')?;
            Some((sha.to_string(), name.to_string()))
        })
        .collect())
}

pub fn list_refs_text(path: &Path) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (sha, name) in list_refs(path)? {
        out.extend_from_slice(sha.as_bytes());
        out.push(b' ');
        out.extend_from_slice(name.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

pub fn create_bundle(path: &Path, have: &[String]) -> Result<Vec<u8>> {
    require_repository(path)?;
    validate_shas(have)?;
    if list_refs(path)?.is_empty() {
        return Ok(Vec::new());
    }
    let bundle_path = temp_path("rngit-fetch", "bundle");
    let exclusions = valid_repo_objects(path, have);
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir")
        .arg(path)
        .arg("bundle")
        .arg("create")
        .arg(&bundle_path)
        .arg("--all");
    add_exclusions(&mut cmd, &exclusions);
    let result = run(&mut cmd);
    let bytes = match result {
        Ok(_) => fs::read(&bundle_path)?,
        Err(err) if is_empty_bundle_error(&err) => Vec::new(),
        Err(err) => {
            let _ = fs::remove_file(&bundle_path);
            return Err(err);
        }
    };
    let _ = fs::remove_file(&bundle_path);
    Ok(bytes)
}

pub fn apply_push(path: &Path, bundle: &[u8], updates: &[RefUpdate]) -> Result<()> {
    validate_ref_updates(updates)?;
    ensure_bare_repository(path)?;
    if !bundle.is_empty() {
        let bundle_path = temp_path("rngit-push", "bundle");
        fs::write(&bundle_path, bundle)?;
        let result = run(Command::new("git")
            .arg("--git-dir")
            .arg(path)
            .arg("fetch")
            .arg(&bundle_path)
            .arg("+refs/heads/*:refs/heads/*")
            .arg("+refs/tags/*:refs/tags/*"));
        let _ = fs::remove_file(&bundle_path);
        result?;
    }

    for update in updates {
        if let Some(new) = update.new.as_deref() {
            update_ref(
                path,
                &update.refname,
                new,
                update.old.as_deref(),
                update.force,
            )?;
        } else {
            delete_ref(path, &update.refname, update.old.as_deref(), update.force)?;
        }
    }
    Ok(())
}

pub fn local_ref_sha(refname: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--verify")
        .arg(refname)
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

pub fn create_local_bundle(refs: &[String], exclusions: &[String]) -> Result<Vec<u8>> {
    create_local_bundle_in(Path::new("."), refs, exclusions)
}

fn create_local_bundle_in(repo: &Path, refs: &[String], exclusions: &[String]) -> Result<Vec<u8>> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    for refname in refs {
        validate_refname(refname)?;
    }
    validate_shas(exclusions)?;
    let bundle_path = temp_path("rngit-local-push", "bundle");
    let valid_exclusions = valid_local_objects_in(repo, exclusions);
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .arg("bundle")
        .arg("create")
        .arg(&bundle_path)
        .args(refs);
    add_exclusions(&mut cmd, &valid_exclusions);
    let result = run(&mut cmd);
    let bytes = match result {
        Ok(_) => fs::read(&bundle_path)?,
        Err(err) if is_empty_bundle_error(&err) => Vec::new(),
        Err(err) => {
            let _ = fs::remove_file(&bundle_path);
            return Err(err);
        }
    };
    let _ = fs::remove_file(&bundle_path);
    Ok(bytes)
}

pub fn object_exists_local(sha: &str) -> bool {
    object_exists_local_in(Path::new("."), sha)
}

fn object_exists_local_in(repo: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("cat-file")
        .arg("-e")
        .arg(format!("{sha}^{{object}}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn fetch_bundle_into_local(bundle: &[u8], wanted: &[String]) -> Result<()> {
    if bundle.is_empty() {
        return Ok(());
    }
    for refname in wanted {
        validate_refname(refname)?;
    }
    let bundle_path = temp_path("rngit-local-fetch", "bundle");
    fs::write(&bundle_path, bundle)?;
    let mut cmd = Command::new("git");
    cmd.arg("fetch").arg(&bundle_path);
    if wanted.is_empty() {
        cmd.arg("refs/*:refs/*");
    } else {
        cmd.args(wanted);
    }
    let result = run(&mut cmd);
    let _ = fs::remove_file(&bundle_path);
    result.map(|_| ())
}

fn update_ref(path: &Path, refname: &str, new: &str, old: Option<&str>, force: bool) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir")
        .arg(path)
        .arg("update-ref")
        .arg(refname)
        .arg(new);
    if !force {
        if let Some(old) = old {
            cmd.arg(old);
        }
    }
    run(&mut cmd).map(|_| ())
}

fn delete_ref(path: &Path, refname: &str, old: Option<&str>, force: bool) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir")
        .arg(path)
        .arg("update-ref")
        .arg("-d")
        .arg(refname);
    if !force {
        if let Some(old) = old {
            cmd.arg(old);
        }
    }
    run(&mut cmd).map(|_| ())
}

fn require_repository(path: &Path) -> Result<()> {
    if is_bare_repository(path) {
        Ok(())
    } else {
        Err(Error::msg("repository not found"))
    }
}

fn valid_repo_objects(path: &Path, shas: &[String]) -> Vec<String> {
    shas.iter()
        .filter(|sha| object_exists_in_repo(path, sha))
        .cloned()
        .collect()
}

fn valid_local_objects_in(repo: &Path, shas: &[String]) -> Vec<String> {
    shas.iter()
        .filter(|sha| object_exists_local_in(repo, sha))
        .cloned()
        .collect()
}

fn object_exists_in_repo(path: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .arg("cat-file")
        .arg("-e")
        .arg(format!("{sha}^{{object}}"))
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn is_valid_refname(refname: &str) -> bool {
    if refname.is_empty()
        || refname.starts_with('-')
        || refname.starts_with('/')
        || refname.ends_with('/')
        || refname.ends_with('.')
        || !refname.contains('/')
        || refname.contains(' ')
        || refname.contains("..")
        || refname.contains("/.")
        || refname.contains("//")
        || refname.contains('\\')
        || refname.contains('~')
        || refname.contains('^')
        || refname.contains(':')
        || refname.contains('?')
        || refname.contains('*')
        || refname.contains('[')
        || refname.contains("@{")
        || refname == "@"
    {
        return false;
    }

    if refname
        .split('/')
        .any(|component| component.is_empty() || component.ends_with(".lock"))
    {
        return false;
    }

    refname.chars().all(|c| (c as u32) >= 40 && c != '\u{7f}')
}

fn is_valid_sha(sha: &str) -> bool {
    sha.len() >= 40 && sha.len() % 2 == 0 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

fn add_exclusions(cmd: &mut Command, exclusions: &[String]) {
    for sha in exclusions {
        cmd.arg(format!("^{sha}"));
    }
}

fn is_empty_bundle_error(err: &Error) -> bool {
    let message = err.to_string();
    message.contains("Refusing to create empty bundle")
        || message.contains("does not have any commits")
        || message.contains("Refusing to create empty")
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}.{extension}", std::process::id()))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn run(cmd: &mut Command) -> Result<String> {
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(Error::msg(if stderr.is_empty() {
        "git command failed".to_string()
    } else {
        stderr
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_repo_can_list_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo.git");
        ensure_bare_repository(&repo).unwrap();
        assert!(list_refs(&repo).unwrap().is_empty());
    }

    #[test]
    fn repository_paths_reject_traversal() {
        assert!(repository_path(Path::new("/tmp/repos"), "../x").is_err());
        assert!(repository_path(Path::new("/tmp/repos"), "group/repo").is_ok());
    }

    #[test]
    fn ref_validation_rejects_noncanonical_names() {
        assert!(validate_refname("refs/heads/main").is_ok());
        assert!(validate_refname("refs/tags/v1").is_ok());

        for name in [
            "-refs/heads/main",
            "/refs/heads/main",
            "refs/heads/main/",
            "refs/heads/main.",
            "refs/heads/feature lock",
            "main",
            "refs/heads/../main",
            "refs/heads/.hidden",
            "refs/heads//main",
            "refs\\heads\\main",
            "refs/heads/main.lock",
            "refs/heads/main~",
            "refs/heads/main^",
            "refs/heads/main:evil",
            "refs/heads/main?",
            "refs/heads/main*",
            "refs/heads/main[",
            "refs/heads/@{upstream}",
            "@",
            "refs/heads/\nmain",
        ] {
            assert!(
                validate_refname(name).is_err(),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn sha_validation_rejects_non_hex_or_short_values() {
        assert!(validate_sha("0123456789abcdef0123456789abcdef01234567").is_ok());
        assert!(
            validate_sha("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .is_ok()
        );

        for sha in [
            "",
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef0123456g",
            "--upload-pack=/tmp/x",
            "0123456789abcdef0123456789abcdef012345678",
        ] {
            assert!(validate_sha(sha).is_err(), "{sha:?} should be rejected");
        }
    }

    #[test]
    fn bundle_push_roundtrip_updates_bare_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let target = tmp.path().join("target.git");
        fs::create_dir_all(&work).unwrap();

        test_git(Command::new("git").arg("init").arg(&work));
        fs::write(work.join("README.md"), "hello\n").unwrap();
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("add")
                .arg("README.md"),
        );
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("-c")
                .arg("user.name=RNS Test")
                .arg("-c")
                .arg("user.email=rns@example.invalid")
                .arg("commit")
                .arg("-m")
                .arg("init"),
        );
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("branch")
                .arg("-M")
                .arg("main"),
        );
        let sha = test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("rev-parse")
                .arg("refs/heads/main"),
        );
        let sha = sha.trim().to_string();
        let bundle_path = tmp.path().join("push.bundle");
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("bundle")
                .arg("create")
                .arg(&bundle_path)
                .arg("refs/heads/main"),
        );

        apply_push(
            &target,
            &fs::read(&bundle_path).unwrap(),
            &[RefUpdate {
                refname: "refs/heads/main".into(),
                old: None,
                new: Some(sha.clone()),
                force: true,
            }],
        )
        .unwrap();

        assert_eq!(
            list_refs(&target).unwrap(),
            vec![(sha.clone(), "refs/heads/main".into())]
        );
        assert!(!create_bundle(&target, &[]).unwrap().is_empty());
        assert!(create_bundle(&target, &[sha]).unwrap().is_empty());
    }

    #[test]
    fn local_push_bundle_excludes_known_remote_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();

        test_git(Command::new("git").arg("init").arg(&work));
        fs::write(work.join("README.md"), "hello\n").unwrap();
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("add")
                .arg("README.md"),
        );
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("-c")
                .arg("user.name=RNS Test")
                .arg("-c")
                .arg("user.email=rns@example.invalid")
                .arg("commit")
                .arg("-m")
                .arg("init"),
        );
        test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("branch")
                .arg("-M")
                .arg("main"),
        );
        let sha = test_git(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("rev-parse")
                .arg("refs/heads/main"),
        )
        .trim()
        .to_string();
        let full = create_local_bundle_in(&work, &["refs/heads/main".into()], &[]).unwrap();
        let excluded = create_local_bundle_in(&work, &["refs/heads/main".into()], &[sha]).unwrap();
        assert!(!full.is_empty());
        assert!(excluded.is_empty());
    }

    fn test_git(cmd: &mut Command) -> String {
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}
