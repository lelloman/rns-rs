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

pub fn ensure_bare_repository(path: &Path) -> Result<()> {
    if path.join("HEAD").exists() && path.join("objects").is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    run(Command::new("git").arg("init").arg("--bare").arg(path)).map(|_| ())
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

pub fn create_bundle(path: &Path, _have: &[String]) -> Result<Vec<u8>> {
    require_repository(path)?;
    if list_refs(path)?.is_empty() {
        return Ok(Vec::new());
    }
    let bundle_path = temp_path("rngit-fetch", "bundle");
    let result = run(Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .arg("bundle")
        .arg("create")
        .arg(&bundle_path)
        .arg("--all"));
    let bytes = match result {
        Ok(_) => fs::read(&bundle_path)?,
        Err(err) => {
            let _ = fs::remove_file(&bundle_path);
            return Err(err);
        }
    };
    let _ = fs::remove_file(&bundle_path);
    Ok(bytes)
}

pub fn apply_push(path: &Path, bundle: &[u8], updates: &[RefUpdate]) -> Result<()> {
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

pub fn create_local_bundle(refs: &[String]) -> Result<Vec<u8>> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let bundle_path = temp_path("rngit-local-push", "bundle");
    let result = run(Command::new("git")
        .arg("bundle")
        .arg("create")
        .arg(&bundle_path)
        .args(refs));
    let bytes = match result {
        Ok(_) => fs::read(&bundle_path)?,
        Err(err) => {
            let _ = fs::remove_file(&bundle_path);
            return Err(err);
        }
    };
    let _ = fs::remove_file(&bundle_path);
    Ok(bytes)
}

pub fn fetch_bundle_into_local(bundle: &[u8], wanted: &[String]) -> Result<()> {
    if bundle.is_empty() {
        return Ok(());
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
    if path.join("HEAD").exists() && path.join("objects").is_dir() {
        Ok(())
    } else {
        Err(Error::msg("repository not found"))
    }
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}.{extension}", std::process::id()))
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
            vec![(sha, "refs/heads/main".into())]
        );
        assert!(!create_bundle(&target, &[]).unwrap().is_empty());
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
