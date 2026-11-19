//! Reading refs, trees, blobs and commits from git.

use super::*;

#[derive(Debug)]
pub(super) struct Refs {
    pub(super) heads: Vec<RefInfo>,
    pub(super) tags: Vec<RefInfo>,
}

#[derive(Debug)]
pub(super) struct RefInfo {
    pub(super) sha: String,
    pub(super) name: String,
}

pub(super) fn git_refs(repo: &Path) -> Result<Refs> {
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .args(["for-each-ref", "--format=%(objectname) %(refname)"]),
    )?;
    let mut refs = Refs {
        heads: Vec::new(),
        tags: Vec::new(),
    };
    for line in output.lines() {
        let Some((sha, name)) = line.split_once(' ') else {
            continue;
        };
        if let Some(short) = name.strip_prefix("refs/heads/") {
            refs.heads.push(RefInfo {
                sha: sha.to_string(),
                name: short.to_string(),
            });
        } else if let Some(short) = name.strip_prefix("refs/tags/") {
            refs.tags.push(RefInfo {
                sha: sha.to_string(),
                name: short.to_string(),
            });
        }
    }
    Ok(refs)
}

pub(super) fn resolve_ref(repo: &Path, reference: &str) -> Result<String> {
    validate_refish(reference)?;
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("rev-parse")
            .arg("--verify")
            .arg(format!("{reference}^{{commit}}")),
    )?;
    Ok(output.trim().to_string())
}

#[derive(Debug)]
pub(super) struct TreeEntry {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) size: Option<u64>,
}

impl TreeEntry {
    pub(super) fn size_label(&self) -> String {
        self.size
            .map(|size| format!(" ({size} bytes)"))
            .unwrap_or_default()
    }
}

pub(super) fn tree_entries(repo: &Path, reference: &str, path: &str) -> Result<Vec<TreeEntry>> {
    validate_git_path(path)?;
    let spec = if path.is_empty() {
        reference.to_string()
    } else {
        format!("{reference}:{path}")
    };
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("ls-tree")
            .arg("-l")
            .arg(spec),
    )?;
    let mut entries = Vec::new();
    for line in output.lines() {
        let Some((meta, name)) = line.split_once('\t') else {
            continue;
        };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let size = parts[3].parse::<u64>().ok();
        entries.push(TreeEntry {
            kind: parts[1].to_string(),
            name: name.to_string(),
            size,
        });
    }
    entries.sort_by_key(|entry| (entry.kind != "tree", entry.name.to_ascii_lowercase()));
    Ok(entries)
}

pub(super) fn git_object_kind(repo: &Path, reference: &str, path: &str) -> Result<String> {
    validate_git_path(path)?;
    let spec = if path.is_empty() {
        reference.to_string()
    } else {
        format!("{reference}:{path}")
    };
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-t")
            .arg(spec),
    )?;
    Ok(output.trim().to_string())
}

pub(super) struct BlobInfo {
    pub(super) content: String,
    pub(super) size: u64,
    pub(super) binary: bool,
    pub(super) displayable: bool,
}

pub(super) fn blob_info(repo: &Path, reference: &str, path: &str) -> Result<BlobInfo> {
    validate_git_path(path)?;
    let spec = format!("{reference}:{path}");
    let size = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-s")
            .arg(&spec),
    )?
    .trim()
    .parse::<u64>()
    .unwrap_or(0);
    if size > 256 * 1024 && !is_image_path(path) {
        return Ok(BlobInfo {
            content: format!("File is too large to display ({size} bytes)."),
            size,
            binary: false,
            displayable: false,
        });
    }
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("show")
            .arg(spec),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    let binary = output.stdout.contains(&0);
    if size > 256 * 1024 && !binary {
        return Ok(BlobInfo {
            content: format!("File is too large to display ({size} bytes)."),
            size,
            binary: false,
            displayable: false,
        });
    }
    Ok(BlobInfo {
        content: if binary {
            "Binary file is not displayed.".to_string()
        } else {
            String::from_utf8_lossy(&output.stdout).into_owned()
        },
        size,
        binary,
        displayable: !binary,
    })
}

#[derive(Debug)]
pub(super) struct CommitSummary {
    pub(super) hash: String,
    pub(super) subject: String,
    pub(super) author: String,
    pub(super) timestamp: i64,
}

pub(super) fn commits(repo: &Path, reference: &str, limit: usize) -> Result<Vec<CommitSummary>> {
    let format = "%H%x1f%s%x1f%an%x1f%at";
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("log")
            .arg(format!("--format={format}"))
            .arg("-n")
            .arg(limit.to_string())
            .arg(reference),
    )?;
    let mut commits = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\x1f').collect();
        if parts.len() == 4 {
            commits.push(CommitSummary {
                hash: parts[0].to_string(),
                subject: parts[1].to_string(),
                author: parts[2].to_string(),
                timestamp: parts[3].parse().unwrap_or_default(),
            });
        }
    }
    Ok(commits)
}

#[derive(Debug)]
pub(super) struct CommitInfo {
    pub(super) hash: String,
    pub(super) subject: String,
    pub(super) body: String,
    pub(super) author: String,
    pub(super) email: String,
    pub(super) timestamp: i64,
    pub(super) files: Vec<CommitFile>,
}

#[derive(Debug)]
pub(super) struct CommitFile {
    pub(super) status: String,
    pub(super) path: String,
}

pub(super) fn commit_info(repo: &Path, hash: &str) -> Result<CommitInfo> {
    validate_refish(hash)?;
    let output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("show")
            .arg("--no-patch")
            .arg("--format=%H%x1f%s%x1f%an%x1f%ae%x1f%at%x1f%B")
            .arg(hash),
    )?;
    let parts: Vec<&str> = output.splitn(6, '\x1f').collect();
    if parts.len() != 6 {
        return Err(Error::msg("invalid commit output"));
    }
    let files_output = run_git(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("diff-tree")
            .arg("--root")
            .arg("--no-commit-id")
            .arg("--name-status")
            .arg("-r")
            .arg(hash),
    )?;
    let mut files = Vec::new();
    for line in files_output.lines() {
        let Some((status, path)) = line.split_once('\t') else {
            continue;
        };
        files.push(CommitFile {
            status: status.to_string(),
            path: path.to_string(),
        });
    }
    Ok(CommitInfo {
        hash: parts[0].trim().to_string(),
        subject: parts[1].trim().to_string(),
        author: parts[2].trim().to_string(),
        email: parts[3].trim().to_string(),
        timestamp: parts[4].trim().parse().unwrap_or_default(),
        body: parts[5].trim().to_string(),
        files,
    })
}

pub(super) fn raw_commit_object(repo: &Path, hash: &str) -> Result<Vec<u8>> {
    validate_refish(hash)?;
    let output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("cat-file")
            .arg("-p")
            .arg(hash),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    Ok(output.stdout)
}

pub(super) fn run_git(cmd: &mut Command) -> Result<String> {
    let output = run_git_output(cmd, GIT_COMMAND_TIMEOUT)?;
    if !output.status.success() {
        return Err(Error::msg(String::from_utf8_lossy(&output.stderr)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) fn run_git_output(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    // Spool both outputs while Git runs: waiting before draining a pipe would
    // deadlock once a media blob fills the pipe buffer. Owned files also let
    // timeout cleanup finish without waiting on pipe-reader threads.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = cmd
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let deadline = Instant::now() + timeout;

    loop {
        if let Some(status) = child.try_wait()? {
            stdout.seek(SeekFrom::Start(0))?;
            stderr.seek(SeekFrom::Start(0))?;
            let mut output = Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
            stdout.read_to_end(&mut output.stdout)?;
            stderr.read_to_end(&mut output.stderr)?;
            return Ok(output);
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            log::warn!("Git command execution timed out");
            return Err(Error::msg("Git command execution timed out"));
        }

        let sleep_for = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }
}
