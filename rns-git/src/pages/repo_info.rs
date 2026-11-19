//! A repository's description, origin, thanks and readme.

use super::*;

pub(super) fn repository_description(repo: &Path) -> Result<String> {
    let path = repo.join("description");
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(path)?.trim().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RepositoryOrigin {
    pub(super) kind: RepositoryOriginKind,
    pub(super) source: String,
    pub(super) synced_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RepositoryOriginKind {
    Fork,
    Mirror,
}

impl RepositoryOrigin {
    pub(super) fn label(&self) -> &'static str {
        match self.kind {
            RepositoryOriginKind::Fork => "Forked",
            RepositoryOriginKind::Mirror => "Mirrored",
        }
    }
}

pub(super) fn repository_origin(repo: &Path) -> Result<Option<RepositoryOrigin>> {
    let kind_output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.type"),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !kind_output.status.success() {
        return Ok(None);
    }
    let kind = match String::from_utf8_lossy(&kind_output.stdout).trim() {
        "fork" => RepositoryOriginKind::Fork,
        "mirror" => RepositoryOriginKind::Mirror,
        _ => return Ok(None),
    };
    let source_output = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.upstream.source"),
        GIT_COMMAND_TIMEOUT,
    )?;
    if !source_output.status.success() {
        return Ok(None);
    }
    let source = String::from_utf8_lossy(&source_output.stdout)
        .trim()
        .to_string();
    if source.is_empty() {
        return Ok(None);
    }
    let synced_at = run_git_output(
        Command::new("git")
            .arg("--git-dir")
            .arg(repo)
            .arg("config")
            .arg("--get")
            .arg("repository.rngit.upstream.sync"),
        GIT_COMMAND_TIMEOUT,
    )
    .ok()
    .and_then(|output| output.status.success().then_some(output))
    .and_then(|output| {
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
    });

    Ok(Some(RepositoryOrigin {
        kind,
        source,
        synced_at,
    }))
}

pub(super) fn format_sync_age(synced_at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds = now.saturating_sub(synced_at);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

pub(super) fn repository_thanks(repo: &Path, add: bool) -> Result<u64> {
    let path = repo.with_extension("thanks");
    let mut count = if path.exists() {
        fs::read_to_string(&path)?
            .trim()
            .parse::<u64>()
            .unwrap_or(0)
    } else {
        0
    };
    if add {
        count = count.saturating_add(1);
        fs::write(path, format!("{count}\n"))?;
    }
    Ok(count)
}

#[derive(Debug)]
pub(super) struct ReadmeContent {
    pub(super) content: String,
    pub(super) markdown: bool,
}

pub(super) fn readme_content(repo: &Path) -> Result<Option<ReadmeContent>> {
    const NAMES: &[&str] = &[
        "README.mu",
        "Readme.mu",
        "readme.mu",
        "README",
        "readme",
        "README.md",
        "readme.md",
        "README.rst",
        "README.txt",
        "readme.rst",
        "readme.txt",
    ];
    for name in NAMES {
        match run_git_output(
            Command::new("git")
                .arg("--git-dir")
                .arg(repo)
                .arg("show")
                .arg(format!("HEAD:{name}")),
            GIT_COMMAND_TIMEOUT,
        ) {
            Ok(output) if output.status.success() => {
                let content = String::from_utf8_lossy(&output.stdout).into_owned();
                let markdown = name.ends_with(".md");
                let content = if markdown || name.ends_with(".mu") {
                    content
                } else {
                    m_escape(&content)
                };
                return Ok(Some(ReadmeContent { content, markdown }));
            }
            Ok(_) => {}
            Err(err) => {
                log::warn!("Git command execution failed while reading README: {err}");
            }
        }
    }
    Ok(None)
}
