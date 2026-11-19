//! A repository's pages: its front page, tree, blobs, commits and refs.

use super::*;

pub(super) fn render_front_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
) -> Result<String> {
    let groups = accessible_groups(config, access, remote)?;
    let mut out = format!(">>\n{} /\n\n>Groups\n\n", m_link("Node", PATH_INDEX, &[]));
    if groups.is_empty() {
        out.push_str("No repository groups available.\n");
        return Ok(out);
    }
    for (group, repos) in groups {
        out.push_str(&format!(
            "{} ({} repositories)\n",
            m_link(&group, PATH_GROUP, &[("g", &group)]),
            repos.len()
        ));
        for repo in repos {
            out.push_str(&format!(
                "  - {}\n",
                m_link_raw(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
            ));
        }
    }
    Ok(out)
}

pub(super) fn render_group_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let group = required_var(vars, "g")?;
    validate_group_name(group)?;
    let repos = accessible_repositories(config, access, remote, group)?;
    if repos.is_empty() {
        return Ok(">Group Not Found\n\nThe requested group was not found.\n".to_string());
    }

    let mut out = format!(
        ">>\n{} / {}\n\n>Repositories\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_escape(group)
    );
    for repo in repos {
        let repo_path = config.repositories_dir.join(group).join(&repo);
        let description = repository_description(&repo_path)?;
        out.push_str(&format!(
            "- {}",
            m_link(&repo, PATH_REPO, &[("g", group), ("r", &repo)])
        ));
        if !description.is_empty() {
            out.push_str(&format!(" - {}", m_escape(&description)));
        }
        out.push('\n');
    }
    Ok(out)
}

pub(super) fn render_repo_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let description = repository_description(&repository)?;
    let origin = repository_origin(&repository)?;
    let refs = git_refs(&repository)?;
    let readme = readme_content(&repository)?;
    let repo_url = format!("rns://<repository-destination>/{group}/{repo}");
    let thanks = repository_thanks(&repository, var(vars, "thanks").is_some())?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let release_count = crate::release::list_releases(&releases_path)?
        .into_iter()
        .filter(|release| release.status == "published")
        .count();
    let work_path = crate::work::work_sidecar_path(&repository);
    let work_lists = crate::work::list_documents(&work_path, crate::work::WorkListScope::All)?;
    let work_count = work_lists.active.len() + work_lists.completed.len();

    let branch_count = refs.heads.len().to_string();
    let tag_count = refs.tags.len().to_string();
    let mut out = format!(
        ">>\n{} / {} / {} `F666{}`f\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_escape(&repo),
        m_escape(&repo_url)
    );
    if let Some(origin) = origin {
        out.push_str(&format!(
            "`F666{} from {}`f",
            origin.label(),
            m_escape(&origin.source)
        ));
        if let Some(synced_at) = origin.synced_at {
            out.push_str(&format!(
                " `*`F666synced {} ago`f`*",
                format_sync_age(synced_at)
            ));
        }
        out.push('\n');
    }
    out.push('\n');
    if !description.is_empty() {
        out.push_str(&format!("{}\n\n", m_escape(&description)));
    }
    let mut nav_links = vec![
        m_link_raw(
            &icon_label(config, "folder", "Files"),
            PATH_TREE,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            &icon_label(config, "commits", "Commits"),
            PATH_COMMITS,
            &[("g", &group), ("r", &repo), ("ref", "HEAD")],
        ),
        m_link_raw(
            &icon_label(config, "branch", &format!("Branches ({branch_count})")),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "heads")],
        ),
        m_link_raw(
            &icon_label(config, "tag", &format!("Tags ({tag_count})")),
            PATH_REFS,
            &[("g", &group), ("r", &repo), ("type", "tags")],
        ),
        m_link_raw(
            &icon_label(config, "heart", &format!("Thanks ({thanks})")),
            PATH_REPO,
            &[("g", &group), ("r", &repo), ("thanks", "y")],
        ),
    ];
    if release_count > 0 {
        nav_links.push(m_link_raw(
            &icon_label(config, "package", &format!("Releases ({release_count})")),
            PATH_RELEASES,
            &[("g", &group), ("r", &repo)],
        ));
    }
    if work_count > 0 {
        nav_links.push(m_link_raw(
            &icon_label(config, "work", &format!("Work ({work_count})")),
            PATH_WORK,
            &[("g", &group), ("r", &repo)],
        ));
    }
    if access.allows(Operation::Stats, &format!("{group}/{repo}"), remote)? {
        nav_links.push(m_link_raw(
            &icon_label(config, "stats", "Stats"),
            PATH_STATS,
            &[("g", &group), ("r", &repo)],
        ));
    }
    let sep = format!(" {} ", icon_sep(config));
    out.push_str(&format!("{}\n\n", nav_links.join(&sep)));
    if let Some(readme) = readme {
        if !readme.content.trim_start().starts_with('>') {
            out.push_str("-\n");
        }
        if readme.markdown {
            out.push_str(&markdown_to_micron_scoped(
                &readme.content,
                Some(&markdown_blob_url_scope(&group, &repo, "HEAD", "README.md")),
            ));
            if !out.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str(readme.content.trim_end());
            out.push('\n');
        }
    } else {
        out.push_str("No README file found in this repository.\n");
    }
    Ok(out)
}

pub(super) fn render_tree_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let path = var(vars, "path").unwrap_or("");
    validate_git_path(path)?;
    let resolved = resolve_ref(&repository, reference)?;
    let entries = tree_entries(&repository, &resolved, path)?;
    let title_path = if path.is_empty() { "/" } else { path };

    let mut out = format!(
        ">>\n{} / {} / {} / files / {}\n\n>Contents: {} ({})\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(title_path),
        m_escape(reference),
        &resolved[..8]
    );
    if entries.is_empty() {
        out.push_str("Empty directory.\n");
    } else {
        for entry in entries {
            let entry_path = join_git_path(path, &entry.name);
            if entry.kind == "tree" {
                let label = icon_label(config, "folder", &format!("{}/", entry.name));
                out.push_str(&format!(
                    "{}\n",
                    m_link_raw(
                        &label,
                        PATH_TREE,
                        &[
                            ("g", &group),
                            ("r", &repo),
                            ("ref", reference),
                            ("path", &entry_path)
                        ]
                    )
                ));
            } else {
                let label = icon_label(config, "file", &entry.name);
                out.push_str(&format!(
                    "{} {}\n",
                    m_link_raw(
                        &label,
                        PATH_BLOB,
                        &[
                            ("g", &group),
                            ("r", &repo),
                            ("ref", reference),
                            ("path", &entry_path)
                        ]
                    ),
                    entry.size_label()
                ));
            }
        }
    }
    Ok(out)
}

pub(super) fn render_blob_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let path = normalize_blob_path(required_var(vars, "path")?);
    validate_git_path(&path)?;
    let resolved = resolve_ref(&repository, reference)?;
    if git_object_kind(&repository, &resolved, &path)? == "tree" {
        return render_tree_page(config, access, remote, vars);
    }
    let blob = blob_info(&repository, &resolved, &path)?;
    let renderable = renderable_blob(&path);
    let raw_requested = var(vars, "raw").is_some();
    let render_requested = var(vars, "render").is_some();
    let render =
        renderable.is_some() && !raw_requested && (render_requested || render_by_default(&path));
    let download_link = m_link(
        "Download",
        PATH_DOWNLOAD,
        &[
            ("g", &group),
            ("r", &repo),
            ("ref", reference),
            ("path", path.as_str()),
        ],
    );
    let converted_download_link = matches!(renderable, Some(RenderableBlob::Markdown)).then(|| {
        m_link(
            "as micron",
            PATH_DOWNLOAD,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path.as_str()),
                ("fmt", "mu"),
            ],
        )
    });
    let controls = if renderable.is_some() {
        let render_link = m_link(
            "View rendered",
            PATH_BLOB,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path.as_str()),
                ("render", "y"),
            ],
        );
        let raw_link = m_link(
            "View raw",
            PATH_BLOB,
            &[
                ("g", &group),
                ("r", &repo),
                ("ref", reference),
                ("path", path.as_str()),
                ("raw", "y"),
            ],
        );
        let sep = icon_sep(config);
        let display_controls = if render {
            format!("Displaying Rendered {sep} {raw_link}")
        } else {
            format!("Displaying Raw {sep} {render_link}")
        };
        Some(match converted_download_link {
            Some(converted) => {
                format!("{display_controls} {sep} {download_link} {sep} {converted}")
            }
            None => format!("{display_controls} {sep} {download_link}"),
        })
    } else {
        Some(format!(
            "Displaying Raw {} {download_link}",
            icon_sep(config)
        ))
    };
    let content = if blob.binary && is_image_path(&path) {
        format!(
            "`(Image file`w=n`a=c`:/media/{group}/{repo}/{reference}/{})\n",
            quote_media_path(&path)
        )
    } else if !blob.displayable {
        crate::highlight::plain_literal_block(&blob.content)
    } else if render {
        match renderable {
            Some(RenderableBlob::Markdown) => markdown_to_micron_scoped(
                &blob.content,
                Some(&markdown_blob_url_scope(&group, &repo, reference, &path)),
            ),
            Some(RenderableBlob::Micron) => {
                let mut out = blob.content.clone();
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out
            }
            None => crate::highlight::literal_block(&blob.content, Some(&path), None),
        }
    } else {
        crate::highlight::literal_block(&blob.content, Some(&path), None)
    };
    let controls = controls
        .map(|controls| format!("{controls}\n\n"))
        .unwrap_or_default();
    Ok(format!(
        ">>\n{} / {} / {} / {}\n\n>{} `F666{} ({}, {})`f\n\n{}{}",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(&path),
        m_escape(&path),
        &resolved[..8],
        if blob.binary { "Binary" } else { "Text" },
        format_size(blob.size),
        controls,
        content
    ))
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RenderableBlob {
    Markdown,
    Micron,
}

pub(super) fn renderable_blob(path: &str) -> Option<RenderableBlob> {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("md") => Some(RenderableBlob::Markdown),
        Some("mu") => Some(RenderableBlob::Micron),
        _ => None,
    }
}

pub(super) fn render_by_default(path: &str) -> bool {
    renderable_blob(path).is_some()
}

pub(super) fn render_commits_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let resolved = resolve_ref(&repository, reference)?;
    let commits = commits(&repository, &resolved, 100)?;

    let mut out = format!(
        ">>\n{} / {} / {} / commits\n\n>Commits `F666{} ({})`f\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(reference),
        &resolved[..8]
    );
    if commits.is_empty() {
        out.push_str("No commits found.\n");
    } else {
        for commit in commits {
            out.push_str(&format!(
                "{} {} `F666{}`f\n{}\n\n",
                m_link_raw(
                    &commit.hash[..7],
                    PATH_COMMIT,
                    &[
                        ("g", &group),
                        ("r", &repo),
                        ("ref", reference),
                        ("h", &commit.hash),
                    ],
                ),
                m_escape(&commit.author),
                format_unix_time(commit.timestamp),
                m_escape(&commit.subject)
            ));
        }
    }
    Ok(out)
}

pub(super) fn render_commit_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let reference = var(vars, "ref").unwrap_or("HEAD");
    let _resolved = resolve_ref(&repository, reference)?;
    let hash = required_var(vars, "h")?;
    validate_refish(hash)?;
    let commit = commit_info(&repository, hash)?;
    let signature = commit_signature_status(&repository, hash)?;
    let commits_link = m_link(
        "commits",
        PATH_COMMITS,
        &[("g", &group), ("r", &repo), ("ref", reference)],
    );
    let mut out = format!(
        ">>\n{} / {} / {} / {} / commit {}\n\n>Commit {}\n\n{}\nAuthor: {} <{}>\nDate: {}\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        commits_link,
        &commit.hash[..7],
        commit.hash,
        m_escape(&commit.subject),
        m_escape(&commit.author),
        m_escape(&commit.email),
        format_unix_time(commit.timestamp)
    );
    if let Some(signature) = signature {
        out.push_str(&format!("Signature: {}\n", m_escape(&signature)));
    }
    if !commit.body.is_empty() {
        out.push_str(&format!("\n{}\n", format_commit_message(&commit.body)));
    }
    out.push_str("\n>Files changed\n\n");
    for file in commit.files {
        out.push_str(&format!("{} {}\n", file.status, m_escape(&file.path)));
    }
    Ok(out)
}

pub(super) fn commit_signature_status(repo: &Path, hash: &str) -> Result<Option<String>> {
    let commit = raw_commit_object(repo, hash)?;
    let (Some(signature), signed_content) = crate::commitsigs::split_commit_signature(&commit)
    else {
        return Ok(None);
    };
    let status = crate::commitsigs::verify_message_signature(&signature, &signed_content, None);
    if status.valid && status.author_match {
        Ok(Some("Valid, signed by author".into()))
    } else if status.valid {
        Ok(Some(status.message))
    } else {
        Ok(Some(format!("Invalid signature: {}", status.message)))
    }
}

pub(super) fn render_refs_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let refs = git_refs(&repository)?;
    let mut out = format!(
        ">>\n{} / {} / {} / refs\n\n>Refs\n\n>Branches\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)])
    );
    for branch in refs.heads {
        out.push_str(&format!(
            "- {} `F666{}`f\n",
            m_link_raw(
                &branch.name,
                PATH_TREE,
                &[("g", &group), ("r", &repo), ("ref", &branch.name)]
            ),
            &branch.sha[..8]
        ));
    }
    out.push_str("\n>Tags\n");
    for tag in refs.tags {
        out.push_str(&format!(
            "- {} `F666{}`f\n",
            m_link_raw(
                &tag.name,
                PATH_TREE,
                &[("g", &group), ("r", &repo), ("ref", &tag.name)]
            ),
            &tag.sha[..8]
        ));
    }
    Ok(out)
}
