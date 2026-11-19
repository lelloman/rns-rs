//! Release pages.

use super::*;

pub(super) fn render_releases_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let releases: Vec<_> = crate::release::list_releases(&releases_path)?
        .into_iter()
        .filter(|release| release.status == "published")
        .collect();
    let latest_release = crate::release::configured_latest_tag(&releases_path)?;
    let mut out = format!(
        ">>\n{} / {} / {} / releases\n\n>Releases ({})\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        releases.len()
    );
    if releases.is_empty() {
        out.push_str("No releases available for this repository.\n");
        return Ok(out);
    }
    for release in releases {
        let latest = if latest_release.as_deref() == Some(release.tag.as_str()) {
            format!(" {} `FT537855`*Latest`*`f", icon_sep(config))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "{} `F666{} artifacts{}`f\n",
            m_link(
                &release.tag,
                PATH_RELEASE,
                &[("g", &group), ("r", &repo), ("tag", &release.tag)]
            ),
            release.artifacts,
            latest
        ));
        if !release.preview.is_empty() {
            append_release_preview(&mut out, &release.preview_format, &release.preview);
        }
        out.push('\n');
    }
    Ok(out)
}

pub(super) fn append_release_preview(out: &mut String, format: &str, preview: &str) {
    match format {
        "markdown" => out.push_str(&markdown_to_micron(preview)),
        "micron" => {
            out.push_str(preview);
            if !preview.ends_with('\n') {
                out.push('\n');
            }
        }
        _ => {
            out.push_str(&m_escape_line_start_controls(preview));
            out.push('\n');
        }
    }
}

pub(super) fn render_release_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, repository) = accessible_repository(config, access, remote, vars)?;
    let releases_path = crate::release::release_sidecar_path(&repository);
    let requested_tag = var(vars, "tag").unwrap_or("latest");
    let tag = if requested_tag == "latest" {
        let Some(tag) = crate::release::latest_published_tag(&releases_path)? else {
            return Ok(">Release Not Found\n\nNo latest release exists.\n".to_string());
        };
        tag
    } else {
        requested_tag.to_string()
    };
    let Some(release) = crate::release::release_data(&releases_path, &tag)? else {
        return Ok(">Release Not Found\n\nThe requested release was not found.\n".to_string());
    };
    if release.status != "published" {
        return Ok(">Release Not Found\n\nThe requested release was not found.\n".to_string());
    }
    let release_dir = releases_path.join(&release.tag);
    let thanks = crate::release::release_thanks(&release_dir, var(vars, "thanks").is_some())?;
    let mut out = format!(
        ">>\n{} / {} / {} / {} / {}\n\n>Release {}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_link("releases", PATH_RELEASES, &[("g", &group), ("r", &repo)]),
        m_escape(&release.tag),
        m_escape(&release.tag)
    );
    out.push_str(&format!(
        "{}\n\n",
        m_link(
            &icon_label(config, "heart", &format!("Thanks ({thanks})")),
            PATH_RELEASE,
            &[
                ("g", &group),
                ("r", &repo),
                ("tag", &release.tag),
                ("thanks", "y")
            ]
        )
    ));
    if !release.notes.is_empty() {
        match release.notes_format.as_str() {
            "markdown" => out.push_str(&markdown_to_micron(&release.notes)),
            "micron" => out.push_str(&release.notes),
            _ => out.push_str(&m_escape(&release.notes)),
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(">Artifacts\n\n");
    if release.artifacts.is_empty() {
        out.push_str("`*No artifacts for this release`*\n");
    } else {
        for artifact in release.artifacts {
            out.push_str(&format!(
                "{} ({})\n",
                m_link(
                    &artifact.name,
                    PATH_DOWNLOAD,
                    &[
                        ("g", &group),
                        ("r", &repo),
                        ("tag", &release.tag),
                        ("artifact", &artifact.name)
                    ]
                ),
                format_size(artifact.size)
            ));
        }
    }
    Ok(out)
}
