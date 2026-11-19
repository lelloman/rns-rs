//! Micron markup: links, icons, escaping and formatted values.

use super::*;

pub(super) fn icon(config: &ServerConfig, name: &str) -> &'static str {
    if !config.unicode_icons {
        return "";
    }
    match name {
        "sep" => "•",
        "folder" => "🗀",
        "file" => "🗎",
        "branch" => "⑃",
        "tag" => "⌆",
        "commits" => "🖹",
        "package" => "▣",
        "stats" => "🗠",
        "heart" => "♥",
        _ => "",
    }
}

pub(super) fn icon_label(config: &ServerConfig, name: &str, label: &str) -> String {
    let icon = icon(config, name);
    if icon.is_empty() {
        label.to_string()
    } else {
        format!("{icon} {label}")
    }
}

pub(super) fn icon_sep(config: &ServerConfig) -> &'static str {
    let sep = icon(config, "sep");
    if sep.is_empty() {
        "•"
    } else {
        sep
    }
}

pub(super) fn m_link(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    format!("`!{}`!", m_link_raw(label, path, fields))
}

pub(super) fn m_link_raw(label: &str, path: &str, fields: &[(&str, &str)]) -> String {
    let mut out = String::from("`[");
    out.push_str(&sanitize_label(label));
    out.push_str("`:");
    out.push_str(path);
    if !fields.is_empty() {
        out.push('`');
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push('|');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(&sanitize_field(value));
        }
    }
    out.push(']');
    out
}

pub(super) fn markdown_blob_url_scope(
    group: &str,
    repo: &str,
    reference: &str,
    current_path: &str,
) -> String {
    let directory = current_path
        .rsplit_once('/')
        .map(|(directory, _)| format!("{directory}/"))
        .unwrap_or_default();
    let mut out = format!(":{PATH_BLOB}`");
    for (index, (key, value)) in [
        ("g", group),
        ("r", repo),
        ("ref", reference),
        ("path", directory.as_str()),
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            out.push('|');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&sanitize_field(value));
    }
    out
}

pub(super) fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '[' && *ch != ']' && *ch != '`')
        .collect()
}

pub(super) fn sanitize_field(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub(super) fn m_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('\t', "   ")
}

pub(super) fn m_escape_line_start_controls(value: &str) -> String {
    let escaped = m_escape(value);
    if value.starts_with('-') || value.starts_with('>') || value.starts_with('<') {
        format!("\\{escaped}")
    } else {
        escaped
    }
}

pub(super) fn format_commit_message(value: &str) -> String {
    value
        .split('\n')
        .map(|line| {
            let escaped = m_escape(line);
            if line.starts_with('-') {
                format!("\\{escaped}")
            } else {
                escaped
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn join_git_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

pub(super) fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(super) fn format_unix_time(timestamp: i64) -> String {
    timestamp.to_string()
}
