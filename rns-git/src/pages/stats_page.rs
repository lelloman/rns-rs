//! The statistics page and its charts.

use super::*;

pub(super) fn render_stats_page(
    config: &ServerConfig,
    access: &Access,
    remote: Option<&[u8; 16]>,
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    let (group, repo, _repository) = accessible_repository(config, access, remote, vars)?;
    if !access.allows(Operation::Stats, &format!("{group}/{repo}"), remote)? {
        return Ok(">>\n>Error\n\nThe requested repository was not found.\n".to_string());
    }
    let Some(stats) = crate::stats::repository_stats(config, access, remote, &group, &repo, 90)?
    else {
        return Ok(
            ">>\n>Stats Unavailable\n\nCould not retrieve statistics for this repository.\n"
                .to_string(),
        );
    };

    let mut out = format!(
        ">>\n{} / {} / {} / stats\n\n>Stats for {}\n\n",
        m_link("Node", PATH_INDEX, &[]),
        m_link(&group, PATH_GROUP, &[("g", &group)]),
        m_link(&repo, PATH_REPO, &[("g", &group), ("r", &repo)]),
        m_escape(&stats.repository)
    );
    out.push_str(&format!(
        "`FT{RCLR_FETCH}Fetches`f   : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.fetches.total,
        stats.fetches.daily.last().copied().unwrap_or(0),
        stats.fetches.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_PUSH}Pushes`f    : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.pushes.total,
        stats.pushes.daily.last().copied().unwrap_or(0),
        stats.pushes.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_VIEW}Views`f     : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.views.total,
        stats.views.daily.last().copied().unwrap_or(0),
        stats.views.peak
    ));
    out.push_str(&format!(
        "`FT{RCLR_DOWNLOAD}Downloads`f : {:>5}  total `F666  today: {:>3}  peak: {:>3} `f\n",
        stats.downloads_combined.total,
        stats.downloads_combined.daily.last().copied().unwrap_or(0),
        stats.downloads_combined.peak
    ));
    out.push_str(&format!(
        "`F0aaActivity`f  : {:>5} points\n\n",
        stats.activity_score
    ));
    out.push_str(&format!(
        "{}{}`f over the last {} days ({})\n\n",
        stats.activity_level.color(),
        stats.activity_level.label(),
        stats.actual_days,
        stats.date_range
    ));

    if stats.fetches.total > 0 {
        out.push_str(">Fetches\n\n");
        out.push_str(&render_chart(
            &stats.fetches.daily,
            &stats.timeline_labels,
            RCLR_FETCH,
            Some(RCLR_FETCH_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.pushes.total > 0 {
        out.push_str(">Pushes\n\n");
        out.push_str(&render_chart(
            &stats.pushes.daily,
            &stats.timeline_labels,
            RCLR_PUSH,
            Some(RCLR_PUSH_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.views.total > 0 {
        out.push_str(">Views\n\n");
        out.push_str(&render_chart(
            &stats.views.daily,
            &stats.timeline_labels,
            RCLR_VIEW,
            Some(RCLR_VIEW_G),
            1.3,
            10,
        ));
        out.push('\n');
    }
    if stats.downloads_combined.total > 0 {
        out.push_str(">Downloads\n\n");
        out.push_str(&render_chart(
            &stats.downloads_combined.daily,
            &stats.timeline_labels,
            RCLR_DOWNLOAD,
            Some(RCLR_DOWNLOAD_G),
            1.7,
            10,
        ));
        out.push('\n');
    }
    if stats.activity_score > 0 {
        out.push_str(">Combined Activity\n\n");
        out.push_str(&render_combined_chart(
            &stats.views.daily,
            &stats.fetches.daily,
            &stats.pushes.daily,
            &stats.downloads_combined.daily,
            &stats.timeline_labels,
            6,
        ));
    } else {
        out.push_str(
            "`*\nNo development activity recorded for this repository in the selected time period.\n\n`*",
        );
    }
    Ok(out)
}

pub(super) fn render_chart(
    data: &[u64],
    labels: &[String; 2],
    color: &str,
    secondary_color: Option<&str>,
    gradient_factor: f64,
    height: u64,
) -> String {
    if data.is_empty() || data.iter().all(|value| *value == 0) {
        return "No data available\n".to_string();
    }
    let max = data.iter().copied().max().unwrap_or(1).max(1) as f64;
    let primary = expand_chart_color(color);
    let secondary = secondary_color
        .map(expand_chart_color)
        .unwrap_or_else(|| dim_chart_color(&primary));
    let mut out = format!("`FT{primary}Peak: {}`f\n", max as u64);
    for row in (1..=height).rev() {
        let row_top = row as f64 / height as f64 * max;
        let row_mid = (row as f64 - 0.5) / height as f64 * max;
        let grad_top = row as f64 / height as f64;
        let grad_mid = (row as f64 - 0.5) / height as f64;
        let top_color = gradient_chart_color(&primary, &secondary, grad_top, gradient_factor);
        let mid_color = gradient_chart_color(&primary, &secondary, grad_mid, gradient_factor);
        out.push('│');
        for value in data {
            let value = *value as f64;
            if value >= row_top {
                out.push_str(&format!("`FT{top_color}`BT{mid_color}▀`f`b"));
            } else if value >= row_mid || (row == 1 && value > 0.0) {
                out.push_str(&format!("`FT{mid_color}▄`f"));
            } else {
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out.push('└');
    for _ in data {
        out.push('─');
    }
    out.push_str("┘\n");
    out.push_str(&format!("`F666{:<12}`f", labels[0]));
    let chart_width = data.len() + 2;
    let spacing = chart_width.saturating_sub(24);
    out.push_str(&" ".repeat(spacing));
    out.push_str(&format!("`F666{:>12}`f\n", labels[1]));
    out
}

pub(super) fn expand_chart_color(color: &str) -> String {
    let color = color.trim_start_matches('#');
    if color.len() == 3 {
        color.chars().flat_map(|ch| [ch, ch]).collect()
    } else {
        color.chars().take(6).collect()
    }
}

pub(super) fn dim_chart_color(primary: &str) -> String {
    let rgb = chart_rgb(primary);
    format!(
        "{:02x}{:02x}{:02x}",
        (rgb[0] as f64 * 0.42) as u8,
        (rgb[1] as f64 * 0.42) as u8,
        (rgb[2] as f64 * 0.42) as u8
    )
}

pub(super) fn gradient_chart_color(primary: &str, secondary: &str, t: f64, factor: f64) -> String {
    let primary = chart_rgb(primary);
    let secondary = chart_rgb(secondary);
    let t = (t * factor).min(1.0);
    format!(
        "{:02x}{:02x}{:02x}",
        (secondary[0] as f64 + (primary[0] as f64 - secondary[0] as f64) * t) as u8,
        (secondary[1] as f64 + (primary[1] as f64 - secondary[1] as f64) * t) as u8,
        (secondary[2] as f64 + (primary[2] as f64 - secondary[2] as f64) * t) as u8
    )
}

pub(super) fn chart_rgb(color: &str) -> [u8; 3] {
    let color = expand_chart_color(color);
    [
        u8::from_str_radix(color.get(0..2).unwrap_or("00"), 16).unwrap_or(0),
        u8::from_str_radix(color.get(2..4).unwrap_or("00"), 16).unwrap_or(0),
        u8::from_str_radix(color.get(4..6).unwrap_or("00"), 16).unwrap_or(0),
    ]
}

pub(super) fn render_combined_chart(
    views: &[u64],
    fetches: &[u64],
    pushes: &[u64],
    downloads: &[u64],
    labels: &[String; 2],
    height: u64,
) -> String {
    if views.is_empty() || fetches.is_empty() || pushes.is_empty() || downloads.is_empty() {
        return "No data available\n".to_string();
    }

    let categories = [
        ("Pushes", dim_to_black(RCLR_PUSH, 0.87), pushes),
        ("Fetches", dim_to_black(RCLR_FETCH, 0.87), fetches),
        ("Views", dim_to_black(RCLR_VIEW, 0.87), views),
        ("Downloads", dim_to_black(RCLR_DOWNLOAD, 0.87), downloads),
    ];
    let mut out = categories
        .iter()
        .map(|(label, color, _)| format!("`FT{color}`BT{color}██`f`b {label}"))
        .collect::<Vec<_>>()
        .join("  ");
    out.push_str("\n\n");
    let num_points = views.len();

    for row in (1..=height).rev() {
        let lower_min = (row as f64 - 1.0) / height as f64;
        let lower_max = (row as f64 - 0.5) / height as f64;
        let upper_min = (row as f64 - 0.5) / height as f64;
        let upper_max = row as f64 / height as f64;
        out.push('│');
        for index in 0..num_points {
            let total: u64 = categories
                .iter()
                .map(|(_, _, data)| data.get(index).copied().unwrap_or(0))
                .sum();
            if total == 0 {
                out.push(' ');
                continue;
            }

            // A category index and its color.
            let category = |pixel_min, pixel_max| {
                let found =
                    stacked_pixel_category(&categories, index, total, pixel_min, pixel_max)?;
                Some((found, &categories.get(found)?.1))
            };
            match (
                category(upper_min, upper_max),
                category(lower_min, lower_max),
            ) {
                (Some((upper, color)), Some((lower, _))) if upper == lower => {
                    out.push_str(&format!("`FT{color}`BT{color}█`f`b"));
                }
                (Some((_, upper_color)), Some((_, lower_color))) => {
                    out.push_str(&format!("`FT{upper_color}`BT{lower_color}▀`f`b"));
                }
                (Some((_, color)), None) => {
                    out.push_str(&format!("`FT{color}▀`f"));
                }
                (None, Some((_, color))) => {
                    out.push_str(&format!("`FT{color}▄`f"));
                }
                (None, None) => out.push(' '),
            }
        }
        out.push('\n');
    }
    out.push('└');
    for _ in 0..num_points {
        out.push('─');
    }
    out.push_str("┘\n");
    out.push_str(&format!(
        "`F666{:<12}`f",
        labels[0].chars().take(12).collect::<String>()
    ));
    let chart_width = num_points + 2;
    let spacing = chart_width.saturating_sub(24);
    out.push_str(&" ".repeat(spacing));
    out.push_str(&format!(
        "`F666{:>12}`f\n",
        labels[1].chars().take(12).collect::<String>()
    ));
    out
}

pub(super) fn stacked_pixel_category(
    categories: &[(&str, String, &[u64])],
    index: usize,
    total: u64,
    pixel_min: f64,
    pixel_max: f64,
) -> Option<usize> {
    let mut cumulative = 0u64;
    for (category_index, (_, _, data)) in categories.iter().enumerate() {
        let value = data.get(index).copied().unwrap_or(0);
        if value == 0 {
            continue;
        }
        let start = cumulative as f64 / total as f64;
        cumulative += value;
        let end = cumulative as f64 / total as f64;
        if pixel_min < end && pixel_max > start {
            return Some(category_index);
        }
    }
    None
}

pub(super) fn dim_to_black(color: &str, dim: f64) -> String {
    gradient_chart_color(&expand_chart_color(color), "000000", dim, 1.0)
}
