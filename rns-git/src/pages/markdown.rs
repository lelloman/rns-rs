//! Rendering Markdown as micron.

use super::*;

pub(super) fn markdown_to_micron(input: &str) -> String {
    markdown_to_micron_scoped(input, None)
}

pub(super) fn markdown_to_micron_scoped(input: &str, url_scope: Option<&str>) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut out = String::new();
    let mut code_block: Option<(Option<String>, String)> = None;
    let mut index = 0;

    while let Some(&line) = lines.get(index) {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if let Some((language, content)) = code_block.take() {
                out.push_str(&markdown_code_block_to_micron(
                    language.as_deref(),
                    &content,
                ));
            } else {
                code_block = Some((markdown_fence_language(trimmed), String::new()));
            }
            index += 1;
            continue;
        }
        if let Some((_, content)) = code_block.as_mut() {
            content.push_str(line);
            content.push('\n');
            index += 1;
            continue;
        }
        if let Some(quote) = markdown_quote(line) {
            let mut parts = vec![quote.to_string()];
            index += 1;
            while let Some(quote) = lines.get(index).and_then(|line| markdown_quote(line)) {
                parts.push(quote.to_string());
                index += 1;
            }
            let formatted = format_markdown_inline_scoped(&parts.join(" "), url_scope);
            for wrapped in markdown_wrap_text(&formatted, 77) {
                out.push_str(" │ ");
                out.push_str(&wrapped);
                out.push('\n');
            }
            continue;
        }
        if is_table_start(&lines, index) {
            let mut table = Vec::new();
            while let Some(&line) = lines.get(index).filter(|line| line.contains('|')) {
                table.push(line);
                index += 1;
            }
            out.push_str(&format_markdown_table(&table, url_scope));
            continue;
        }
        if let Some((level, text)) = markdown_heading(line) {
            out.push_str(&">".repeat(level));
            out.push_str(&format_markdown_inline_scoped(text.trim(), url_scope));
            out.push('\n');
        } else if is_markdown_rule(trimmed) {
            out.push_str("-\n");
        } else if let Some((indent, text)) = unordered_list_item(line) {
            out.push_str(indent);
            out.push_str(" • ");
            out.push_str(&format_markdown_inline_scoped(text, url_scope));
            out.push('\n');
        } else if let Some((indent, number, text)) = ordered_list_item(line) {
            out.push_str(indent);
            out.push_str(number);
            out.push_str(". ");
            out.push_str(&format_markdown_inline_scoped(text, url_scope));
            out.push('\n');
        } else {
            out.push_str(&format_markdown_line(line, url_scope));
            out.push('\n');
        }
        index += 1;
    }
    if let Some((language, content)) = code_block {
        out.push_str(&markdown_code_block_to_micron(
            language.as_deref(),
            &content,
        ));
    }

    out
}

pub(super) fn markdown_code_block_to_micron(language: Option<&str>, content: &str) -> String {
    if language.is_some_and(|language| language.eq_ignore_ascii_case("rawmu")) {
        return content.to_string();
    }
    crate::highlight::literal_block(content, None, language)
}

pub(super) fn markdown_fence_language(trimmed: &str) -> Option<String> {
    trimmed
        .strip_prefix("```")
        .and_then(|info| info.split_whitespace().next())
        .filter(|language| !language.is_empty())
        .map(str::to_string)
}

pub(super) fn markdown_quote(line: &str) -> Option<&str> {
    line.strip_prefix('>')
        .map(|quote| quote.strip_prefix(' ').unwrap_or(quote))
}

pub(super) fn markdown_heading(line: &str) -> Option<(usize, &str)> {
    let level = line.chars().take_while(|ch| *ch == '#').count();
    if (1..=6).contains(&level) && line.as_bytes().get(level) == Some(&b' ') {
        Some((level, &line[level + 1..]))
    } else {
        None
    }
}

pub(super) fn is_markdown_rule(trimmed: &str) -> bool {
    trimmed.len() >= 3
        && ["-", "*", "_", "="]
            .iter()
            .any(|marker| trimmed.chars().all(|ch| ch.to_string() == *marker))
}

pub(super) fn unordered_list_item(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    for marker in ["- ", "* ", "+ "] {
        if let Some(text) = trimmed.strip_prefix(marker) {
            return Some((indent, text));
        }
    }
    None
}

pub(super) fn ordered_list_item(line: &str) -> Option<(&str, &str, &str)> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let (number, text) = trimmed.split_once(". ")?;
    if !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit()) {
        Some((indent, number, text))
    } else {
        None
    }
}

pub(super) fn format_markdown_line(line: &str, url_scope: Option<&str>) -> String {
    let formatted = format_markdown_inline_scoped(line, url_scope);
    if (line.starts_with('-') && !line.starts_with("---") && !line.starts_with("- "))
        || line.starts_with('<')
    {
        format!("\\{formatted}")
    } else {
        formatted
    }
}

pub(super) fn is_table_start(lines: &[&str], index: usize) -> bool {
    match lines.get(index..) {
        Some([line, next, ..]) => {
            line.contains('|') && next.contains('|') && is_table_separator(next)
        }
        _ => false,
    }
}

pub(super) fn is_table_separator(line: &str) -> bool {
    parse_table_row(line)
        .iter()
        .all(|cell| !cell.is_empty() && cell.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
}

#[derive(Clone, Copy)]
pub(super) enum TableAlign {
    Left,
    Right,
    Center,
}

pub(super) fn format_markdown_table(lines: &[&str], url_scope: Option<&str>) -> String {
    let [header_line, alignment_line, ..] = lines else {
        return String::new();
    };
    let header: Vec<String> = parse_table_row(header_line)
        .into_iter()
        .map(|cell| format_markdown_inline_scoped(cell.trim(), url_scope))
        .collect();
    if header.is_empty() {
        return String::new();
    }
    let columns = header.len();
    let mut alignments = parse_table_alignments(alignment_line);
    while alignments.len() < columns {
        alignments.push(TableAlign::Left);
    }
    alignments.truncate(columns);

    let rows: Vec<Vec<String>> = lines
        .iter()
        .skip(2)
        .map(|line| {
            let mut row: Vec<String> = parse_table_row(line)
                .into_iter()
                .map(|cell| format_markdown_inline_scoped(cell.trim(), url_scope))
                .collect();
            while row.len() < columns {
                row.push(String::new());
            }
            row.truncate(columns);
            row
        })
        .collect();

    let mut widths = vec![3; columns];
    for row in std::iter::once(&header).chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(markdown_visible_width(cell));
        }
    }

    let mut out = String::new();
    out.push_str(&table_border('┌', '┬', '┐', &widths));
    out.push_str(&table_row(
        &header,
        &widths,
        &vec![TableAlign::Left; columns],
    ));
    out.push_str(&table_border('├', '┼', '┤', &widths));
    for row in rows {
        out.push_str(&table_row(&row, &widths, &alignments));
    }
    out.push_str(&table_border('└', '┴', '┘', &widths));
    out
}

pub(super) fn parse_table_row(line: &str) -> Vec<String> {
    let mut trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix('|') {
        trimmed = rest;
    }
    if let Some(rest) = trimmed.strip_suffix('|') {
        trimmed = rest;
    }
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in trimmed.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            cells.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    cells.push(current.trim().to_string());
    cells
}

pub(super) fn parse_table_alignments(line: &str) -> Vec<TableAlign> {
    parse_table_row(line)
        .into_iter()
        .map(|cell| {
            let cell = cell.trim();
            if cell.starts_with(':') && cell.ends_with(':') {
                TableAlign::Center
            } else if cell.ends_with(':') {
                TableAlign::Right
            } else {
                TableAlign::Left
            }
        })
        .collect()
}

pub(super) fn table_border(left: char, middle: char, right: char, widths: &[usize]) -> String {
    let mut out = String::new();
    out.push(left);
    for (index, width) in widths.iter().enumerate() {
        out.push_str(&"─".repeat(width + 2));
        if index + 1 == widths.len() {
            out.push(right);
        } else {
            out.push(middle);
        }
    }
    out.push('\n');
    out
}

pub(super) fn table_row(cells: &[String], widths: &[usize], alignments: &[TableAlign]) -> String {
    let mut out = String::from("│");
    for (index, width) in widths.iter().enumerate() {
        let cell = cells.get(index).map(String::as_str).unwrap_or("");
        out.push(' ');
        out.push_str(&pad_table_cell(
            cell,
            *width,
            alignments.get(index).copied().unwrap_or(TableAlign::Left),
        ));
        out.push(' ');
        out.push('│');
    }
    out.push('\n');
    out
}

pub(super) fn pad_table_cell(cell: &str, width: usize, alignment: TableAlign) -> String {
    let visible = markdown_visible_width(cell);
    let padding = width.saturating_sub(visible);
    match alignment {
        TableAlign::Left => format!("{cell}{}", " ".repeat(padding)),
        TableAlign::Right => format!("{}{cell}", " ".repeat(padding)),
        TableAlign::Center => {
            let left = padding / 2;
            let right = padding - left;
            format!("{}{cell}{}", " ".repeat(left), " ".repeat(right))
        }
    }
}

pub(super) fn markdown_visible_width(value: &str) -> usize {
    let mut width = 0;
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '`' {
            if matches!(chars.peek(), Some('F') | Some('B')) {
                chars.next();
                if matches!(chars.peek(), Some('T')) {
                    chars.next();
                    for _ in 0..6 {
                        chars.next();
                    }
                } else {
                    for _ in 0..3 {
                        chars.next();
                    }
                }
                continue;
            }
            if matches!(chars.peek(), Some('!') | Some('*') | Some('_') | Some('=')) {
                chars.next();
                continue;
            }
            if matches!(chars.peek(), Some('f') | Some('b') | Some('a')) {
                chars.next();
                continue;
            }
            if matches!(chars.peek(), Some('[')) {
                let mut label_width = 0;
                for link_ch in chars.by_ref() {
                    if link_ch == '`' {
                        for target_ch in chars.by_ref() {
                            if target_ch == ']' {
                                break;
                            }
                        }
                        break;
                    }
                    label_width += 1;
                }
                width += label_width;
                continue;
            }
        }
        width += 1;
    }
    width
}

pub(super) fn markdown_wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;
    for word in text.split_whitespace() {
        let word_width = markdown_visible_width(word);
        if !current.is_empty() && current_width + 1 + word_width > width {
            lines.push(current);
            current = String::new();
            current_width = 0;
        }
        if !current.is_empty() {
            current.push(' ');
            current_width += 1;
        }
        current.push_str(word);
        current_width += word_width;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[derive(Debug)]
pub(super) enum InlineToken {
    Link { label: String, target: String },
    Code(String),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MarkdownLinkStyle<'a> {
    pub(super) bold: bool,
    pub(super) underline: bool,
    pub(super) color: Option<&'a str>,
}

impl Default for MarkdownLinkStyle<'_> {
    fn default() -> Self {
        Self {
            bold: true,
            underline: true,
            color: None,
        }
    }
}

pub(super) fn format_markdown_inline_scoped(input: &str, url_scope: Option<&str>) -> String {
    let (with_placeholders, tokens) = extract_markdown_inline_tokens(input);
    let escaped = m_escape(&with_placeholders);
    let styled = apply_markdown_style(&escaped, "**", "`!", "`!");
    let styled = apply_markdown_style(&styled, "__", "`!", "`!");
    let styled = apply_markdown_style(&styled, "*", "`*", "`*");
    let styled = apply_markdown_style(&styled, "_", "`*", "`*");
    restore_markdown_inline_tokens(&styled, &tokens, url_scope)
}

pub(super) fn extract_markdown_inline_tokens(input: &str) -> (String, Vec<InlineToken>) {
    let mut out = String::new();
    let mut tokens = Vec::new();
    let mut index = 0;

    while index < input.len() {
        let rest = &input[index..];
        if let Some(stripped) = rest.strip_prefix('`') {
            if let Some(end) = stripped.find('`') {
                let content = &stripped[..end];
                if is_markdown_inline_code(content) {
                    tokens.push(InlineToken::Code(content.to_string()));
                    out.push_str(&markdown_token_placeholder(tokens.len() - 1));
                    index += end + 2;
                    continue;
                }
            }
        }
        if rest.starts_with('[') {
            if let Some((consumed, label, target)) = parse_markdown_link(rest) {
                tokens.push(InlineToken::Link { label, target });
                out.push_str(&markdown_token_placeholder(tokens.len() - 1));
                index += consumed;
                continue;
            }
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        out.push(ch);
        index += ch.len_utf8();
    }

    (out, tokens)
}

pub(super) fn is_markdown_inline_code(content: &str) -> bool {
    !content.is_empty()
        && !content
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '!' | '*' | '_' | '=' | 'F' | 'B' | 'f' | 'b' | 'a'))
}

pub(super) fn parse_markdown_link(input: &str) -> Option<(usize, String, String)> {
    let label_end = input[1..].find(']')? + 1;
    if !input[label_end + 1..].starts_with('(') {
        return None;
    }
    let target_start = label_end + 2;
    let target_end = input[target_start..].find(')')? + target_start;
    Some((
        target_end + 1,
        input[1..label_end].replace('`', ""),
        input[target_start..target_end].to_string(),
    ))
}

pub(super) fn markdown_token_placeholder(index: usize) -> String {
    format!("\u{1f}{index}\u{1f}")
}

pub(super) fn restore_markdown_inline_tokens(
    input: &str,
    tokens: &[InlineToken],
    url_scope: Option<&str>,
) -> String {
    let mut out = input.to_string();
    for (index, token) in tokens.iter().enumerate() {
        let replacement = match token {
            InlineToken::Link { label, target } => {
                format_markdown_link(label, target, url_scope, MarkdownLinkStyle::default())
            }
            InlineToken::Code(value) => format!("`BT383838`Fddd{}`f`b", m_escape(value)),
        };
        out = out.replace(&markdown_token_placeholder(index), &replacement);
    }
    out
}

pub(super) fn format_markdown_link(
    label: &str,
    target: &str,
    url_scope: Option<&str>,
    style: MarkdownLinkStyle<'_>,
) -> String {
    let mut link = String::new();
    if style.underline {
        link.push_str("`_");
    }
    if style.bold {
        link.push_str("`!");
    }
    link.push_str("`[");
    link.push_str(sanitize_label(label).trim());
    link.push('`');
    link.push_str(&markdown_link_target(target, url_scope));
    link.push(']');
    if style.bold {
        link.push_str("`!");
    }
    if style.underline {
        link.push_str("`_");
    }

    match style.color {
        Some(color) if color.len() == 3 => format!("`F{color}{link}`f"),
        Some(color) if color.len() == 6 => format!("`FT{color}{link}`f"),
        _ => link,
    }
}

pub(super) fn markdown_link_target(value: &str, url_scope: Option<&str>) -> String {
    if let Some(scope) = url_scope {
        if !value.contains(":/") {
            let (path, anchor) = value
                .split_once('#')
                .map(|(path, anchor)| (path, Some(anchor)))
                .unwrap_or((value, None));
            let mut out = format!("{scope}{}", sanitize_field(path));
            if let Some(anchor) = anchor.filter(|anchor| !anchor.is_empty()) {
                out.push_str("|anchor=");
                out.push_str(&sanitize_field(anchor));
            }
            return out;
        }
    }
    sanitize_markdown_link_target(value)
}

pub(super) fn sanitize_markdown_link_target(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '[' && *ch != ']' && *ch != '`')
        .collect()
}

pub(super) fn apply_markdown_style(input: &str, marker: &str, open: &str, close: &str) -> String {
    let mut out = String::new();
    let mut rest = input;

    while let Some(start) = rest.find(marker) {
        let content_start = start + marker.len();
        let Some(end) = rest[content_start..].find(marker) else {
            out.push_str(rest);
            return out;
        };
        let content_end = content_start + end;
        out.push_str(&rest[..start]);
        out.push_str(open);
        out.push_str(&rest[content_start..content_end]);
        out.push_str(close);
        rest = &rest[content_end + marker.len()..];
    }
    out.push_str(rest);
    out
}
