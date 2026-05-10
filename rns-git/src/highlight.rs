#[cfg(feature = "syntax-highlighting")]
use std::path::Path;
#[cfg(feature = "syntax-highlighting")]
use std::sync::OnceLock;

#[cfg(feature = "syntax-highlighting")]
use syntect::easy::HighlightLines;
#[cfg(feature = "syntax-highlighting")]
use syntect::highlighting::{Style, Theme, ThemeSet};
#[cfg(feature = "syntax-highlighting")]
use syntect::parsing::{SyntaxReference, SyntaxSet};
#[cfg(feature = "syntax-highlighting")]
use syntect::util::LinesWithEndings;

pub(crate) fn literal_block(content: &str, path: Option<&str>, language: Option<&str>) -> String {
    let body =
        highlighted_content(content, path, language).unwrap_or_else(|| escape_micron(content));
    block_from_body(&body)
}

pub(crate) fn plain_literal_block(content: &str) -> String {
    block_from_body(&escape_micron(content))
}

fn block_from_body(body: &str) -> String {
    let mut out = String::from("`=\n");
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("`=\n");
    out
}

fn escape_micron(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('\t', "   ")
}

#[cfg(not(feature = "syntax-highlighting"))]
fn highlighted_content(
    _content: &str,
    _path: Option<&str>,
    _language: Option<&str>,
) -> Option<String> {
    None
}

#[cfg(feature = "syntax-highlighting")]
fn highlighted_content(
    content: &str,
    path: Option<&str>,
    language: Option<&str>,
) -> Option<String> {
    let syntax_set = syntax_set();
    let syntax = syntax_for(syntax_set, path, language)?;
    let theme = theme()?;
    let mut highlighter = HighlightLines::new(syntax, theme);
    let mut out = String::new();

    for line in LinesWithEndings::from(content) {
        let ranges = highlighter.highlight_line(line, syntax_set).ok()?;
        for (style, text) in ranges {
            push_colored_span(&mut out, style, text);
        }
    }

    Some(escape_line_start_controls(&out))
}

#[cfg(feature = "syntax-highlighting")]
fn syntax_set() -> &'static SyntaxSet {
    static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
    SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines)
}

#[cfg(feature = "syntax-highlighting")]
fn theme_set() -> &'static ThemeSet {
    static THEME_SET: OnceLock<ThemeSet> = OnceLock::new();
    THEME_SET.get_or_init(ThemeSet::load_defaults)
}

#[cfg(feature = "syntax-highlighting")]
fn theme() -> Option<&'static Theme> {
    theme_set().themes.get("base16-ocean.dark")
}

#[cfg(feature = "syntax-highlighting")]
fn syntax_for<'a>(
    syntax_set: &'a SyntaxSet,
    path: Option<&str>,
    language: Option<&str>,
) -> Option<&'a SyntaxReference> {
    if let Some(language) = language.and_then(normalize_language) {
        if let Some(syntax) = syntax_set.find_syntax_by_token(language) {
            return Some(syntax);
        }
    }

    let extension = path
        .and_then(|path| Path::new(path).extension())
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())?;
    syntax_set.find_syntax_by_extension(extension)
}

#[cfg(feature = "syntax-highlighting")]
fn normalize_language(language: &str) -> Option<&str> {
    let language = language.trim();
    if language.is_empty() {
        None
    } else {
        Some(language)
    }
}

#[cfg(feature = "syntax-highlighting")]
fn push_colored_span(out: &mut String, style: Style, text: &str) {
    let mut escaped = escape_micron(text);
    while escaped.starts_with('\n') {
        out.push('\n');
        escaped.remove(0);
    }
    let mut trailing_newlines = 0;
    while escaped.ends_with('\n') {
        escaped.pop();
        trailing_newlines += 1;
    }
    if escaped.is_empty() {
        for _ in 0..trailing_newlines {
            out.push('\n');
        }
        return;
    }
    out.push_str(&format!(
        "`FT{:02x}{:02x}{:02x}",
        style.foreground.r, style.foreground.g, style.foreground.b
    ));
    out.push_str(&escaped);
    out.push_str("`f");
    for _ in 0..trailing_newlines {
        out.push('\n');
    }
}

#[cfg(feature = "syntax-highlighting")]
fn escape_line_start_controls(value: &str) -> String {
    let mut out = String::new();
    for segment in value.split_inclusive('\n') {
        let (line, newline) = segment
            .strip_suffix('\n')
            .map(|line| (line, "\n"))
            .unwrap_or((segment, ""));
        if line.starts_with('-') || line.starts_with('>') || line.starts_with('<') {
            out.push('\\');
        }
        out.push_str(line);
        out.push_str(newline);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_literal_blocks_escape_backslashes_ticks_and_expand_tabs() {
        let out = plain_literal_block("path\\name\t`tick`\n");

        assert!(out.contains("path\\\\name   \\`tick\\`"));
    }

    #[test]
    fn literal_block_fallback_escape_backslashes_ticks_and_expand_tabs() {
        let out = literal_block("path\\name\t`tick`\n", Some("blob.unknown"), None);

        assert!(!out.contains("`FT"));
        assert!(out.contains("path\\\\name   \\`tick\\`"));
    }

    #[cfg(feature = "syntax-highlighting")]
    #[test]
    fn highlighted_literal_blocks_keep_newlines_outside_color_tags_and_escape_headings() {
        let out = literal_block(">not a heading\nlet value = 1;\n", Some("main.rs"), None);
        assert!(!out.contains("`f\n`f"));
        assert!(out.ends_with("`=\n"));
    }

    #[cfg(feature = "syntax-highlighting")]
    #[test]
    fn highlighted_line_start_micron_controls_are_escaped() {
        let escaped = escape_line_start_controls("-dash\n>heading\n<align\nplain\n");
        assert_eq!(escaped, "\\-dash\n\\>heading\n\\<align\nplain\n");
    }
}
