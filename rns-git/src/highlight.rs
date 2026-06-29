pub(crate) fn literal_block(content: &str, _path: Option<&str>, _language: Option<&str>) -> String {
    plain_literal_block(content)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_literal_blocks_escape_backslashes_ticks_and_expand_tabs() {
        let out = plain_literal_block("path\\name\t`tick`\n");

        assert!(out.contains("path\\\\name   \\`tick\\`"));
    }

    #[test]
    fn literal_blocks_escape_backslashes_ticks_and_expand_tabs() {
        let out = literal_block("path\\name\t`tick`\n", Some("main.rs"), Some("rust"));

        assert!(!out.contains("`FT"));
        assert!(out.contains("path\\\\name   \\`tick\\`"));
    }
}
