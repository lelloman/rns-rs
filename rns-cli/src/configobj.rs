//! The part of upstream's vendored ConfigObj and Validator that `rnid -E`
//! uses to read signed-message metadata: an ordered parse of `key = value`
//! lines and `[section]`s, with ConfigObj's lists, quoting and comments,
//! and the common Validator checks of a spec file.

/// A ConfigObj value, as `ConfigObj.dict()` returns it.
#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    /// A string scalar.
    Str(String),
    /// A comma-separated list.
    List(Vec<Entry>),
    /// An integer, after validation against an `integer` check.
    Int(i64),
    /// A float, after validation against a `float` check.
    Float(f64),
    /// A boolean, after validation against a `boolean` check.
    Bool(bool),
    /// A `[section]`.
    Section(Section),
}

/// A section: its scalars first, then its subsections, as ConfigObj
/// iterates them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Section {
    /// The `key = value` entries, in file order.
    pub scalars: Vec<(String, Entry)>,
    /// The subsections, in file order.
    pub sections: Vec<(String, Section)>,
}

impl Section {
    fn contains(&self, key: &str) -> bool {
        self.scalars.iter().any(|(k, _)| k == key) || self.sections.iter().any(|(k, _)| k == key)
    }

    fn section_mut(&mut self, path: &[usize]) -> &mut Section {
        let mut section = self;
        for &i in path {
            section = &mut section.sections[i].1;
        }
        section
    }

    /// `dict()`: scalars, then sections.
    pub fn entries(&self) -> Vec<(String, Entry)> {
        let mut out = self.scalars.clone();
        out.extend(
            self.sections
                .iter()
                .map(|(k, s)| (k.clone(), Entry::Section(s.clone()))),
        );
        out
    }
}

fn is_space(c: char) -> bool {
    c.is_whitespace()
}

/// `_unquote`.
fn unquote(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '"' || chars[0] == '\'')
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        value.to_string()
    }
}

/// `_sectionmarker`: (depth open, name, depth close) of a section line.
fn section_marker(line: &str) -> Option<(usize, String, usize)> {
    let rest = line.trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    let mut open = 0;
    let mut chars = rest.char_indices().peekable();
    let mut name_start = rest.len();
    while let Some(&(i, c)) = chars.peek() {
        if c == '[' {
            open += 1;
            chars.next();
        } else if is_space(c) {
            chars.next();
        } else {
            name_start = i;
            break;
        }
    }
    let after = &rest[name_start..];
    // Strip an optional comment and the closing brackets from the end.
    let without_comment = match after.find('#') {
        Some(at) if !after.starts_with('"') && !after.starts_with('\'') => &after[..at],
        _ => after,
    };
    let trimmed = without_comment.trim_end();
    let mut close = 0;
    let mut end = trimmed.len();
    for (i, c) in trimmed.char_indices().rev() {
        if c == ']' {
            close += 1;
            end = i;
        } else if is_space(c) && close > 0 {
            end = i;
        } else {
            break;
        }
    }
    if close == 0 {
        return None;
    }
    let name = trimmed[..end].trim_end();
    if name.is_empty() {
        return None;
    }
    Some((open, unquote(name), close))
}

/// `_keyword`: (key, value) of a `key = value` line.
fn keyword(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start();
    let first = rest.chars().next()?;
    let value_after = |eq: usize| rest[eq + 1..].trim_start().to_string();
    if first == '"' || first == '\'' {
        // The shortest quoted key followed by `\s*=`.
        for (i, c) in rest.char_indices().skip(1) {
            if c == first {
                let tail = rest[i + 1..].trim_start();
                if let Some(stripped) = tail.strip_prefix('=') {
                    let eq = rest.len() - stripped.len() - 1;
                    return Some((unquote(&rest[..=i]), value_after(eq)));
                }
            }
        }
        return None;
    }
    if first == '=' {
        return None;
    }
    let eq = rest.find('=')?;
    Some((unquote(rest[..eq].trim_end()), value_after(eq)))
}

/// `_handle_value`: the value, unquoted, as a string or a list.
fn handle_value(value: &str) -> Result<Entry, ()> {
    if value.starts_with("\"\"\"") || value.starts_with("'''") {
        let quote = &value[..3];
        let rest = &value[3..];
        let end = rest.find(quote).ok_or(())?;
        let tail = rest[end + 3..].trim_start();
        if !(tail.is_empty() || tail.starts_with('#')) {
            return Err(());
        }
        return Ok(Entry::Str(rest[..end].to_string()));
    }
    let chars: Vec<char> = value.chars().collect();
    let mut items = Vec::new();
    let mut i = 0;
    let skip_space = |i: &mut usize| {
        while *i < chars.len() && is_space(chars[*i]) {
            *i += 1;
        }
    };
    // A lone comma: the empty list.
    {
        let mut j = 0;
        if chars.first() == Some(&',') {
            j += 1;
            skip_space(&mut j);
            if j == chars.len() || chars[j] == '#' {
                return Ok(Entry::List(Vec::new()));
            }
        }
    }
    let mut commas = 0;
    let mut last: Option<String> = None;
    loop {
        if i >= chars.len() || chars[i] == '#' {
            break;
        }
        let item: String;
        let c = chars[i];
        if c == '"' || c == '\'' {
            // The shortest quoted item the rest of the value still follows
            // (a comma, a comment or the end), as the regex backtracks.
            let follows = |at: usize| {
                let mut j = at;
                while j < chars.len() && is_space(chars[j]) {
                    j += 1;
                }
                j == chars.len() || chars[j] == ',' || chars[j] == '#'
            };
            let close = (i + 1..chars.len())
                .find(|&j| chars[j] == c && follows(j + 1))
                .ok_or(())?;
            item = chars[i..=close].iter().collect();
            i = close + 1;
        } else if c == ',' {
            return Err(());
        } else {
            let start = i;
            while i < chars.len() && chars[i] != ',' && chars[i] != '#' {
                i += 1;
            }
            item = chars[start..i]
                .iter()
                .collect::<String>()
                .trim_end()
                .to_string();
        }
        skip_space(&mut i);
        if i < chars.len() && chars[i] == ',' {
            commas += 1;
            items.push(unquote(&item));
            i += 1;
            skip_space(&mut i);
            continue;
        }
        if i < chars.len() && chars[i] != '#' {
            return Err(());
        }
        last = Some(item);
        break;
    }
    if commas == 0 {
        return Ok(Entry::Str(unquote(&last.unwrap_or_default())));
    }
    if let Some(last) = last.filter(|l| !l.is_empty()) {
        items.push(unquote(&last));
    }
    Ok(Entry::List(items.into_iter().map(Entry::Str).collect()))
}

/// `ConfigObj(lines)`, or the message of the `ConfigObjError` it raises.
pub fn parse(text: &str) -> Result<Section, String> {
    let mut root = Section::default();
    // The path to the current section and its depth.
    let mut path: Vec<usize> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let sline = line.trim();
        if sline.is_empty() || sline.starts_with('#') {
            continue;
        }
        if let Some((open, name, close)) = section_marker(line) {
            if open != close {
                errors.push(format!(
                    "Cannot compute the section depth at line {number}."
                ));
                continue;
            }
            let depth = path.len();
            let parent_len = if open <= depth {
                open - 1
            } else if open == depth + 1 {
                depth
            } else {
                errors.push(format!("Section too nested at line {number}."));
                continue;
            };
            if open == 0 {
                errors.push(format!("Cannot compute nesting level at line {number}."));
                continue;
            }
            path.truncate(parent_len);
            let parent = root.section_mut(&path);
            if parent.contains(&name) {
                errors.push(format!("Duplicate section name at line {number}."));
                continue;
            }
            parent.sections.push((name, Section::default()));
            path.push(parent.sections.len() - 1);
            continue;
        }
        let Some((key, raw)) = keyword(line) else {
            errors.push(format!(
                "Invalid line ({}) (matched as neither section nor keyword) at line {number}.",
                crate::argparse::repr(line)
            ));
            continue;
        };
        let Ok(value) = handle_value(&raw) else {
            errors.push(format!("Parse error in value at line {number}."));
            continue;
        };
        let section = root.section_mut(&path);
        if section.contains(&key) {
            errors.push(format!("Duplicate keyword name at line {number}."));
            continue;
        }
        section.scalars.push((key, value));
    }
    match errors.len() {
        0 => Ok(root),
        1 => Err(errors.remove(0)),
        _ => Err(format!(
            "Parsing failed with several errors.\nFirst error {}",
            errors[0]
                .rsplit_once(" at line ")
                .map(|(_, l)| format!("at line {l}"))
                .unwrap_or_default()
        )),
    }
}

/// A Validator check: its name, positional and keyword arguments.
struct Check {
    name: String,
    args: Vec<String>,
    kwargs: Vec<(String, String)>,
}

fn parse_check(check: &str) -> Check {
    let check = check.trim();
    let Some(open) = check.find('(') else {
        return Check {
            name: check.to_string(),
            args: Vec::new(),
            kwargs: Vec::new(),
        };
    };
    let name = check[..open].trim().to_string();
    let inner = check[open + 1..].trim_end().trim_end_matches(')');
    let mut args = Vec::new();
    let mut kwargs = Vec::new();
    for part in inner.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some((k, v)) => kwargs.push((k.trim().to_string(), unquote(v.trim()))),
            None => args.push(unquote(part)),
        }
    }
    Check { name, args, kwargs }
}

impl Check {
    fn kw(&self, key: &str) -> Option<&str> {
        self.kwargs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn to_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn in_range(value: f64, check: &Check) -> bool {
    let bound = |key: &str| check.kw(key).and_then(|v| v.parse::<f64>().ok());
    bound("min").is_none_or(|min| value >= min) && bound("max").is_none_or(|max| value <= max)
}

/// `Validator.check`: the converted value, or `None` when it fails.
fn check_value(check: &Check, value: &Entry) -> Option<Entry> {
    let scalar = |v: &Entry| match v {
        Entry::Str(s) => Some(s.clone()),
        _ => None,
    };
    match check.name.as_str() {
        "pass" | "" => Some(value.clone()),
        "string" => {
            let s = scalar(value)?;
            in_range(s.chars().count() as f64, check).then_some(Entry::Str(s))
        }
        "integer" => {
            let n: i64 = crate::argparse::python_int(&scalar(value)?)?;
            in_range(n as f64, check).then_some(Entry::Int(n))
        }
        "float" => {
            let f = crate::argparse::python_float(&scalar(value)?)?;
            in_range(f, check).then_some(Entry::Float(f))
        }
        "boolean" => to_bool(&scalar(value)?).map(Entry::Bool),
        "option" => {
            let s = scalar(value)?;
            check.args.contains(&s).then_some(Entry::Str(s))
        }
        "list" | "string_list" | "int_list" | "float_list" | "bool_list" => {
            let Entry::List(items) = value else {
                return None;
            };
            if !in_range(items.len() as f64, check) {
                return None;
            }
            let item_check = |name: &str| Check {
                name: name.into(),
                args: Vec::new(),
                kwargs: Vec::new(),
            };
            let each = match check.name.as_str() {
                "string_list" => Some(item_check("string")),
                "int_list" => Some(item_check("integer")),
                "float_list" => Some(item_check("float")),
                "bool_list" => Some(item_check("boolean")),
                _ => None,
            };
            match each {
                None => Some(value.clone()),
                Some(each) => items
                    .iter()
                    .map(|item| check_value(&each, item))
                    .collect::<Option<Vec<_>>>()
                    .map(Entry::List),
            }
        }
        _ => None,
    }
}

/// `ConfigObj.validate(Validator())` against `spec`: converts the values
/// in place; false when any check fails or a value is missing.
pub fn validate(section: &mut Section, spec: &Section) -> bool {
    let mut ok = true;
    for (key, check) in &spec.scalars {
        if key == "__many__" {
            continue;
        }
        let Entry::Str(check) = check else {
            ok = false;
            continue;
        };
        let check = parse_check(check);
        match section.scalars.iter_mut().find(|(k, _)| k == key) {
            Some((_, value)) => match check_value(&check, value) {
                Some(converted) => *value = converted,
                None => ok = false,
            },
            None => match check.kw("default") {
                Some(default) => {
                    let value = Entry::Str(default.to_string());
                    match check_value(&check, &value) {
                        Some(converted) => section.scalars.push((key.clone(), converted)),
                        None => ok = false,
                    }
                }
                None => ok = false,
            },
        }
    }
    for (name, subspec) in &spec.sections {
        if name == "__many__" {
            continue;
        }
        if !section.sections.iter().any(|(k, _)| k == name) {
            if section.scalars.iter().any(|(k, _)| k == name) {
                ok = false;
                continue;
            }
            section.sections.push((name.clone(), Section::default()));
        }
        let sub = section
            .sections
            .iter_mut()
            .find(|(k, _)| k == name)
            .map(|(_, s)| s)
            .expect("just added");
        ok &= validate(sub, subspec);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Entry {
        Entry::Str(v.into())
    }

    #[test]
    fn values_lists_quotes_and_comments() {
        let parsed = parse(
            "a = 1\nb = x, y # c\nc = \"q, r\"\nd = ,\ne =\nf = 'it''s'\ng = one,\nh = a#b\nj = x y , z\n[s]\nk = v\n[[t]]\nz = 1\n[u]\n",
        )
        .unwrap();
        assert_eq!(
            parsed.scalars,
            vec![
                ("a".into(), s("1")),
                ("b".into(), Entry::List(vec![s("x"), s("y")])),
                ("c".into(), s("q, r")),
                ("d".into(), Entry::List(vec![])),
                ("e".into(), s("")),
                ("f".into(), s("it''s")),
                ("g".into(), Entry::List(vec![s("one")])),
                ("h".into(), s("a")),
                ("j".into(), Entry::List(vec![s("x y"), s("z")])),
            ]
        );
        assert_eq!(parsed.sections[0].0, "s");
        assert_eq!(parsed.sections[0].1.sections[0].0, "t");
        assert_eq!(parsed.sections[1].0, "u");
    }

    #[test]
    fn errors_are_configobjs() {
        assert_eq!(
            parse("nonsense\n").unwrap_err(),
            "Invalid line ('nonsense') (matched as neither section nor keyword) at line 1."
        );
        assert_eq!(
            parse("a = 1\na = 2\n").unwrap_err(),
            "Duplicate keyword name at line 2."
        );
        assert!(parse("i = \"x\" y\n").is_err());
        assert!(parse("k = ,x\n").is_err());
        assert_eq!(
            parse("[[x]]\n").unwrap_err(),
            "Section too nested at line 1."
        );
    }

    #[test]
    fn validation_converts_and_fills_defaults() {
        let mut meta = parse("n = 5\nf = 1.5\nb = yes\n").unwrap();
        let spec =
            parse("n = integer(min=1)\nf = float\nb = boolean\nd = string(default=x)\n").unwrap();
        assert!(validate(&mut meta, &spec));
        assert_eq!(
            meta.scalars,
            vec![
                ("n".into(), Entry::Int(5)),
                ("f".into(), Entry::Float(1.5)),
                ("b".into(), Entry::Bool(true)),
                ("d".into(), s("x")),
            ]
        );
        let mut meta = parse("n = 0\n").unwrap();
        assert!(!validate(
            &mut meta,
            &parse("n = integer(min=1)\n").unwrap()
        ));
        let mut meta = parse("").unwrap();
        assert!(!validate(&mut meta, &parse("n = integer\n").unwrap()));
    }
}
