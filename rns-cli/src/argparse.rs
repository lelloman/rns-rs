//! Upstream's command-line help and errors, byte for byte.
//!
//! A port of the parts of Python 3.12's `argparse.HelpFormatter` (3.10 to
//! 3.12 print the same) and `textwrap` that upstream's utilities use, driven
//! by their parsers as `tests/generate_argparse_fixtures.py` captured them
//! (`upstream_parsers.rs`), and of argparse's error reporting: the usage
//! line, `<prog>: error: <message>` and exit status 2.

use crate::args::{Args, Seen};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Store,
    StoreTrue,
    Count,
    Append,
    Help,
    Version,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    One,
    Zero,
    Optional,
    ZeroOrMore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Str,
    Float,
    Int,
}

/// One `add_argument` of an upstream parser.
#[derive(Debug)]
pub struct Action {
    pub opts: &'static [&'static str],
    pub dest: &'static str,
    pub kind: Kind,
    pub nargs: Nargs,
    pub metavar: Option<&'static str>,
    pub help: Option<&'static str>,
    pub ty: Ty,
    pub required: bool,
}

/// An upstream utility's `ArgumentParser`.
#[derive(Debug)]
pub struct Parser {
    pub name: &'static str,
    pub description: Option<&'static str>,
    /// Text after the options.
    pub epilog: Option<&'static str>,
    /// `RawDescriptionHelpFormatter`: the description and epilog are
    /// printed as written, not refilled.
    pub raw_description: bool,
    pub actions: &'static [Action],
}

/// What parsing a command line comes to before the tool runs.
#[derive(Debug, PartialEq, Eq)]
pub struct Exit {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `shutil.get_terminal_size().columns`: `COLUMNS`, else the terminal on
/// stdout, else 80.
pub fn terminal_columns() -> usize {
    if let Some(columns) = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|c| *c > 0)
    {
        return columns as usize;
    }
    crate::sys::stdout_columns().unwrap_or(80)
}

/// argparse's `SUPPRESS`: an action left out of usage and help.
const SUPPRESS: &str = "==SUPPRESS==";

fn shown(action: &&Action) -> bool {
    action.help != Some(SUPPRESS)
}

fn len(s: &str) -> usize {
    s.chars().count()
}

fn spaces(n: i64) -> String {
    " ".repeat(n.max(0) as usize)
}

struct Formatter<'a> {
    prog: &'a str,
    width: i64,
    max_help_position: i64,
}

impl<'a> Formatter<'a> {
    fn new(prog: &'a str, columns: usize) -> Self {
        let width = columns as i64 - 2;
        Formatter {
            prog,
            width,
            max_help_position: 24.min((width - 20).max(4)),
        }
    }

    fn metavar(action: &Action, default: &str) -> String {
        action.metavar.unwrap_or(default).to_string()
    }

    fn format_args(action: &Action, default: &str) -> String {
        let m = Self::metavar(action, default);
        match action.nargs {
            Nargs::One => m,
            Nargs::Optional => format!("[{m}]"),
            Nargs::ZeroOrMore => format!("[{m} ...]"),
            Nargs::Zero => String::new(),
        }
    }

    fn usage_part(action: &Action) -> String {
        if action.opts.is_empty() {
            return Self::format_args(action, action.dest);
        }
        let part = if action.nargs == Nargs::Zero {
            action.opts[0].to_string()
        } else {
            let args = Self::format_args(action, &action.dest.to_uppercase());
            format!("{} {args}", action.opts[0])
        };
        if action.required {
            part
        } else {
            format!("[{part}]")
        }
    }

    fn invocation(action: &Action) -> String {
        if action.opts.is_empty() {
            return Self::metavar(action, action.dest);
        }
        if action.nargs == Nargs::Zero {
            return action.opts.join(", ");
        }
        let args = Self::format_args(action, &action.dest.to_uppercase());
        action
            .opts
            .iter()
            .map(|o| format!("{o} {args}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `_format_usage` with the default `usage: ` prefix.
    fn usage(&self, parser: &Parser) -> String {
        let prefix = "usage: ";
        let prog = self.prog;
        let (optionals, positionals): (Vec<&Action>, Vec<&Action>) = parser
            .actions
            .iter()
            .filter(shown)
            .partition(|a| !a.opts.is_empty());
        let opt_parts: Vec<String> = optionals.iter().map(|a| Self::usage_part(a)).collect();
        let pos_parts: Vec<String> = positionals.iter().map(|a| Self::usage_part(a)).collect();
        let action_usage = opt_parts
            .iter()
            .chain(pos_parts.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let mut usage = if action_usage.is_empty() {
            prog.to_string()
        } else {
            format!("{prog} {action_usage}")
        };
        let text_width = self.width;
        if (len(prefix) + len(&usage)) as i64 > text_width {
            let get_lines = |parts: &[String], indent: &str, prefix: Option<&str>| {
                let mut lines: Vec<String> = Vec::new();
                let mut line: Vec<&str> = Vec::new();
                let indent_length = len(indent) as i64;
                let mut line_len = match prefix {
                    Some(prefix) => len(prefix) as i64 - 1,
                    None => indent_length - 1,
                };
                for part in parts {
                    if line_len + 1 + len(part) as i64 > text_width && !line.is_empty() {
                        lines.push(format!("{indent}{}", line.join(" ")));
                        line.clear();
                        line_len = indent_length - 1;
                    }
                    line.push(part);
                    line_len += len(part) as i64 + 1;
                }
                if !line.is_empty() {
                    lines.push(format!("{indent}{}", line.join(" ")));
                }
                if prefix.is_some() {
                    if let Some(first) = lines.first_mut() {
                        *first = first.chars().skip(indent_length as usize).collect();
                    }
                }
                lines
            };
            let lines: Vec<String> = if 4 * (len(prefix) + len(prog)) as i64 <= 3 * text_width {
                let indent = " ".repeat(len(prefix) + len(prog) + 1);
                let with_prog = |parts: &[String]| {
                    let mut all = vec![prog.to_string()];
                    all.extend(parts.iter().cloned());
                    all
                };
                if !opt_parts.is_empty() {
                    let mut lines = get_lines(&with_prog(&opt_parts), &indent, Some(prefix));
                    lines.extend(get_lines(&pos_parts, &indent, None));
                    lines
                } else if !pos_parts.is_empty() {
                    get_lines(&with_prog(&pos_parts), &indent, Some(prefix))
                } else {
                    vec![prog.to_string()]
                }
            } else {
                let indent = " ".repeat(len(prefix));
                let parts: Vec<String> =
                    opt_parts.iter().chain(pos_parts.iter()).cloned().collect();
                let mut lines = get_lines(&parts, &indent, None);
                if lines.len() > 1 {
                    lines = get_lines(&opt_parts, &indent, None);
                    lines.extend(get_lines(&pos_parts, &indent, None));
                }
                let mut all = vec![prog.to_string()];
                all.extend(lines);
                all
            };
            usage = lines.join("\n");
        }
        format!("{prefix}{usage}\n\n")
    }

    fn text(&self, text: &str, indent: i64) -> String {
        let text_width = (self.width - indent).max(11);
        let indent = spaces(indent);
        let text = collapse_whitespace(text);
        let lines = wrap(&text, text_width as usize, &indent, &indent);
        format!("{}\n\n", lines.join("\n"))
    }

    /// The description or epilog: refilled as [`Formatter::text`], or
    /// as written under `RawDescriptionHelpFormatter`.
    fn description_text(&self, parser: &Parser, text: &str) -> String {
        if parser.raw_description {
            format!("{text}\n\n")
        } else {
            self.text(text, 0)
        }
    }

    fn action(&self, action: &Action, indent: i64, max_length: i64) -> String {
        let help_position = (max_length + 2).min(self.max_help_position);
        let help_width = (self.width - help_position).max(11);
        let action_width = help_position - indent - 2;
        let header = Self::invocation(action);
        let help = action.help.filter(|h| !h.trim().is_empty());
        let mut out = String::new();
        let indent_first;
        if action.help.is_none_or(|h| h.is_empty()) {
            out.push_str(&format!("{}{header}\n", spaces(indent)));
            indent_first = 0;
        } else if len(&header) as i64 <= action_width {
            let pad = spaces(action_width - len(&header) as i64);
            out.push_str(&format!("{}{header}{pad}  ", spaces(indent)));
            indent_first = 0;
        } else {
            out.push_str(&format!("{}{header}\n", spaces(indent)));
            indent_first = help_position;
        }
        if let Some(help) = help {
            let lines = wrap(&collapse_whitespace(help), help_width as usize, "", "");
            if let Some((first, rest)) = lines.split_first() {
                out.push_str(&format!("{}{first}\n", spaces(indent_first)));
                for line in rest {
                    out.push_str(&format!("{}{line}\n", spaces(help_position)));
                }
            }
        } else if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    fn help(&self, parser: &Parser) -> String {
        let indent = 2;
        let max_length = parser
            .actions
            .iter()
            .filter(shown)
            .map(|a| len(&Self::invocation(a)) as i64 + indent)
            .max()
            .unwrap_or(0);
        let mut out = self.usage(parser);
        if let Some(description) = parser.description {
            out.push_str(&self.description_text(parser, description));
        }
        for (heading, positional) in [("positional arguments", true), ("options", false)] {
            let items: String = parser
                .actions
                .iter()
                .filter(shown)
                .filter(|a| a.opts.is_empty() == positional)
                .map(|a| self.action(a, indent, max_length))
                .collect();
            if !items.is_empty() {
                out.push_str(&format!("\n{heading}:\n{items}\n"));
            }
        }
        if let Some(epilog) = parser.epilog {
            out.push_str(&self.description_text(parser, epilog));
        }
        finish(out)
    }
}

/// `format_help`'s last step: no more than one empty line in a row, and
/// exactly one newline at the end.
fn finish(text: String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut newlines = 0;
    for c in text.chars() {
        if c == '\n' {
            newlines += 1;
            if newlines <= 2 {
                out.push(c);
            }
        } else {
            newlines = 0;
            out.push(c);
        }
    }
    format!("{}\n", out.trim_matches('\n'))
}

/// `re.sub(r'\s+', ' ', text).strip()` with ASCII whitespace.
fn collapse_whitespace(text: &str) -> String {
    text.split(|c: char| c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_letter(c: char) -> bool {
    is_word(c) && !c.is_numeric()
}

fn is_word_punct(c: char) -> bool {
    is_word(c) || "!\"'&.,?".contains(c)
}

/// `textwrap.TextWrapper._split`: whitespace runs, and words split after
/// hyphens between letters and before em-dashes, as `wordsep_re` does.
fn split_chunks(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < n {
        if chars[i] == ' ' {
            let start = i;
            while i < n && chars[i] == ' ' {
                i += 1;
            }
            chunks.push(chars[start..i].iter().collect());
            continue;
        }
        // An em-dash between words: (?<=wp) -{2,} (?=\w).
        let em_dash_at = |j: usize| {
            if j == 0 || j >= n || chars[j] != '-' || !is_word_punct(chars[j - 1]) {
                return None;
            }
            let mut k = j;
            while k < n && chars[k] == '-' {
                k += 1;
            }
            (k - j >= 2 && k < n && is_word(chars[k])).then_some(k)
        };
        if let Some(end) = em_dash_at(i) {
            chunks.push(chars[i..end].iter().collect());
            i = end;
            continue;
        }
        // A word, possibly hyphenated: nws+? up to the first place one of
        // the word endings matches.
        let start = i;
        let mut j = i + 1;
        loop {
            // j is one past the last char taken (at least one).
            let last = j - 1;
            let hyphen_split = chars[last] == '-'
                && ((last >= 2 && is_letter(chars[last - 1]) && is_letter(chars[last - 2]))
                    || (last >= 3
                        && is_letter(chars[last - 1])
                        && chars[last - 2] == '-'
                        && is_letter(chars[last - 3])))
                && j < n
                && is_letter(chars[j])
                && ((j + 1 < n && is_letter(chars[j + 1]))
                    || (j + 2 < n && chars[j + 1] == '-' && is_letter(chars[j + 2])));
            let word_end = j >= n || chars[j] == ' ';
            let before_em_dash = is_word_punct(chars[last]) && em_dash_at(j).is_some();
            if hyphen_split || word_end || before_em_dash {
                break;
            }
            j += 1;
        }
        chunks.push(chars[start..j].iter().collect());
        i = j;
    }
    chunks
}

/// `textwrap.wrap(text, width, initial_indent=, subsequent_indent=)` with
/// the defaults argparse uses.
fn wrap(text: &str, width: usize, initial_indent: &str, subsequent_indent: &str) -> Vec<String> {
    let mut chunks = split_chunks(text);
    chunks.reverse();
    let mut lines: Vec<String> = Vec::new();
    while !chunks.is_empty() {
        let mut cur_line: Vec<String> = Vec::new();
        let mut cur_len = 0usize;
        let indent = if lines.is_empty() {
            initial_indent
        } else {
            subsequent_indent
        };
        let width = width as i64 - len(indent) as i64;
        if !lines.is_empty() && chunks.last().is_some_and(|c| c.trim().is_empty()) {
            chunks.pop();
        }
        while let Some(l) = chunks.last().map(|chunk| len(chunk)) {
            if (cur_len + l) as i64 > width {
                break;
            }
            cur_len += l;
            cur_line.extend(chunks.pop());
        }
        if let Some(last) = chunks.last_mut().filter(|c| len(c) as i64 > width) {
            // _handle_long_word, break_long_words and break_on_hyphens on.
            let space_left = if width < 1 {
                1
            } else {
                (width - cur_len as i64) as usize
            };
            let chunk: Vec<char> = last.chars().collect();
            let mut end = space_left;
            if chunk.len() > space_left {
                if let Some(hyphen) = chunk[..space_left].iter().rposition(|c| *c == '-') {
                    if hyphen > 0 && chunk[..hyphen].iter().any(|c| *c != '-') {
                        end = hyphen + 1;
                    }
                }
            }
            let end = end.min(chunk.len());
            cur_line.push(chunk[..end].iter().collect());
            *last = chunk[end..].iter().collect();
            if chunks.last().is_some_and(|c| c.is_empty()) {
                chunks.pop();
            }
        }
        if cur_line.last().is_some_and(|c| c.trim().is_empty()) {
            cur_line.pop();
        }
        if !cur_line.is_empty() {
            lines.push(format!("{indent}{}", cur_line.concat()));
        }
    }
    lines
}

/// The parser's `format_help()` for `prog` at a terminal of `columns`.
pub fn format_help(parser: &Parser, prog: &str, columns: usize) -> String {
    Formatter::new(prog, columns).help(parser)
}

/// The parser's `format_usage()`.
pub fn format_usage(parser: &Parser, prog: &str, columns: usize) -> String {
    finish(Formatter::new(prog, columns).usage(parser))
}

/// Python's `repr()` of a string.
pub fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's digits with single underscores between them, without them.
fn python_digits(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_' {
            let digit = |j: Option<&char>| j.is_some_and(|c| c.is_ascii_digit());
            if i == 0 || !digit(chars.get(i - 1)) || !digit(chars.get(i + 1)) {
                return None;
            }
        }
    }
    Some(s.replace('_', ""))
}

/// Whether Python's `float(s)` accepts `s`.
pub fn python_float_ok(s: &str) -> bool {
    python_digits(s.trim()).is_some_and(|s| !s.is_empty() && s.parse::<f64>().is_ok())
}

/// Whether Python's `int(s)` accepts `s`.
pub fn python_int_ok(s: &str) -> bool {
    let s = s.trim();
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_')
        && python_digits(digits).is_some()
}

/// Python's `int(s)`, for values [`python_int_ok`] accepts that fit an i64.
pub fn python_int(s: &str) -> Option<i64> {
    python_int_ok(s)
        .then(|| s.trim().replace('_', "").parse().ok())
        .flatten()
}

/// Python's `float(s)`.
pub fn python_float(s: &str) -> Option<f64> {
    python_float_ok(s)
        .then(|| python_digits(s.trim())?.parse().ok())
        .flatten()
}

fn action_for<'p>(parser: &'p Parser, opt: &crate::args::Opt) -> Option<&'p Action> {
    let long = (!opt.long.is_empty()).then(|| format!("--{}", opt.long));
    let short = (!opt.short.is_empty()).then(|| format!("-{}", opt.short));
    parser.actions.iter().find(|a| {
        a.opts
            .iter()
            .any(|o| Some(o.to_string()) == long || Some(o.to_string()) == short)
    })
}

fn names(parser: &Parser, opt: &crate::args::Opt) -> String {
    match action_for(parser, opt) {
        Some(action) => action.opts.join("/"),
        None => [opt.short, opt.long]
            .iter()
            .zip(["-", "--"])
            .filter(|(n, _)| !n.is_empty())
            .map(|(n, dash)| format!("{dash}{n}"))
            .collect::<Vec<_>>()
            .join("/"),
    }
}

/// What upstream's parser does with the command line `args` came from
/// before the tool itself runs: print its help (exit 0), report the first
/// error as argparse does (exit 2), or nothing (`None`), the tool goes on.
pub fn check(args: &Args, parser: &Parser, prog: &str, columns: usize) -> Option<Exit> {
    let error = |message: String| Exit {
        code: 2,
        stdout: String::new(),
        stderr: format!(
            "{}{prog}: error: {message}\n",
            format_usage(parser, prog, columns)
        ),
    };
    let mut positional_room: usize = parser
        .actions
        .iter()
        .filter(|a| a.opts.is_empty())
        .map(|a| match a.nargs {
            Nargs::ZeroOrMore => usize::MAX / 2,
            _ => 1,
        })
        .sum();
    let mut unrecognized: Vec<&str> = Vec::new();
    // After a nargs="*" option, the values up to the next option are its.
    let mut absorbing = false;
    for seen in &args.trace {
        if !matches!(seen, Seen::Positional(_)) {
            absorbing = false;
        }
        match seen {
            Seen::Option(opt, value) => {
                let Some(action) = action_for(parser, opt) else {
                    continue;
                };
                absorbing = action.nargs == Nargs::ZeroOrMore;
                match action.kind {
                    Kind::Help => {
                        return Some(Exit {
                            code: 0,
                            stdout: format_help(parser, prog, columns),
                            stderr: String::new(),
                        })
                    }
                    Kind::Version => return None,
                    _ => {}
                }
                if let Some(value) = value {
                    let (ok, ty) = match action.ty {
                        Ty::Float => (python_float_ok(value), "float"),
                        Ty::Int => (python_int_ok(value), "int"),
                        Ty::Str => (true, ""),
                    };
                    if !ok {
                        return Some(error(format!(
                            "argument {}: invalid {ty} value: {}",
                            action.opts.join("/"),
                            repr(value)
                        )));
                    }
                }
            }
            Seen::Missing(opt) => {
                return Some(error(format!(
                    "argument {}: expected one argument",
                    names(parser, opt)
                )))
            }
            Seen::Ignored(opt, explicit) => {
                return Some(error(format!(
                    "argument {}: ignored explicit argument {}",
                    names(parser, opt),
                    repr(explicit)
                )))
            }
            Seen::Ambiguous(arg, rust_matches) => {
                // In the order argparse registered the option strings.
                let prefix = arg.split_once('=').map_or(arg.as_str(), |(p, _)| p);
                let mut matches: Vec<&str> = parser
                    .actions
                    .iter()
                    .flat_map(|a| a.opts.iter().copied())
                    .filter(|o| o.starts_with("--") && o.starts_with(prefix))
                    .collect();
                if matches.len() < 2 {
                    matches = rust_matches.iter().map(String::as_str).collect();
                }
                return Some(error(format!(
                    "ambiguous option: {arg} could match {}",
                    matches.join(", ")
                )));
            }
            Seen::Unknown(arg) => unrecognized.push(arg),
            Seen::Positional(_) if absorbing => {}
            Seen::Positional(arg) => {
                if positional_room > 0 {
                    positional_room -= 1;
                } else {
                    unrecognized.push(arg);
                }
            }
        }
    }
    if !unrecognized.is_empty() {
        return Some(error(format!(
            "unrecognized arguments: {}",
            unrecognized.join(" ")
        )));
    }
    None
}

/// Print upstream's help for the tool `name`, as `prog`.
pub fn print_help(name: &str, prog: &str) {
    if let Some(parser) = crate::upstream_parsers::by_name(name) {
        print!("{}", format_help(parser, prog, terminal_columns()));
    }
}

/// [`check`] against upstream's parser named `name` at the terminal's width,
/// exiting as argparse would when it decides the outcome.
pub fn enforce(args: &Args, name: &str, prog: &str) {
    let Some(parser) = crate::upstream_parsers::by_name(name) else {
        return;
    };
    if let Some(exit) = check(args, parser, prog, terminal_columns()) {
        print!("{}", exit.stdout);
        eprint!("{}", exit.stderr);
        std::process::exit(exit.code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::OptionSpec;
    use rns_net::pickle::PickleValue;

    fn spec(tool: &str) -> &'static OptionSpec {
        match tool {
            "rnsd" => &crate::rnsd::OPTIONS,
            "rnstatus" => &crate::rnstatus_command::OPTIONS,
            "rnpath" => &crate::rnpath_command::OPTIONS,
            "rnprobe" => &crate::rnprobe_command::OPTIONS,
            "rnid" => &crate::rnid_command::OPTIONS,
            "rncp" => &crate::rncp::OPTIONS,
            "rnx" => &crate::rnx::OPTIONS,
            "rnir" => &crate::placeholder::RNIR_OPTIONS,
            "rnpkg" => &crate::placeholder::OPTIONS,
            "rnsh" => &crate::rnsh::OPTIONS,
            other => panic!("no option table for {other}"),
        }
    }

    /// Every tool's --help at several widths, and its outcome for every
    /// invalid command line in `tests/fixtures/argparse` (upstream's own
    /// parsers, `tests/generate_argparse_fixtures.py`), byte for byte.
    #[test]
    fn help_and_errors_match_upstreams_parsers() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/argparse");
        let mut failures = Vec::new();
        let mut checked = 0;
        for tool in [
            "rnsd", "rnstatus", "rnpath", "rnprobe", "rnid", "rncp", "rnx", "rnir", "rnpkg", "rnsh",
        ] {
            let parser = crate::upstream_parsers::by_name(tool).unwrap();
            let fixture = rns_net::pickle::decode(
                &std::fs::read(dir.join(format!("{tool}.pickle"))).unwrap(),
            )
            .unwrap();
            let Some(PickleValue::Dict(helps)) = fixture.get("help") else {
                panic!("no help in {tool}");
            };
            for (width, expected) in helps {
                let width = width.as_int().unwrap() as usize;
                let rendered = format_help(parser, tool, width);
                checked += 1;
                if Some(rendered.as_str()) != expected.as_str() {
                    failures.push(format!(
                        "{tool} --help at {width}:\n--- rust\n{rendered}--- upstream\n{}",
                        expected.as_str().unwrap()
                    ));
                }
            }
            for case in fixture.get("errors").unwrap().as_list().unwrap() {
                let argv: Vec<String> = case
                    .get("argv")
                    .unwrap()
                    .as_list()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_string())
                    .collect();
                let expected = Exit {
                    code: case.get("code").unwrap().as_int().unwrap() as i32,
                    stdout: case.get("stdout").unwrap().as_str().unwrap().to_string(),
                    stderr: case.get("stderr").unwrap().as_str().unwrap().to_string(),
                };
                let args = crate::args::Args::parse_spec_from(argv.clone(), spec(tool));
                // Options only this implementation has (rnid's -Z, -c for
                // --config) are accepted on purpose.
                if args.trace.iter().any(|seen| {
                    matches!(seen, Seen::Option(opt, _) | Seen::Missing(opt) | Seen::Ignored(opt, _)
                        if action_for(parser, opt).is_none())
                }) {
                    continue;
                }
                let outcome = check(&args, parser, tool, 80);
                let expected =
                    (expected.code != 0 || !expected.stdout.is_empty()).then_some(expected);
                checked += 1;
                if outcome != expected {
                    failures.push(format!(
                        "{tool} {argv:?}:\n  rust:     {:?}\n  upstream: {:?}",
                        outcome.map(|e| (e.code, e.stderr.lines().last().map(str::to_string))),
                        expected.map(|e| (e.code, e.stderr.lines().last().map(str::to_string)))
                    ));
                }
            }
        }
        assert!(checked > 500, "{checked}");
        assert!(
            failures.is_empty(),
            "{} of {checked} differ:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn textwrap_splits_as_python() {
        // textwrap.TextWrapper()._split(...) in Python 3.12.
        assert_eq!(
            split_chunks("a well-known non-interactive x--y look-at-me"),
            [
                "a",
                " ",
                "well-",
                "known",
                " ",
                "non-",
                "interactive",
                " ",
                "x",
                "--",
                "y",
                " ",
                "look-",
                "at-",
                "me"
            ]
        );
        assert_eq!(
            split_chunks("--config -v a-b"),
            ["--config", " ", "-v", " ", "a-b"]
        );
    }

    #[test]
    fn python_number_syntax() {
        for ok in [
            "5",
            " 5 ",
            "1_0",
            "-2",
            "+3",
            "1e3",
            ".5",
            "5.",
            "inf",
            "-Infinity",
            "nan",
        ] {
            assert!(python_float_ok(ok), "{ok}");
        }
        for bad in ["x", "", "1__0", "_1", "1_", "1e", "0x10"] {
            assert!(!python_float_ok(bad), "{bad}");
        }
        for ok in ["5", " -5 ", "1_000", "+7"] {
            assert!(python_int_ok(ok), "{ok}");
        }
        for bad in ["5.0", "x", "", "1__0", "_5", "inf"] {
            assert!(!python_int_ok(bad), "{bad}");
        }
        assert_eq!(repr("x"), "'x'");
        assert_eq!(repr("it's"), "\"it's\"");
    }
}
