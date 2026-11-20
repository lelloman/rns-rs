//! Names of destination types (upstream `Transport.destination_type_map`).
//!
//! A destination type is known by its name hash. Upstream records the name
//! behind a hash when the `[filter]` section blocks or allows it, when a
//! local application asks for it, and, since c90a5d58, from the
//! `known_destination_types` file in the config directory. Its log lines
//! name a type through this map (`Transport.destination_type_name`).

use std::collections::BTreeMap;
use std::path::Path;

use rns_core::encoding::hex;
use rns_core::transport::destination_filter::{
    configured_destination_type_name, destination_type, DestinationType,
};

use crate::config::FilterSection;

/// The file of known destination type names, in the config directory.
pub const KNOWN_DESTINATION_TYPES_FILE: &str = "known_destination_types";
/// The file of flagged destination type names, in the config directory.
pub const FLAGGED_DESTINATION_TYPES_FILE: &str = "flagged_destination_types";

/// Upstream's `Transport.destination_type_map`: a name for each destination
/// type hash it has seen one for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationTypeNames {
    names: BTreeMap<DestinationType, String>,
}

impl DestinationTypeNames {
    /// The map as upstream has it once its config is applied: the types
    /// the `[filter]` section blocks and allows, then the
    /// `known_destination_types` file of `config_dir`, read as
    /// [`DestinationTypeNames::load_files`] reads it.
    pub fn from_config(config_dir: &Path, filter: &FilterSection) -> Self {
        let (mut names, lines) = Self::from_filter(filter);
        for line in lines {
            log::debug!("{line}");
        }
        names.load_files(config_dir);
        names
    }

    /// The names the `[filter]` section records, with the debug lines
    /// upstream logs while it applies the section.
    ///
    /// Upstream reads the options in file order. `block_destination_type`
    /// logs `Blocked <name> <hash> destinations` for each ignored type, and
    /// `allow_destination_type` logs `Allowing <<name>> <hash> destinations`
    /// for each allowed type, but only when `required_destinations_only` is
    /// already set, so only when `required_only = yes` comes before
    /// `allowed_types`. Each records its name, so of a type listed under
    /// both keys the later key's name stays. An empty name is ignored
    /// without a line.
    ///
    /// Upstream also has `Could not add … destination type to blocked
    /// list` and `… to allowed list` errors. Their `try` blocks cannot fail
    /// for a config value, which ConfigObj always decodes to a `str`, so
    /// there is nothing here to log them for.
    pub fn from_filter(filter: &FilterSection) -> (Self, Vec<String>) {
        let mut names = Self::default();
        let mut lines = Vec::new();
        let mut required_only = false;
        for key in &filter.key_order {
            let (allowing, full_names) = match key.as_str() {
                "required_only" => {
                    required_only = filter.required_only;
                    continue;
                }
                "ignored_types" => (false, &filter.ignored_types),
                "allowed_types" => (true, &filter.allowed_types),
                _ => continue,
            };
            for full_name in full_names {
                let Some((destination_type, name)) = configured_destination_type_name(full_name)
                else {
                    continue;
                };
                if !allowing {
                    lines.push(format!(
                        "Blocked {name} <{}> destinations",
                        hex(&destination_type)
                    ));
                }
                names.insert(destination_type, name);
                if allowing && required_only {
                    lines.push(format!(
                        "Allowing {} destinations",
                        names.describe(&destination_type)
                    ));
                }
            }
        }
        (names, lines)
    }

    /// Record `name` for `destination_type`, replacing any earlier name.
    pub fn insert(&mut self, destination_type: DestinationType, name: String) {
        self.names.insert(destination_type, name);
    }

    /// The name recorded for `destination_type`, if any.
    pub fn get(&self, destination_type: &DestinationType) -> Option<&str> {
        self.names.get(destination_type).map(String::as_str)
    }

    /// `Transport.destination_type_name`: the name in angle brackets, or
    /// `<unknown>`.
    pub fn type_name(&self, destination_type: &DestinationType) -> String {
        format!("<{}>", self.get(destination_type).unwrap_or("unknown"))
    }

    /// How upstream's log lines show a destination type: its name, then its
    /// hash (`<lxmf.delivery> <hash>`).
    pub fn describe(&self, destination_type: &DestinationType) -> String {
        format!(
            "{} <{}>",
            self.type_name(destination_type),
            hex(destination_type)
        )
    }

    /// The `known_destination_types` and `flagged_destination_types` files
    /// of `config_dir`, as upstream c90a5d58 reads them at startup: each
    /// one only if it is a file, its text stripped and split into lines,
    /// each line stripped, lines starting with `#` skipped, and every other
    /// line, an empty one included, recorded under its name hash. A file
    /// that cannot be read is logged as an error and adds nothing.
    ///
    /// Upstream records the flagged names in `Transport.flagged_type_map`,
    /// which it does not have yet at c90a5d58 (commit 3f55e9eb adds it):
    /// the first line to record fails, and that error is logged, as there.
    pub fn load_files(&mut self, config_dir: &Path) {
        if let Some(lines) = read_type_file(
            &config_dir.join(KNOWN_DESTINATION_TYPES_FILE),
            "known destination types list",
        ) {
            for name in lines {
                self.insert(destination_type(&name), name);
            }
        }
        if let Some(mut lines) = read_type_file(
            &config_dir.join(FLAGGED_DESTINATION_TYPES_FILE),
            "flagged destination types list",
        ) {
            if lines.next().is_some() {
                log::error!(
                    "Error while loading flagged destination types list: type object 'Transport' has no attribute 'flagged_type_map'"
                );
            }
        }
    }
}

/// The names in a destination type file, or `None` when there is no such
/// file or it cannot be read (logged as upstream's `what` error).
fn read_type_file(path: &Path, what: &str) -> Option<impl Iterator<Item = String>> {
    if !path.is_file() {
        return None;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            log::error!("Error while loading {what}: {error}");
            return None;
        }
    };
    let names: Vec<String> = python_splitlines(python_strip(&text))
        .into_iter()
        .map(|line| python_strip(line).to_string())
        .filter(|line| !line.starts_with('#'))
        .collect();
    Some(names.into_iter())
}

/// Python's `str.isspace` for one character.
fn python_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()`.
fn python_strip(s: &str) -> &str {
    s.trim_matches(python_isspace)
}

/// Python's `str.splitlines()`: split at every line boundary Python
/// recognises, `\r\n` counting as one, with no empty last line for a
/// trailing boundary.
fn python_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        lines.push(&s[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' {
            if let Some(&(j, '\n')) = chars.peek() {
                chars.next();
                end = j + 1;
            }
        }
        start = end;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_and_strip_follow_python() {
        assert_eq!(
            python_splitlines("a\nb\r\nc\rd\u{0b}e\u{0c}f\u{1c}g\u{85}h\u{2028}i\u{2029}j"),
            ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        );
        assert_eq!(python_splitlines("a\n\nb\n"), ["a", "", "b"]);
        assert!(python_splitlines("").is_empty());
        assert_eq!(python_strip("\u{1f} \t a b \u{a0}\n"), "a b");
    }

    #[test]
    fn known_destination_types_are_read_as_upstream() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(KNOWN_DESTINATION_TYPES_FILE),
            "\n\n# a comment\n  lxmf.delivery  \r\n #indented comment\nnomadnetwork.node # not a comment\n\n\u{85}rncp.receive\n\n",
        )
        .unwrap();
        let mut names = DestinationTypeNames::default();
        names.load_files(dir.path());
        let expected: BTreeMap<DestinationType, String> = [
            "lxmf.delivery",
            "nomadnetwork.node # not a comment",
            // The empty lines inside the stripped text: upstream records
            // the empty name too.
            "",
            "rncp.receive",
        ]
        .into_iter()
        .map(|name| (destination_type(name), name.to_string()))
        .collect();
        assert_eq!(names.names, expected);
        assert_eq!(
            names.type_name(&destination_type("lxmf.delivery")),
            "<lxmf.delivery>"
        );
        assert_eq!(
            names.describe(&destination_type("lxmf.delivery")),
            format!(
                "<lxmf.delivery> <{}>",
                hex(&destination_type("lxmf.delivery"))
            )
        );
        assert_eq!(
            names.type_name(&destination_type("rnx.execute")),
            "<unknown>"
        );
    }

    #[test]
    fn missing_unreadable_and_flagged_type_files_add_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut names = DestinationTypeNames::default();
        names.load_files(dir.path());
        assert_eq!(names, DestinationTypeNames::default());

        // Not UTF-8: an error, nothing loaded. A directory is not a file.
        std::fs::write(dir.path().join(KNOWN_DESTINATION_TYPES_FILE), [0xff, b'\n']).unwrap();
        std::fs::create_dir(dir.path().join(FLAGGED_DESTINATION_TYPES_FILE)).unwrap();
        names.load_files(dir.path());
        assert_eq!(names, DestinationTypeNames::default());

        // At c90a5d58 flagged names have nowhere to go upstream.
        std::fs::remove_dir(dir.path().join(FLAGGED_DESTINATION_TYPES_FILE)).unwrap();
        std::fs::write(
            dir.path().join(FLAGGED_DESTINATION_TYPES_FILE),
            "# flagged\nlxmf.propagation\n",
        )
        .unwrap();
        names.load_files(dir.path());
        assert_eq!(names, DestinationTypeNames::default());
    }

    #[test]
    fn the_config_filter_names_come_first_and_the_file_overrides_them() {
        let dir = tempfile::tempdir().unwrap();
        let lxmf = destination_type("lxmf.delivery");
        let filter = FilterSection {
            required_only: false,
            ignored_types: vec!["nomadnetwork.node".into(), String::new()],
            allowed_types: vec![format!("<{}>", hex(&lxmf))],
            key_order: vec!["ignored_types".into(), "allowed_types".into()],
        };
        let names = DestinationTypeNames::from_config(dir.path(), &filter);
        assert_eq!(names.get(&lxmf), Some(hex(&lxmf).as_str()));
        assert_eq!(
            names.get(&destination_type("nomadnetwork.node")),
            Some("nomadnetwork.node")
        );
        assert_eq!(names.get(&destination_type("")), None);

        std::fs::write(
            dir.path().join(KNOWN_DESTINATION_TYPES_FILE),
            "lxmf.delivery\n",
        )
        .unwrap();
        let names = DestinationTypeNames::from_config(dir.path(), &filter);
        assert_eq!(names.get(&lxmf), Some("lxmf.delivery"));
    }

    /// The `[filter]` section of `config`, as the parser reads it.
    fn filter_of(config: &str) -> FilterSection {
        crate::config::parse(config).unwrap().filter
    }

    // Upstream's block_destination_type and allow_destination_type, applied
    // in file order as Reticulum.__apply_config applies them.
    #[test]
    fn filter_types_are_logged_as_upstream_applies_them() {
        let lxmf = destination_type("lxmf.delivery");
        let node = destination_type("nomadnetwork.node");
        let rncp = destination_type("rncp.receive");
        let blocked =
            |name: &str, t: &DestinationType| format!("Blocked {name} <{}> destinations", hex(t));
        let allowing = |name: &str, t: &DestinationType| {
            format!("Allowing <{name}> <{}> destinations", hex(t))
        };

        // required_only before allowed_types: every type is logged.
        let (names, lines) = DestinationTypeNames::from_filter(&filter_of(
            "[filter]\nrequired_only = yes\nignored_types = nomadnetwork.node\n\
             allowed_types = lxmf.delivery, rncp.receive\n",
        ));
        assert_eq!(
            lines,
            [
                blocked("nomadnetwork.node", &node),
                allowing("lxmf.delivery", &lxmf),
                allowing("rncp.receive", &rncp),
            ]
        );
        assert_eq!(names.get(&lxmf), Some("lxmf.delivery"));

        // After allowed_types, required_only is not yet set when the types
        // are allowed: they are not logged.
        let (_, lines) = DestinationTypeNames::from_filter(&filter_of(
            "[filter]\nallowed_types = lxmf.delivery\nignored_types = nomadnetwork.node\n\
             required_only = yes\n",
        ));
        assert_eq!(lines, [blocked("nomadnetwork.node", &node)]);

        // Not required: allowed types are never logged.
        let (_, lines) = DestinationTypeNames::from_filter(&filter_of(
            "[filter]\nrequired_only = no\nallowed_types = lxmf.delivery\n",
        ));
        assert!(lines.is_empty());

        // File order decides the order of the lines and which name a type
        // listed under both keys keeps. The bracketed form logs the kept
        // characters, in both lines.
        let hash = hex(&lxmf);
        let (names, lines) = DestinationTypeNames::from_filter(&filter_of(&format!(
            "[filter]\nrequired_only = yes\nallowed_types = <{hash}>\nignored_types = lxmf.delivery\n"
        )));
        assert_eq!(
            lines,
            [allowing(&hash, &lxmf), blocked("lxmf.delivery", &lxmf)]
        );
        assert_eq!(names.get(&lxmf), Some("lxmf.delivery"));
        let (names, lines) = DestinationTypeNames::from_filter(&filter_of(&format!(
            "[filter]\nignored_types = lxmf.delivery\nrequired_only = yes\nallowed_types = <{hash}>\n"
        )));
        assert_eq!(
            lines,
            [blocked("lxmf.delivery", &lxmf), allowing(&hash, &lxmf)]
        );
        assert_eq!(names.get(&lxmf), Some(hash.as_str()));

        // No section, no lines.
        let (names, lines) = DestinationTypeNames::from_filter(&filter_of(""));
        assert!(lines.is_empty());
        assert_eq!(names, DestinationTypeNames::default());
    }
}
