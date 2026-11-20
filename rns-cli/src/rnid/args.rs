//! Options, as upstream rnid takes them, and the namespace they parse into.

use super::*;

/// upstream rnid's options. `-d`, `-e`, `-V` and `-s` take any number of
/// paths (`nargs="*"`): the first is the option's value and the rest
/// follow it as positionals in the parser's trace.
pub static OPTIONS: OptionSpec = OptionSpec::new(
    Some(&crate::upstream_parsers::RNID),
    &[],
    &[
        // Rust-only: the older short name of --base256.
        Opt::flag("Z", ""),
    ],
);

/// `-S` without a message is upstream's `NO_MESSAGE`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum MessageArg {
    NoMessage,
    Text(String),
}

/// `-E` without a path is upstream's `NO_META`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum MetaArg {
    NoMeta,
    Path(String),
}

/// upstream's argparse namespace.
#[derive(Debug, Default)]
pub(super) struct Namespace {
    pub(super) config: Option<String>,
    pub(super) identity: Option<String>,
    pub(super) generate: Option<String>,
    pub(super) import_pub: Option<String>,
    pub(super) import_prv: Option<String>,
    pub(super) export_pub: bool,
    pub(super) export_prv: bool,
    pub(super) verbose: i32,
    pub(super) quiet: i32,
    pub(super) announce: Option<String>,
    pub(super) hash: Option<String>,
    pub(super) decrypt: Option<Vec<String>>,
    pub(super) encrypt: Option<Vec<String>>,
    pub(super) validate: Option<Vec<String>>,
    pub(super) sign: Option<Vec<String>>,
    pub(super) sign_message: Option<MessageArg>,
    pub(super) embed_meta: Option<MetaArg>,
    pub(super) meta_spec: Option<String>,
    pub(super) raw: bool,
    pub(super) write: Option<String>,
    pub(super) read: Option<String>,
    pub(super) force: bool,
    pub(super) stdout: bool,
    pub(super) request: bool,
    pub(super) no_cache: bool,
    pub(super) t: f64,
    pub(super) print_identity: bool,
    pub(super) print_private: bool,
    pub(super) base32: bool,
    pub(super) base64: bool,
    pub(super) base256: bool,
    pub(super) hex: bool,
    pub(super) meta: bool,
}

/// Python's truthiness of an optional string.
pub(super) fn truthy(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.is_empty())
}

pub(super) fn truthy_list(value: &Option<Vec<String>>) -> bool {
    value.as_ref().is_some_and(|v| !v.is_empty())
}

impl Namespace {
    /// The namespace argparse builds, from what the parser saw: the last
    /// occurrence of an option wins, and the arguments after a `nargs="*"`
    /// option are its values.
    pub(super) fn from_args(args: &Args) -> Self {
        let mut ns = Namespace {
            t: PATH_REQUEST_TIMEOUT,
            verbose: i32::from(args.verbosity),
            quiet: i32::from(args.quiet),
            ..Default::default()
        };
        let mut collecting: Option<&'static str> = None;
        for seen in &args.trace {
            match seen {
                Seen::Option(opt, value) => {
                    collecting = ns.set(opt, value.clone());
                }
                Seen::Missing(opt) => {
                    collecting = ns.set(opt, None);
                }
                Seen::Positional(value) => {
                    if let Some(list) = collecting.and_then(|dest| ns.list_mut(dest)) {
                        list.push(value.clone());
                    }
                }
                _ => collecting = None,
            }
        }
        ns
    }

    pub(super) fn list_mut(&mut self, dest: &str) -> Option<&mut Vec<String>> {
        match dest {
            "decrypt" => self.decrypt.as_mut(),
            "encrypt" => self.encrypt.as_mut(),
            "validate" => self.validate.as_mut(),
            "sign" => self.sign.as_mut(),
            _ => None,
        }
    }

    /// Store one option; returns the list it collects into, if any.
    pub(super) fn set(&mut self, opt: &Opt, value: Option<String>) -> Option<&'static str> {
        let name = if opt.long.is_empty() {
            opt.short
        } else {
            opt.long
        };
        let list = |value: Option<String>| Some(value.into_iter().collect::<Vec<_>>());
        match name {
            "config" => self.config = value,
            "identity" => self.identity = value,
            "generate" => self.generate = value,
            "import-pub" => self.import_pub = value,
            "import-prv" => self.import_prv = value,
            "export-pub" => self.export_pub = true,
            "export-prv" => self.export_prv = true,
            "announce" => self.announce = Some(value.unwrap_or_else(|| DEFAULT_ASPECTS.into())),
            "hash" => self.hash = value,
            "decrypt" => {
                self.decrypt = list(value);
                return Some("decrypt");
            }
            "encrypt" => {
                self.encrypt = list(value);
                return Some("encrypt");
            }
            "validate" => {
                self.validate = list(value);
                return Some("validate");
            }
            "sign" => {
                self.sign = list(value);
                return Some("sign");
            }
            "sign-message" => {
                self.sign_message = Some(value.map_or(MessageArg::NoMessage, MessageArg::Text))
            }
            "embed-meta" => self.embed_meta = Some(value.map_or(MetaArg::NoMeta, MetaArg::Path)),
            "meta-spec" => self.meta_spec = value,
            "raw" => self.raw = true,
            "write" => self.write = value,
            "read" => self.read = value,
            "force" => self.force = true,
            "stdout" => self.stdout = true,
            "request" => self.request = true,
            "no-cache" => self.no_cache = true,
            "t" => {
                if let Some(t) = value.as_deref().and_then(crate::argparse::python_float) {
                    self.t = t;
                }
            }
            "print-identity" => self.print_identity = true,
            "print-private" => self.print_private = true,
            "base32" => self.base32 = true,
            "base64" => self.base64 = true,
            "base256" | "Z" => self.base256 = true,
            "hex" => self.hex = true,
            "meta" => self.meta = true,
            _ => {}
        }
        None
    }

    pub(super) fn sign_message_truthy(&self) -> bool {
        match &self.sign_message {
            Some(MessageArg::NoMessage) => true,
            Some(MessageArg::Text(text)) => !text.is_empty(),
            None => false,
        }
    }

    pub(super) fn embed_meta_truthy(&self) -> bool {
        match &self.embed_meta {
            Some(MetaArg::NoMeta) => true,
            Some(MetaArg::Path(path)) => !path.is_empty(),
            None => false,
        }
    }

    pub(super) fn output(&self) -> &'static str {
        if self.base32 {
            "base32"
        } else if self.base64 {
            "base64"
        } else if self.base256 {
            "base256"
        } else if self.hex {
            "hex"
        } else {
            "bin"
        }
    }
}
