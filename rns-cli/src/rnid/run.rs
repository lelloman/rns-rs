//! Running rnid: checking the arguments and dispatching to an action.

use super::*;

impl Rnid {
    pub(super) fn exit(&mut self, code: i32) -> ! {
        let _ = std::io::stdout().flush();
        if let Some(node) = self.node.take() {
            node.shutdown();
        }
        process::exit(code)
    }

    pub(super) fn validate_args(&mut self) {
        let a = &self.args;
        let ops = [
            truthy_list(&a.encrypt),
            truthy_list(&a.decrypt),
            truthy_list(&a.validate),
            truthy_list(&a.sign),
            a.sign_message_truthy(),
        ]
        .iter()
        .filter(|o| **o)
        .count();
        if ops > 1 {
            println!("This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation");
            self.exit(1);
        }
        let g = [
            truthy(&a.import_pub),
            truthy(&a.import_prv),
            truthy(&a.identity),
            truthy(&a.generate),
        ]
        .iter()
        .filter(|o| **o)
        .count();
        if g > 1 {
            println!("The -i, -g, -m and -M args are mutually exclusive");
            self.exit(1);
        }
        let g = [a.base64, a.base32, a.base256, a.hex]
            .iter()
            .filter(|o| **o)
            .count();
        if g > 1 {
            println!("The -b, -B, --hex and --base256 args are mutually exclusive");
            self.exit(1);
        }
    }

    pub(super) fn main(&mut self, usage_name: &str) -> ! {
        self.validate_args();
        let a = &self.args;
        let op_requires_identity = truthy_list(&a.sign)
            || a.sign_message_truthy()
            || truthy_list(&a.encrypt)
            || truthy_list(&a.decrypt)
            || truthy(&a.announce)
            || truthy(&a.write)
            || a.print_identity
            || a.export_pub
            || a.export_prv;
        let no_cache = a.no_cache;
        let identity = self.get_operating_identity(!op_requires_identity, no_cache);
        if identity.is_none() && op_requires_identity {
            println!("Could not get working identity");
            self.exit(R_NO_IDENTITY);
        }
        let mut op = false;
        // `identity or args.identity`.
        let target = match (&identity, &self.args.identity) {
            (Some(identity), _) => Target::Identity(identity),
            (None, Some(s)) if !s.is_empty() => Target::Str(s.clone()),
            _ => Target::None,
        };
        let id = identity.as_ref();
        if self.args.print_identity {
            self.print_identity_information(id.expect("required"));
            op = true;
        }
        if self.args.export_pub {
            self.export_pub_identity(id.expect("required"));
            op = true;
        }
        if self.args.export_prv {
            self.export_prv_identity(id.expect("required"));
            op = true;
        }
        if truthy(&self.args.hash) {
            self.print_hash_information(&target);
            op = true;
        }
        if truthy(&self.args.announce) {
            self.announce(id.expect("required"));
            op = true;
        }
        if truthy_list(&self.args.validate) {
            for path in self.args.validate.clone().unwrap_or_default() {
                self.validate(&path, &target);
            }
            self.exit(R_OK);
        }
        if truthy_list(&self.args.sign) {
            for path in self.args.sign.clone().unwrap_or_default() {
                self.sign(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if self.args.sign_message_truthy() {
            self.sign_message(id.expect("required"));
        }
        if truthy_list(&self.args.encrypt) {
            for path in self.args.encrypt.clone().unwrap_or_default() {
                self.encrypt(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if truthy_list(&self.args.decrypt) {
            for path in self.args.decrypt.clone().unwrap_or_default() {
                self.decrypt(&path, id.expect("required"));
            }
            self.exit(R_OK);
        }
        if truthy(&self.args.write) {
            self.write_identity(id.expect("required"));
            op = true;
        }
        if truthy(&self.args.generate) {
            op = true;
        }
        if !op {
            crate::argparse::print_help("rnid", usage_name);
        }
        self.exit(R_OK)
    }

    pub(super) fn ensure_reticulum(&mut self) -> Result<(), String> {
        if self.node.is_some() {
            return Ok(());
        }
        let mut level = 4;
        if self.args.verbose != 0 || self.args.quiet != 0 {
            level = level + self.args.verbose - self.args.quiet;
        }
        // `RNS.Reticulum(configdir, loglevel=...)` with
        // `RNS.compact_log_fmt`.
        pylog::install_utility_logging(self.args.config.as_deref(), Some(level), 0, true);
        let config_dir =
            rns_net::storage::resolve_config_dir(self.args.config.as_deref().map(Path::new));
        let node = match rns_net::RnsNode::connect_shared_from_config(
            Some(&config_dir),
            Box::new(NoCallbacks),
        ) {
            Ok(node) => node,
            Err(_) => rns_net::RnsNode::from_config(Some(&config_dir), Box::new(NoCallbacks))
                .map_err(|e| e.to_string())?,
        };
        self.node = Some(node);
        pylog::set_loglevel(level);
        if self.args.stdout {
            pylog::set_loglevel(pylog::LOG_NONE);
        }
        // Reticulum's own handler: exit quietly with 0.
        crate::stdout::exit_on_interrupt(0);
        Ok(())
    }
}
