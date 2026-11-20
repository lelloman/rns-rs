//! Identities: recalling, importing, announcing, exporting and printing them.

use super::*;

impl Rnid {
    /// `RNS.Identity.recall(hash)`, or with `from_identity_hash` by the
    /// identity's own hash.
    pub(super) fn recall(&self, hash: &[u8], from_identity_hash: bool) -> Option<Identity> {
        let entries = self.node.as_ref()?.known_destinations().ok()?;
        let entry = entries.iter().find(|e| {
            if from_identity_hash {
                e.identity_hash[..] == *hash
            } else {
                e.dest_hash[..] == *hash
            }
        })?;
        Identity::from_public_key(&entry.public_key).ok()
    }

    pub(super) fn recall_any(&self, hash: &[u8]) -> Option<Identity> {
        self.recall(hash, false).or_else(|| self.recall(hash, true))
    }

    pub(super) fn get_operating_identity(
        &mut self,
        allow_none: bool,
        no_cache: bool,
    ) -> Option<Identity> {
        if let Some(path) = self.args.generate.clone().filter(|p| !p.is_empty()) {
            // Before any Reticulum instance sets the log level, so at
            // upstream's default this line is not shown.
            let identity = pylog::new_identity();
            if !self.args.force && isfile(&path) {
                println!("Identity file {path} already exists. Not overwriting.");
                self.exit(R_FILE_EXISTS);
            }
            key_to_file(&identity.get_private_key().unwrap_or([0; KEYSIZE]), &path);
            println!("New identity {} written to {path}", id_str(&identity));
            return Some(identity);
        }
        if let Some(given) = self.args.identity.clone().filter(|p| !p.is_empty()) {
            let load_path = expanduser(&given);
            if isfile(&load_path) {
                match identity_from_file(&load_path) {
                    Some(identity) => {
                        println!("Loaded Identity {} from {load_path}", id_str(&identity));
                        return Some(identity);
                    }
                    None => {
                        println!("Loaded Identity None from {load_path}");
                        println!("Could not load Identity from specified file: 'NoneType' object has no attribute 'get_private_key'");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            } else if no_cache {
                if allow_none {
                    return None;
                }
                println!("Could not resolve identity");
                self.exit(R_NO_IDENTITY);
            } else if given.chars().count() == 32 {
                return self.recall_identity(&given, allow_none);
            }
            return None;
        }
        if truthy(&self.args.import_pub) || truthy(&self.args.import_prv) {
            let (spec, private) = match &self.args.import_pub {
                Some(spec) if !spec.is_empty() => (spec.clone(), false),
                _ => (self.args.import_prv.clone().unwrap_or_default(), true),
            };
            let Some(bytes) = self.import_bytes(&spec) else {
                let which = if private { "private" } else { "public" };
                println!("Could not decode specified data to a valid {which} Reticulum Identity");
                self.exit(R_INVALID_IDENTITY);
            };
            if private {
                return Some(Identity::from_private_key(&bytes));
            }
            return match Identity::from_public_key(&bytes) {
                Ok(identity) => Some(identity),
                Err(e) => {
                    println!("Could not create Reticulum identity from specified data: {e:?}");
                    self.exit(R_INVALID_IDENTITY);
                }
            };
        }
        None
    }

    /// The key bytes `-m`/`-M` names: a file of exactly the key's size,
    /// else hex, base32 or base64 text of it.
    pub(super) fn import_bytes(&self, spec: &str) -> Option<[u8; KEYSIZE]> {
        let import_path = expanduser(spec);
        if isfile(&import_path) {
            if let Ok(input) = fs::read(&import_path) {
                if let Ok(key) = <[u8; KEYSIZE]>::try_from(input) {
                    println!("Reticulum Identity imported from {import_path}");
                    return Some(key);
                }
            }
        }
        if spec.chars().count() == KEYSIZE * 2 {
            if let Ok(bytes) = fromhex(spec) {
                if !bytes.is_empty() {
                    println!("Reticulum Identity imported from hex input");
                    // Hex with spaces in it decodes to fewer bytes; upstream
                    // then fails creating the identity.
                    return bytes.try_into().ok();
                }
            }
        }
        if let Some(key) = b32decode(spec).and_then(|b| b.try_into().ok()) {
            println!("Reticulum Identity imported from base32 input");
            return Some(key);
        }
        if let Some(key) = urlsafe_b64decode(spec).and_then(|b| b.try_into().ok()) {
            println!("Reticulum Identity imported from base64 input");
            return Some(key);
        }
        None
    }

    /// `-i` with a 32-character hash: recalled from what the instance
    /// knows, or with `-R` requested from the network.
    pub(super) fn recall_identity(&mut self, given: &str, allow_none: bool) -> Option<Identity> {
        match self.try_recall_identity(given, allow_none) {
            Ok(identity) => identity,
            Err(e) => {
                println!("Invalid hexadecimal hash provided: {e}");
                self.exit(R_INVALID_IDENTITY);
            }
        }
    }

    pub(super) fn try_recall_identity(
        &mut self,
        given: &str,
        allow_none: bool,
    ) -> Result<Option<Identity>, String> {
        self.ensure_reticulum()?;
        let requested_hash = fromhex(given)?;
        let mut identity = self.recall_any(&requested_hash);
        match &identity {
            None if allow_none && !self.args.request => return Ok(None),
            None if !self.args.request => {
                println!(
                    "Could not recall Identity for {}.",
                    prettyhexrep(&requested_hash)
                );
                println!("You can query the network for unknown Identities with the -R option.");
                self.exit(R_NO_IDENTITY);
            }
            None => {
                let id_destination_hash =
                    hash_from_name_and_identity(DEFAULT_ASPECTS, &requested_hash);
                if let Some(node) = &self.node {
                    if let Ok(hash) = <[u8; 16]>::try_from(requested_hash.as_slice()) {
                        let _ = node.request_path(&rns_net::DestHash(hash));
                    }
                    let _ = node.request_path(&rns_net::DestHash(id_destination_hash));
                }
                let message = format!(
                    "Requesting unknown Identity for {}",
                    prettyhexrep(&requested_hash)
                );
                spin(
                    || self.recall_any(&requested_hash).is_some(),
                    &message,
                    Some(self.args.t),
                );
                match self.recall_any(&requested_hash) {
                    None => {
                        println!("Identity request timed out");
                        if !allow_none {
                            self.exit(R_NO_IDENTITY);
                        }
                        return Ok(None);
                    }
                    Some(received) => {
                        println!(
                            "Received Identity {} for destination {} from the network",
                            id_str(&received),
                            prettyhexrep(&requested_hash)
                        );
                        identity = Some(received);
                    }
                }
            }
            Some(recalled) => {
                let ident_str = id_str(recalled);
                let hash_str = prettyhexrep(&requested_hash);
                if ident_str == hash_str {
                    println!("Recalled Identity {ident_str}");
                } else {
                    println!("Recalled Identity {ident_str} for destination {hash_str}");
                }
            }
        }
        if let (Some(identity), Some(node)) = (&identity, &self.node) {
            let _ = node.retain_identity(&rns_net::IdentityHash(*identity.hash()));
        }
        Ok(identity)
    }

    pub(super) fn announce(&mut self, identity: &Identity) {
        if let Err(e) = self.try_announce(identity) {
            println!("An error ocurred while attempting to send the announce: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    pub(super) fn try_announce(&mut self, identity: &Identity) -> Result<(), String> {
        let announce = self.args.announce.clone().unwrap_or_default();
        self.ensure_reticulum()?;
        let mut parts = announce.split('.');
        let app_name = parts.next().unwrap_or_default().to_string();
        let aspects: Vec<&str> = parts.collect();
        if aspects.is_empty() {
            println!("Invalid destination aspects specified");
            self.exit(R_INVALID_ASPECTS);
        }
        let Some(private_key) = identity.get_private_key() else {
            println!("Cannot announce this destination, since the private key is not held");
            self.exit(R_NO_PRVKEY);
        };
        let node = self
            .node
            .as_ref()
            .ok_or_else(|| "the instance is not running".to_string())?;
        let destination = rns_net::Destination::single_in(
            &app_name,
            &aspects,
            rns_net::IdentityHash(*identity.hash()),
        );
        node.register_destination_with_proof(&destination, Some(private_key))
            .map_err(|_| "the instance is not running".to_string())?;
        println!(
            "Announcing {announce} destination {} for identity {}",
            prettyhexrep(&destination.hash.0),
            id_str(identity)
        );
        node.announce_queued(&destination, identity, None)
            .map_err(|_| "the instance is not running".to_string())?;
        std::thread::sleep(Duration::from_millis(250));
        Ok(())
    }

    pub(super) fn write_identity(&mut self, identity: &Identity) {
        let mut wp = expanduser(self.args.write.as_deref().unwrap_or_default());
        if let (Some(private), true) = (identity.get_private_key(), self.args.export_prv) {
            if !isfile(&wp) || self.args.force {
                key_to_file(&private, &wp);
                println!("Wrote private identity to {wp}");
            } else {
                println!("File {wp} already exists, not overwriting");
                self.exit(R_FILE_EXISTS);
            }
        } else if let Some(public) = identity.get_public_key() {
            if !wp.to_lowercase().ends_with(&format!(".{PUB_EXT}")) {
                wp.push_str(&format!(".{PUB_EXT}"));
            }
            if !isfile(&wp) || self.args.force {
                key_to_file(&public, &wp);
                println!("Wrote public identity to {wp}");
            } else {
                println!("File {wp} already exists, not overwriting");
                self.exit(R_FILE_EXISTS);
            }
        } else {
            println!("Identity holds neither a public nor private key");
            self.exit(R_NO_KEYS);
        }
    }

    pub(super) fn encode_key(&self, key: &[u8]) -> String {
        if self.args.base64 {
            urlsafe_b64encode(key)
        } else if self.args.base32 {
            b32encode(key)
        } else {
            hexrep(key)
        }
    }

    pub(super) fn print_identity_information(&self, identity: &Identity) {
        println!("Identity Hash : {}", id_str(identity));
        let public = identity.get_public_key().unwrap_or([0; KEYSIZE]);
        println!("Public Key    : {}", self.encode_key(&public));
        if let Some(private) = identity.get_private_key() {
            if self.args.print_private {
                println!("Private Key   : {}", self.encode_key(&private));
            } else {
                println!("Private Key   : Hidden");
            }
        }
    }

    pub(super) fn print_hash_information(&mut self, target: &Target) {
        let hash = self.args.hash.clone().unwrap_or_default();
        let (identity_hash, destination) = match target {
            Target::None => {
                println!("Invalid identity");
                self.exit(R_INVALID_IDENTITY);
            }
            Target::Str(s) => {
                if s.chars().count() != 32 {
                    println!("Invalid identity hash length");
                    self.exit(R_INVALID_IDENTITY);
                }
                match fromhex(s) {
                    Ok(hash) => (hash, None),
                    Err(e) => {
                        println!("Invalid identity: {e}");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            }
            Target::Identity(identity) => {
                // `str(RNS.Destination(identity, OUT, SINGLE, app, *aspects))`.
                let destination_hash = hash_from_name_and_identity(&hash, identity.hash());
                let full = format!(
                    "<{hash}.{}:{}>",
                    hexrep(identity.hash()),
                    hexrep(&destination_hash)
                );
                (identity.hash().to_vec(), Some(full))
            }
        };
        let destination_hash = hash_from_name_and_identity(&hash, &identity_hash);
        println!(
            "The {hash} destination for this Identity is {}",
            prettyhexrep(&destination_hash)
        );
        if let Some(destination) = destination {
            println!("The full destination specifier is {destination}");
        }
    }

    pub(super) fn export_pub_identity(&mut self, identity: &Identity) {
        match identity.get_public_key() {
            None => {
                println!("Identity doesn't hold a public key, cannot export");
                self.exit(R_NO_PUBKEY);
            }
            Some(key) => println!("Public Identity Keys  : {}", self.encode_key(&key)),
        }
    }

    pub(super) fn export_prv_identity(&mut self, identity: &Identity) {
        match identity.get_private_key() {
            None => {
                println!("Identity doesn't hold a private key, cannot export");
                self.exit(R_NO_PRVKEY);
            }
            Some(key) => println!("Private Identity Keys : {}", self.encode_key(&key)),
        }
    }
}
