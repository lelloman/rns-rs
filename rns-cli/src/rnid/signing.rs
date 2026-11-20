//! Signing and validating files and messages.

use super::*;

impl Rnid {
    /// The required signer of `-V`: a string must be an identity hash.
    pub(super) fn signer_from<'a>(&mut self, target: &'a Target<'a>) -> Signer<'a> {
        match target {
            Target::Identity(identity) => Signer::Identity(identity),
            Target::Str(s) => {
                if s.chars().count() != 32 {
                    println!("Invalid identity hash length");
                    self.exit(R_INVALID_IDENTITY);
                }
                match fromhex(s) {
                    Ok(hash) => Signer::Hash(hash),
                    Err(e) => {
                        println!("Invalid identity hash: {e}");
                        self.exit(R_INVALID_IDENTITY);
                    }
                }
            }
            Target::None => Signer::None,
        }
    }

    pub(super) fn validate(&mut self, path: &str, target: &Target) {
        let msg_ext = format!(".{MSG_EXT}");
        let sig_ext = format!(".{SIG_EXT}");
        let validate_path = expanduser(path);
        let lower = validate_path.to_lowercase();
        let path_is_msgfile = lower.ends_with(&msg_ext);
        let path_is_sigfile = lower.ends_with(&sig_ext);
        let (signature_path, file_path) = if path_is_sigfile {
            let cut = validate_path.len() - sig_ext.len();
            (validate_path.clone(), validate_path[..cut].to_string())
        } else {
            (format!("{validate_path}{sig_ext}"), validate_path.clone())
        };
        if path_is_msgfile {
            return self.validate_message(&validate_path, target);
        }
        if !isfile(&file_path) {
            println!("The validation target \"{file_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if !isfile(&signature_path) {
            println!("No signature file exists for \"{file_path}\"");
            self.exit(R_NO_FILE);
        }
        let rsg = match fs::read(&signature_path) {
            Ok(rsg) => rsg,
            Err(e) => {
                println!(
                    "Could not detect rsg format: {}",
                    io_error(&e, &signature_path)
                );
                self.exit(R_UNKNOWN_ERROR);
            }
        };
        if let Ok(signature) = <&[u8; SIGLEN]>::try_from(rsg.as_slice()) {
            let Target::Identity(identity) = target else {
                println!(
                    "Cannot validate legacy rsg signatures without an explicit required identity"
                );
                self.exit(R_NO_IDENTITY);
            };
            let data = match fs::read(&file_path) {
                Ok(data) => data,
                Err(e) => {
                    println!("Could not validate signature: {}", io_error(&e, &file_path));
                    self.exit(R_READ_ERROR);
                }
            };
            if !identity.verify(signature, &data) {
                println!(
                    "Invalid signature {signature_path} for file {file_path}\nThis file was NOT signed by {}",
                    id_str(identity)
                );
                self.exit(R_INVALID_SIGNATURE);
            }
            println!(
                "Signature is valid, the file {file_path} was signed by {}",
                id_str(identity)
            );
            self.exit(R_OK);
        } else {
            let signer = self.signer_from(target);
            if let Err(e) = fs::File::open(&file_path) {
                println!("Could not read {file_path}: {}", io_error(&e, &file_path));
                self.exit(R_READ_ERROR);
            }
            match validate_rsg(&rsg, RsgMessage::File(&file_path), &signer) {
                Err(e) => {
                    println!("Error while validating {signature_path}: {e}");
                    self.exit(R_UNKNOWN_ERROR);
                }
                Ok((valid, _, signing_identity)) => {
                    let signer_description = if signer.is_truthy() {
                        format!("\nThis file was NOT signed by {}", signer.describe())
                    } else {
                        String::new()
                    };
                    if !valid {
                        println!(
                            "Invalid signature {signature_path} for file {file_path}{signer_description}"
                        );
                        self.exit(R_INVALID_SIGNATURE);
                    }
                    println!(
                        "Signature is valid, the file {file_path} was signed by {}",
                        signing_identity.as_ref().map_or("None".into(), id_str)
                    );
                }
            }
        }
    }

    pub(super) fn validate_message(&mut self, signature_path: &str, target: &Target) {
        if !isfile(signature_path) {
            println!("The signature file \"{signature_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        let rsg = match fs::read(signature_path) {
            Ok(rsg) => rsg,
            Err(e) => {
                println!("Could not read rsg: {}", io_error(&e, signature_path));
                self.exit(R_READ_ERROR);
            }
        };
        let signer = self.signer_from(target);
        if let Err(e) = self.try_validate_message(signature_path, &rsg, &signer) {
            println!("Error while validating {signature_path}: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    pub(super) fn try_validate_message(
        &mut self,
        signature_path: &str,
        rsg: &[u8],
        signer: &Signer,
    ) -> Result<(), String> {
        let contents = extract_signed_rsg_data(rsg);
        let message = match &contents {
            None => return Err("argument of type 'NoneType' is not iterable".into()),
            Some(Value::Map(entries)) => map_get(entries, "message"),
            Some(Value::Array(_) | Value::Str(_)) => None,
            Some(other) => return Err(not_iterable(other)),
        };
        let Some(message) = message else {
            println!("No embedded message in {signature_path}");
            self.exit(R_INVALID_SIGNATURE);
        };
        let message_bytes = match message {
            Value::Bin(b) => b.clone(),
            Value::Str(s) => s.clone().into_bytes(),
            other => {
                return Err(format!(
                    "Invalid input type <class '{}'> for rsg creation",
                    type_name(other)
                ))
            }
        };
        let (valid, signed_data, signing_identity) =
            validate_rsg(rsg, RsgMessage::Bytes(&message_bytes), signer)?;
        let signer_description = if signer.is_truthy() {
            format!("\nThe message was NOT signed by {}", signer.describe())
        } else {
            String::new()
        };
        if !valid {
            println!("Invalid signature in {signature_path}{signer_description}");
            self.exit(R_INVALID_SIGNATURE);
        }
        let Some(Value::Map(signed)) = signed_data else {
            return Err("invalid signed data".into());
        };
        if self.args.meta {
            println!("RSM Metadata\n============\n");
            if let Some(Value::Map(meta)) = map_get(&signed, "meta") {
                for (key, entry) in meta {
                    recurse(entry, &py_str(key), 1);
                }
            }
            println!("\nValidation\n==========");
        }
        let c = if !self.args.meta { ":" } else { "" };
        let f = if !self.args.meta { " following" } else { "" };
        println!(
            "\nSignature is valid, the{f} message was signed by {}{c}\n",
            signing_identity.as_ref().map_or("None".into(), id_str)
        );
        if self.args.meta {
            println!("Message\n=======\n");
        }
        match map_get(&signed, "message") {
            Some(Value::Bin(bytes)) => println!("{}", decode_utf8(bytes)?),
            Some(Value::Str(_)) => return Err("'str' object has no attribute 'decode'".into()),
            _ => return Err("'NoneType' object has no attribute 'decode'".into()),
        }
        self.exit(R_OK)
    }

    pub(super) fn sign(&mut self, path: &str, identity: &Identity) {
        let sign_path = expanduser(path);
        let rsg_path = format!("{sign_path}.{SIG_EXT}");
        let file_exists = isfile(&sign_path);
        let signature_exists = isfile(&rsg_path);
        let output = self.args.output();
        if identity.get_private_key().is_none() {
            println!("Cannot sign \"{sign_path}\", the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if !file_exists {
            println!("The file \"{sign_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if output == "bin" && signature_exists && !self.args.force {
            println!("The signature file \"{rsg_path}\" already exists, not overwriting");
            self.exit(R_FILE_EXISTS);
        }
        if let Err(e) = self.try_sign(&sign_path, &rsg_path, identity, output) {
            println!("Could not sign {sign_path}: {e}");
            self.exit(R_UNKNOWN_ERROR);
        }
    }

    pub(super) fn try_sign(
        &mut self,
        sign_path: &str,
        rsg_path: &str,
        identity: &Identity,
        output: &str,
    ) -> Result<(), String> {
        if self.args.raw {
            let data = fs::read(sign_path).map_err(|e| io_error(&e, sign_path))?;
            let signature = identity.sign(&data).map_err(|e| format!("{e:?}"))?;
            fs::write(rsg_path, signature).map_err(|e| io_error(&e, rsg_path))?;
        } else {
            fs::File::open(sign_path).map_err(|e| io_error(&e, sign_path))?;
            match create_rsg(identity, RsgMessage::File(sign_path), false, None, output)? {
                Rsg::Bin(bytes) => {
                    fs::write(rsg_path, bytes).map_err(|e| io_error(&e, rsg_path))?
                }
                Rsg::Text(text) => println!("\n{}\n", wrap_rsg(&text)),
            }
        }
        println!("Signed file {sign_path} with {}", id_str(identity));
        Ok(())
    }

    pub(super) fn sign_message(&mut self, identity: &Identity) -> ! {
        let Some(mut message) = self.args.sign_message.clone() else {
            println!("No message specified");
            self.exit(R_INVALID_ARGS);
        };
        let output = self.args.output();
        if output == "bin" && !truthy(&self.args.write) {
            println!("No write path specified");
            self.exit(R_INVALID_ARGS);
        }
        if identity.get_private_key().is_none() {
            println!("Cannot sign, the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if let Some(read) = self.args.read.clone().filter(|r| !r.is_empty()) {
            if message != MessageArg::NoMessage {
                println!(
                    "Both an input file and command-line provided message was specified, aborting"
                );
                self.exit(R_INVALID_ARGS);
            }
            let sign_path = expanduser(&read);
            if !isfile(&sign_path) {
                println!("The file {sign_path} does not exist");
                self.exit(R_NO_FILE);
            }
            // Read as text, outside upstream's error handling: a failure is
            // an uncaught exception there.
            match fs::read(&sign_path).map(String::from_utf8) {
                Ok(Ok(read)) => message = MessageArg::Text(read),
                Ok(Err(e)) => {
                    let _ = std::io::stdout().flush();
                    eprintln!(
                        "UnicodeDecodeError: {}",
                        utf8_error(e.as_bytes(), e.utf8_error())
                    );
                    self.exit(1);
                }
                Err(e) => {
                    let _ = std::io::stdout().flush();
                    eprintln!("{}", io_error(&e, &sign_path));
                    self.exit(1);
                }
            }
        }
        // Text is hashed as UTF-8; the editor's content is bytes already.
        let message_bytes = match &message {
            MessageArg::NoMessage => self.get_editor_content(),
            MessageArg::Text(text) => text.as_bytes().to_vec(),
        };
        if message_bytes.is_empty() {
            println!("No message specified");
            self.exit(R_INVALID_ARGS);
        }
        let mut meta = None;
        if self.args.embed_meta_truthy() {
            let meta_path = match self.args.embed_meta.clone() {
                Some(MetaArg::Path(path)) => expanduser(&path),
                _ => {
                    let _ = std::io::stdout().flush();
                    eprintln!("TypeError: expected str, bytes or os.PathLike object, not int");
                    self.exit(1);
                }
            };
            let meta_spec_path = match self.args.meta_spec.clone().filter(|s| !s.is_empty()) {
                Some(spec) => spec,
                None => format!("{meta_path}.spec"),
            };
            if !isfile(&meta_path) {
                println!("Metadata file {meta_path} does not exist");
                self.exit(R_NO_FILE);
            }
            let meta_spec_path = Some(meta_spec_path).filter(|p| isfile(p));
            let spec_info = meta_spec_path
                .as_deref()
                .map(|p| format!(" using spec from {p}"))
                .unwrap_or_default();
            println!("Embedding metadata from {meta_path}{spec_info}");
            match rsg_meta_from_file(&meta_path, meta_spec_path.as_deref()) {
                Ok(parsed) => meta = Some(parsed),
                Err(e) => {
                    println!("Could not load metadata from {meta_path}: {e}");
                    self.exit(R_UNKNOWN_ERROR);
                }
            }
        }
        if let Err(e) = self.try_sign_message(identity, &message_bytes, meta.as_ref(), output) {
            println!("Could not sign message: {e}");
        }
        self.exit(R_UNKNOWN_ERROR)
    }

    pub(super) fn try_sign_message(
        &mut self,
        identity: &Identity,
        message: &[u8],
        meta: Option<&Vec<(String, Entry)>>,
        output: &str,
    ) -> Result<(), String> {
        match create_rsg(identity, RsgMessage::Bytes(message), true, meta, output)? {
            Rsg::Bin(rsg) => {
                let sig_ext = format!(".{MSG_EXT}");
                let mut rsg_path = expanduser(self.args.write.as_deref().unwrap_or_default());
                if !rsg_path.ends_with(&sig_ext) {
                    rsg_path.push_str(&sig_ext);
                }
                if isfile(&rsg_path) && !self.args.force {
                    println!("The signature file \"{rsg_path}\" already exists, not overwriting");
                    self.exit(R_FILE_EXISTS);
                }
                fs::write(&rsg_path, rsg).map_err(|e| io_error(&e, &rsg_path))?;
                println!(
                    "Message signed with {} saved to {rsg_path}",
                    id_str(identity)
                );
                self.exit(R_OK);
            }
            Rsg::Text(text) => println!("\n{}\n", wrap_rsg(&text)),
        }
        println!("Message signed with {}", id_str(identity));
        self.exit(R_OK)
    }

    pub(super) fn get_editor_content(&mut self) -> Vec<u8> {
        let mut editor = std::env::var("EDITOR").unwrap_or_default();
        if editor.is_empty() {
            for fallback in ["nano", "vim", "vi"] {
                let found = process::Command::new("which")
                    .arg(fallback)
                    .stdout(process::Stdio::null())
                    .stderr(process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if found {
                    editor = fallback.into();
                    break;
                }
            }
        }
        if editor.is_empty() {
            println!("Could not launch editor");
            self.exit(R_READ_ERROR);
        }
        let tmp = std::env::temp_dir().join(format!("tmp-rnid-{}.tmp", process::id()));
        let tmp_name = tmp.to_string_lossy().into_owned();
        if let Err(e) = fs::write(&tmp, b"") {
            println!(
                "Could not get content from editor: {}",
                io_error(&e, &tmp_name)
            );
            self.exit(R_READ_ERROR);
        }
        let status = match process::Command::new(&editor).arg(&tmp).status() {
            Ok(status) => status,
            Err(e) => {
                println!(
                    "Could not get content from editor: {}",
                    io_error(&e, &editor)
                );
                self.exit(R_READ_ERROR);
            }
        };
        if !status.success() {
            println!(
                "Editor exited with error code {}",
                status.code().unwrap_or(-1)
            );
            let _ = fs::remove_file(&tmp);
            self.exit(R_READ_ERROR);
        }
        let content = fs::read(&tmp);
        let _ = fs::remove_file(&tmp);
        match content {
            Ok(content) => content,
            Err(e) => {
                println!(
                    "Could not get content from editor: {}",
                    io_error(&e, &tmp_name)
                );
                self.exit(R_READ_ERROR);
            }
        }
    }
}
