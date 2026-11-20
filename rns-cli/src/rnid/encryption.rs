//! Encrypting and decrypting files.

use super::*;

impl Rnid {
    pub(super) fn encrypt(&mut self, path: &str, identity: &Identity) {
        let encrypt_path = expanduser(path);
        let rfe_path = match self.args.write.clone().filter(|w| !w.is_empty()) {
            Some(write) => write,
            None => format!("{encrypt_path}.{ENCRYPT_EXT}"),
        };
        if identity.get_public_key().is_none() {
            println!("Cannot encrypt \"{encrypt_path}\", the identity does not hold a public key");
            self.exit(R_NO_PUBKEY);
        }
        if !isfile(&encrypt_path) {
            println!("The file \"{encrypt_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if isfile(&rfe_path) && !self.args.force {
            println!("The encryption output file \"{rfe_path}\" already exists, not overwriting");
            self.exit(R_FILE_EXISTS);
        }
        let mut input = match fs::File::open(&encrypt_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError reading {encrypt_path} for encryption: {}",
                    io_error(&e, &encrypt_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut output = match fs::File::create(&rfe_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError writing encrypted output to {rfe_path}: {}",
                    io_error(&e, &rfe_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut wrote = 0usize;
        loop {
            let chunk = match read_chunk(&mut input, ENC_CHUNK) {
                Ok(chunk) => chunk,
                Err(e) => {
                    println!(
                        "\nError writing encrypted output to {rfe_path}: {}",
                        io_error(&e, &encrypt_path)
                    );
                    self.exit(R_WRITE_ERROR);
                }
            };
            let done = chunk.is_empty();
            if !done {
                let written = identity
                    .encrypt(&chunk, &mut OsRng)
                    .map_err(|e| format!("{e:?}"))
                    .and_then(|token| {
                        output
                            .write_all(&token)
                            .map(|_| token.len())
                            .map_err(|e| io_error(&e, &rfe_path))
                    });
                match written {
                    Ok(n) => wrote += n,
                    Err(e) => {
                        println!("\nError writing encrypted output to {rfe_path}: {e}");
                        self.exit(R_WRITE_ERROR);
                    }
                }
            }
            print!("\rWrote {} to {rfe_path}   ", prettysize(wrote as f64, "B"));
            if done {
                break;
            }
        }
        println!(
            "\nFile {encrypt_path} encrypted for {} to {rfe_path}",
            id_str(identity)
        );
    }

    pub(super) fn decrypt(&mut self, path: &str, identity: &Identity) {
        let enc_ext = format!(".{ENCRYPT_EXT}");
        let rfe_path = expanduser(path);
        if !rfe_path.ends_with(&enc_ext) {
            println!("The file {rfe_path} does not appear to be a Reticulum encrypted file");
            self.exit(R_INVALID_FILE);
        }
        let decrypt_path = match self.args.write.clone().filter(|w| !w.is_empty()) {
            Some(write) => expanduser(&write),
            None => rfe_path[..rfe_path.len() - enc_ext.len()].to_string(),
        };
        if decrypt_path.is_empty() {
            println!("Invalid output filename");
            self.exit(R_INVALID_FILE);
        }
        if identity.get_private_key().is_none() {
            println!("Cannot decrypt \"{rfe_path}\", the identity does not hold a private key");
            self.exit(R_NO_PRVKEY);
        }
        if !isfile(&rfe_path) {
            println!("The file \"{rfe_path}\" does not exist");
            self.exit(R_NO_FILE);
        }
        if isfile(&decrypt_path) && !self.args.force {
            println!(
                "The decryption output file \"{decrypt_path}\" already exists, not overwriting"
            );
            self.exit(R_FILE_EXISTS);
        }
        let mut input = match fs::File::open(&rfe_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError reading {rfe_path} for decryption: {}",
                    io_error(&e, &rfe_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut output = match fs::File::create(&decrypt_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "\nError writing decrypted output to {decrypt_path}: {}",
                    io_error(&e, &decrypt_path)
                );
                self.exit(R_WRITE_ERROR);
            }
        };
        let mut wrote = 0usize;
        loop {
            let chunk = match read_chunk(&mut input, DEC_CHUNK) {
                Ok(chunk) => chunk,
                Err(e) => {
                    println!(
                        "\nError writing decrypted output to {decrypt_path}: {}",
                        io_error(&e, &rfe_path)
                    );
                    self.exit(R_WRITE_ERROR);
                }
            };
            if chunk.is_empty() {
                break;
            }
            // `if not decrypted`: an empty plaintext reads as a failure too.
            match identity.decrypt(&chunk) {
                Ok(plain) if !plain.is_empty() => {
                    if let Err(e) = output.write_all(&plain) {
                        println!(
                            "\nError writing decrypted output to {decrypt_path}: {}",
                            io_error(&e, &decrypt_path)
                        );
                        self.exit(R_WRITE_ERROR);
                    }
                    wrote += plain.len();
                }
                _ => {
                    println!("The provided identity could not decrypt the file");
                    self.exit(R_DECRYPT_FAILED);
                }
            }
            print!(
                "\rWrote {} to {decrypt_path}   ",
                prettysize(wrote as f64, "B")
            );
        }
        println!("\nFile {rfe_path} decrypted to {decrypt_path}");
    }
}
