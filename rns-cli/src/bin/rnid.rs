//! rnid - Reticulum Identity Management
//!
//! Generate, inspect, and manage RNS identities. Standalone tool, no RPC needed.

use std::fs;
use std::path::Path;
use std::process;

use rns_crypto::identity::Identity;
use rns_crypto::OsRng;
use rns_core::destination::destination_hash;
use rns_cli::args::Args;
use rns_cli::format::prettyhexrep;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("rnid {}", VERSION);
        return;
    }

    if args.has("help") || args.has("h") {
        print_usage();
        return;
    }

    // Generate new identity
    if let Some(file) = args.get("g") {
        generate_identity(file);
        return;
    }

    // Import from hex
    if let Some(hex_str) = args.get("m") {
        import_from_hex(hex_str, &args);
        return;
    }

    // Load identity from file or hash
    if let Some(file_or_hash) = args.get("i") {
        let path = Path::new(file_or_hash);
        if path.exists() {
            inspect_identity_file(path, &args);
        } else {
            // Treat as hash
            println!("Hash: {}", file_or_hash);
        }
        return;
    }

    print_usage();
}

fn generate_identity(file: &str) {
    let path = Path::new(file);
    if path.exists() {
        eprintln!("File already exists: {}", file);
        process::exit(1);
    }

    let identity = Identity::new(&mut OsRng);
    let prv_key = identity.get_private_key().expect("generated identity has private key");

    fs::write(path, &prv_key).unwrap_or_else(|e| {
        eprintln!("Error writing identity: {}", e);
        process::exit(1);
    });

    println!("Generated new identity");
    println!("  Hash : {}", prettyhexrep(identity.hash()));
    println!("  Saved: {}", file);
}

fn inspect_identity_file(path: &Path, args: &Args) {
    let data = fs::read(path).unwrap_or_else(|e| {
        eprintln!("Error reading file: {}", e);
        process::exit(1);
    });

    let identity = if data.len() == 64 {
        // Private key (32 enc + 32 sig)
        let mut key = [0u8; 64];
        key.copy_from_slice(&data);
        Identity::from_private_key(&key)
    } else if data.len() == 64 + 64 {
        // Could be full private key (enc_prv + enc_pub + sig_prv + sig_pub) - unlikely
        // or public key only
        let mut key = [0u8; 64];
        key.copy_from_slice(&data[..64]);
        Identity::from_private_key(&key)
    } else if data.len() == 32 + 32 {
        // Public keys only (32 enc_pub + 32 sig_pub)
        let mut key = [0u8; 64];
        key.copy_from_slice(&data);
        Identity::from_public_key(&key)
    } else {
        eprintln!("Unknown identity file format ({} bytes)", data.len());
        process::exit(1);
    };

    println!("Identity <{}>", prettyhexrep(identity.hash()));
    println!("  Hash      : {}", prettyhexrep(identity.hash()));

    let show_private = args.has("P");
    let show_public = args.has("p") || show_private;

    if show_public {
        if let Some(pub_key) = identity.get_public_key() {
            println!("  Public key: {}", prettyhexrep(&pub_key));
        }
    }

    if show_private {
        if let Some(prv_key) = identity.get_private_key() {
            println!("  Private key: {}", prettyhexrep(&prv_key));
        } else {
            println!("  Private key: (not available)");
        }
    }

    // Compute destination hash if -H is given
    if let Some(aspects_str) = args.get("H") {
        let parts: Vec<&str> = aspects_str.split('.').collect();
        if parts.len() >= 2 {
            let app_name = parts[0];
            let aspects: Vec<&str> = parts[1..].to_vec();
            let dest_hash = destination_hash(app_name, &aspects, Some(identity.hash()));
            println!("  Dest hash : {}", prettyhexrep(&dest_hash));
        } else {
            eprintln!("  Aspects must be in format: app_name.aspect1.aspect2");
        }
    }

    // Encrypt file
    if let Some(file) = args.get("e") {
        let plaintext = fs::read(file).unwrap_or_else(|e| {
            eprintln!("Error reading file: {}", e);
            process::exit(1);
        });
        let ciphertext = identity.encrypt(&plaintext, &mut OsRng).unwrap_or_else(|e| {
            eprintln!("Encryption failed: {:?}", e);
            process::exit(1);
        });
        let out_file = format!("{}.enc", file);
        fs::write(&out_file, &ciphertext).unwrap_or_else(|e| {
            eprintln!("Error writing: {}", e);
            process::exit(1);
        });
        println!("  Encrypted {} -> {}", file, out_file);
    }

    // Decrypt file
    if let Some(file) = args.get("d") {
        let ciphertext = fs::read(file).unwrap_or_else(|e| {
            eprintln!("Error reading file: {}", e);
            process::exit(1);
        });
        match identity.decrypt(&ciphertext) {
            Ok(plaintext) => {
                let out_file = if file.ends_with(".enc") {
                    file[..file.len() - 4].to_string()
                } else {
                    format!("{}.dec", file)
                };
                fs::write(&out_file, &plaintext).unwrap_or_else(|e| {
                    eprintln!("Error writing: {}", e);
                    process::exit(1);
                });
                println!("  Decrypted {} -> {}", file, out_file);
            }
            Err(e) => {
                eprintln!("  Decryption failed: {:?}", e);
                process::exit(1);
            }
        }
    }

    // Sign file
    if let Some(file) = args.get("s") {
        let data = fs::read(file).unwrap_or_else(|e| {
            eprintln!("Error reading file: {}", e);
            process::exit(1);
        });
        match identity.sign(&data) {
            Ok(sig) => {
                let out_file = format!("{}.sig", file);
                fs::write(&out_file, &sig).unwrap_or_else(|e| {
                    eprintln!("Error writing: {}", e);
                    process::exit(1);
                });
                println!("  Signed {} -> {}", file, out_file);
            }
            Err(e) => {
                eprintln!("  Signing failed: {:?}", e);
                process::exit(1);
            }
        }
    }

    // Verify signature
    if let Some(sig_file) = args.get("V") {
        let sig_data = fs::read(sig_file).unwrap_or_else(|e| {
            eprintln!("Error reading signature: {}", e);
            process::exit(1);
        });
        if sig_data.len() != 64 {
            eprintln!("  Invalid signature (expected 64 bytes, got {})", sig_data.len());
            process::exit(1);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_data);

        // Read the data file (remove .sig extension)
        let data_file = if sig_file.ends_with(".sig") {
            &sig_file[..sig_file.len() - 4]
        } else {
            eprintln!("  Cannot determine data file (expected .sig extension)");
            process::exit(1);
        };

        let data = fs::read(data_file).unwrap_or_else(|e| {
            eprintln!("Error reading {}: {}", data_file, e);
            process::exit(1);
        });

        if identity.verify(&sig, &data) {
            println!("  Signature valid");
        } else {
            println!("  Signature INVALID");
            process::exit(1);
        }
    }

    // Export as hex
    if args.has("x") {
        if let Some(prv_key) = identity.get_private_key() {
            println!("{}", prettyhexrep(&prv_key));
        } else if let Some(pub_key) = identity.get_public_key() {
            println!("{}", prettyhexrep(&pub_key));
        }
    }

    // Export as base64
    if args.has("b") {
        if let Some(prv_key) = identity.get_private_key() {
            println!("{}", base64_encode(&prv_key));
        } else if let Some(pub_key) = identity.get_public_key() {
            println!("{}", base64_encode(&pub_key));
        }
    }
}

fn import_from_hex(hex_str: &str, args: &Args) {
    let bytes = match parse_hex(hex_str) {
        Some(b) => b,
        None => {
            eprintln!("Invalid hex string");
            process::exit(1);
        }
    };

    if bytes.len() == 64 {
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        let identity = Identity::from_private_key(&key);
        println!("Identity <{}>", prettyhexrep(identity.hash()));

        // Save to file if -w is provided
        if let Some(file) = args.get("w") {
            fs::write(file, &key).unwrap_or_else(|e| {
                eprintln!("Error writing: {}", e);
                process::exit(1);
            });
            println!("  Saved to {}", file);
        }
    } else {
        eprintln!("Expected 64 bytes (128 hex chars), got {} bytes", bytes.len());
        process::exit(1);
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }
    Some(bytes)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }
    result
}

fn print_usage() {
    println!("Usage: rnid [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -g FILE            Generate new identity and save to file");
    println!("  -i FILE            Load and inspect identity from file");
    println!("  -p                 Print public key");
    println!("  -P                 Print private key (implies -p)");
    println!("  -H APP.ASPECT      Compute destination hash");
    println!("  -e FILE            Encrypt file with identity");
    println!("  -d FILE            Decrypt file with identity");
    println!("  -s FILE            Sign file with identity");
    println!("  -V FILE.sig        Verify signature");
    println!("  -m HEX             Import identity from hex string");
    println!("  -w FILE            Write imported identity to file");
    println!("  -x                 Export as hex");
    println!("  -b                 Export as base64");
    println!("  --version          Print version and exit");
    println!("  --help, -h         Print this help");
}
