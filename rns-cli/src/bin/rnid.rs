//! rnid - Reticulum identity, encryption and signature utility.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{self, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_cli::args::Args;
use rns_cli::format::{
    b256_to_bytes, b256rep, base32_decode, base32_encode, prettyb256rep, prettyhexrep,
};
use rns_core::destination::destination_hash;
use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::sha256;
use rns_crypto::OsRng;
use rns_net::event::KnownDestinationEntry;
use rns_net::rpc::derive_auth_key;
use rns_net::{config, storage, RpcAddr, RpcClient};

const VERSION: &str = env!("FULL_VERSION");
const LARGE_FILE_WARN: u64 = 16 * 1024 * 1024;
const DEFAULT_ASPECTS: &str = "rns.id";
const PUB_EXT: &str = "pub";
const SIG_EXT: &str = "rsg";
const MSG_EXT: &str = "rsm";
const ENCRYPT_EXT: &str = "rfe";
const SIG_LEN: usize = 64;
const RSG_ASCII_HEADER: &str = "#### Start of rsg data ";
const RSG_ASCII_FOOTER: &str = " End of rsg data ####";
const RSG_ASCII_ROW_WIDTH: usize = 64;

enum IdentityRef {
    Identity(Identity),
    Hash([u8; 16]),
}

#[derive(Clone, Copy)]
enum RsgOutputFormat {
    Binary,
    Hex,
    Base32,
    Base256,
    Base64,
}

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

    validate_args(&args).unwrap_or_else(|e| die(&e, 1));

    let needs_identity = args.has("p")
        || args.has("print-identity")
        || args.has("x")
        || args.has("export-pub")
        || args.has("X")
        || args.has("export-prv")
        || args.has("s")
        || args.has("sign")
        || args.has("S")
        || args.has("sign-message")
        || args.has("e")
        || args.has("encrypt")
        || args.has("d")
        || args.has("decrypt")
        || (args.has("w")
            && !args.has("e")
            && !args.has("encrypt")
            && !args.has("d")
            && !args.has("decrypt")
            && !args.has("s")
            && !args.has("sign")
            && !args.has("S")
            && !args.has("sign-message"))
        || args.has("generate")
        || args.has("g");

    let identity_ref = load_identity_ref(&args, !needs_identity).unwrap_or_else(|e| die(&e, 1));
    let mut operated = false;

    if args.has("p") || args.has("print-identity") {
        let identity = require_identity(identity_ref.as_ref());
        print_identity_information(&args, identity);
        operated = true;
    }

    if let Some(aspects) = args.get("H").or_else(|| args.get("hash")) {
        print_hash_information(aspects, identity_ref.as_ref()).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("x") || args.has("export-pub") {
        let identity = require_identity(identity_ref.as_ref());
        export_public_identity(&args, identity).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("X") || args.has("export-prv") {
        let identity = require_identity(identity_ref.as_ref());
        export_private_identity(&args, identity).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("V") || args.has("validate") {
        let paths = operation_paths(&args, "V", "validate").unwrap_or_else(|e| die(&e, 1));
        validate_signatures(&paths, identity_ref.as_ref(), &args).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("s") || args.has("sign") {
        let identity = require_identity(identity_ref.as_ref());
        let paths = operation_paths(&args, "s", "sign").unwrap_or_else(|e| die(&e, 1));
        sign_files(&paths, identity, &args).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("S") || args.has("sign-message") {
        let identity = require_identity(identity_ref.as_ref());
        sign_message(identity, &args).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("e") || args.has("encrypt") {
        let identity = require_identity(identity_ref.as_ref());
        let paths = operation_paths(&args, "e", "encrypt").unwrap_or_else(|e| die(&e, 1));
        encrypt_files(&paths, identity, &args).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("d") || args.has("decrypt") {
        let identity = require_identity(identity_ref.as_ref());
        let paths = operation_paths(&args, "d", "decrypt").unwrap_or_else(|e| die(&e, 1));
        decrypt_files(&paths, identity, &args).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("w")
        && !args.has("e")
        && !args.has("encrypt")
        && !args.has("d")
        && !args.has("decrypt")
        && !args.has("s")
        && !args.has("sign")
        && !args.has("S")
        && !args.has("sign-message")
    {
        let identity = require_identity(identity_ref.as_ref());
        write_identity(&args, identity).unwrap_or_else(|e| die(&e, 1));
        operated = true;
    }

    if args.has("g") || args.has("generate") {
        operated = true;
    }

    if !operated {
        print_usage();
    }
}

fn validate_args(args: &Args) -> Result<(), String> {
    let operations = [
        args.has("e") || args.has("encrypt"),
        args.has("d") || args.has("decrypt"),
        args.has("s") || args.has("sign"),
        args.has("S") || args.has("sign-message"),
        args.has("V") || args.has("validate"),
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    if operations > 1 {
        return Err(
            "Only one of encrypt, decrypt, sign, sign-message or validate is supported per invocation"
                .into(),
        );
    }

    let identity_sources = [
        args.has("g") || args.has("generate"),
        args.has("i") || args.has("identity"),
        args.has("m") || args.has("import-pub"),
        args.has("M") || args.has("import-prv"),
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    if identity_sources > 1 {
        return Err("The -i, -g, -m and -M options are mutually exclusive".into());
    }

    let output_formats = [
        args.has("b") || args.has("base64"),
        args.has("B") || args.has("base32"),
        args.has("Z") || args.has("base256"),
        args.has("hex"),
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    if output_formats > 1 {
        return Err("The -b, -B, --base256 and --hex options are mutually exclusive".into());
    }

    Ok(())
}

fn operation_paths<'a>(args: &'a Args, short: &str, long: &str) -> Result<Vec<&'a str>, String> {
    let mut paths = Vec::new();
    if let Some(path) = args.get(short).or_else(|| args.get(long)) {
        if path != "true" {
            paths.push(path);
        }
    }
    paths.extend(args.positional.iter().map(String::as_str));
    if paths.is_empty() {
        Err("missing operation path".into())
    } else {
        Ok(paths)
    }
}

fn load_identity_ref(args: &Args, allow_none: bool) -> Result<Option<IdentityRef>, String> {
    if let Some(path) = args.get("g").or_else(|| args.get("generate")) {
        let identity = generate_identity(path, args)?;
        return Ok(Some(IdentityRef::Identity(identity)));
    }

    if let Some(spec) = args.get("i").or_else(|| args.get("identity")) {
        let expanded = Path::new(spec);
        if expanded.exists() {
            return load_private_identity_file(expanded).map(|id| Some(IdentityRef::Identity(id)));
        }

        let hash = parse_identity_hash(spec)?;
        if args.has("N") || args.has("no-cache") {
            return Ok(Some(IdentityRef::Hash(hash)));
        }

        if args.has("R") || args.has("request") {
            if let Some(identity) = request_identity(args, hash)? {
                return Ok(Some(IdentityRef::Identity(identity)));
            }
        }

        if allow_none {
            return Ok(Some(IdentityRef::Hash(hash)));
        }

        return Err(format!(
            "Could not resolve identity {}. Use -R to request it from the network.",
            prettyhexrep(&hash)
        ));
    }

    if let Some(spec) = args.get("m").or_else(|| args.get("import-pub")) {
        let public_key = load_or_decode_key(spec, 64, args)?;
        let key: [u8; 64] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid public identity length".to_string())?;
        return Ok(Some(IdentityRef::Identity(Identity::from_public_key(&key))));
    }

    if let Some(spec) = args.get("M").or_else(|| args.get("import-prv")) {
        let private_key = load_or_decode_key(spec, 64, args)?;
        let key: [u8; 64] = private_key
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid private identity length".to_string())?;
        return Ok(Some(IdentityRef::Identity(Identity::from_private_key(
            &key,
        ))));
    }

    if allow_none {
        Ok(None)
    } else {
        Err("Could not get working identity".into())
    }
}

fn generate_identity(path: &str, args: &Args) -> Result<Identity, String> {
    let force = args.has("f") || args.has("force");
    let path = Path::new(path);
    if path.exists() && !force {
        return Err(format!("Identity file {} already exists", path.display()));
    }

    let identity = Identity::new(&mut OsRng);
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| "Generated identity is missing a private key".to_string())?;
    fs::write(path, private_key).map_err(|e| format!("Error writing identity: {}", e))?;

    println!("Generated new identity");
    println!("  Hash : {}", prettyhexrep(identity.hash()));
    if args.has("Z") || args.has("base256") {
        println!("  B256 : {}", prettyb256rep(identity.hash()));
    }
    println!("  Saved: {}", path.display());
    Ok(identity)
}

fn load_private_identity_file(path: &Path) -> Result<Identity, String> {
    let data = fs::read(path).map_err(|e| format!("Error reading identity: {}", e))?;
    let key = if data.len() == 64 {
        data
    } else if data.len() == 128 {
        data[..64].to_vec()
    } else {
        return Err(format!(
            "Unknown private identity file format ({} bytes)",
            data.len()
        ));
    };
    let key: [u8; 64] = key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid private identity length".to_string())?;
    Ok(Identity::from_private_key(&key))
}

fn load_or_decode_key(spec: &str, expected_len: usize, args: &Args) -> Result<Vec<u8>, String> {
    let path = Path::new(spec);
    if path.exists() {
        let data = fs::read(path).map_err(|e| format!("Error reading identity: {}", e))?;
        if data.len() == expected_len {
            return Ok(data);
        }
        return Err(format!(
            "Invalid identity file length: expected {} bytes, got {}",
            expected_len,
            data.len()
        ));
    }

    let decoded = if args.has("B") || args.has("base32") {
        base32_decode(spec).ok_or_else(|| "Invalid base32 identity data".to_string())?
    } else if args.has("b") || args.has("base64") {
        base64_decode(spec).ok_or_else(|| "Invalid base64 identity data".to_string())?
    } else {
        parse_hex(spec).ok_or_else(|| "Invalid hexadecimal identity data".to_string())?
    };

    if decoded.len() != expected_len {
        return Err(format!(
            "Invalid identity length: expected {} bytes, got {}",
            expected_len,
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn request_identity(args: &Args, requested_hash: [u8; 16]) -> Result<Option<Identity>, String> {
    let mut default_parts = DEFAULT_ASPECTS.split('.');
    let app_name = default_parts.next().unwrap_or("rns");
    let aspects: Vec<&str> = default_parts.collect();
    let id_dest_hash = destination_hash(app_name, &aspects, Some(&requested_hash));

    rpc_client(args)?
        .call(&rns_net::pickle::PickleValue::Dict(vec![(
            rns_net::pickle::PickleValue::String("request_path".into()),
            rns_net::pickle::PickleValue::Bytes(requested_hash.to_vec()),
        )]))
        .map_err(|e| format!("Could not request destination path: {}", e))?;
    rpc_client(args)?
        .call(&rns_net::pickle::PickleValue::Dict(vec![(
            rns_net::pickle::PickleValue::String("request_path".into()),
            rns_net::pickle::PickleValue::Bytes(id_dest_hash.to_vec()),
        )]))
        .map_err(|e| format!("Could not request identity path: {}", e))?;

    let timeout_secs = args
        .get("t")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(5.0);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);

    loop {
        let entries = rpc_client(args)?
            .known_destinations()
            .map_err(|e| format!("Could not query known destinations: {}", e))?;
        if let Some(entry) = find_identity_entry(&entries, requested_hash) {
            let retained = rpc_client(args)?
                .retain_identity(entry.identity_hash)
                .unwrap_or(false);
            if retained {
                println!("Retained Identity {}", prettyhexrep(&entry.identity_hash));
            }
            return Ok(Some(Identity::from_public_key(&entry.public_key)));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn find_identity_entry(
    entries: &[KnownDestinationEntry],
    requested_hash: [u8; 16],
) -> Option<&KnownDestinationEntry> {
    entries
        .iter()
        .find(|entry| entry.identity_hash == requested_hash || entry.dest_hash == requested_hash)
}

fn rpc_client(args: &Args) -> Result<RpcClient, String> {
    let config_dir = storage::resolve_config_dir(args.config_path().map(|s| Path::new(s)));
    let config_file = config_dir.join("config");
    let rns_config = if config_file.exists() {
        config::parse_file(&config_file).map_err(|e| format!("Error reading config: {}", e))?
    } else {
        config::parse("").map_err(|e| format!("Error parsing default config: {}", e))?
    };
    let paths = storage::ensure_storage_dirs(&config_dir).map_err(|e| e.to_string())?;
    let identity =
        storage::load_or_create_identity(&paths.identities).map_err(|e| e.to_string())?;
    let auth_key = derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));
    let rpc_addr = RpcAddr::Tcp(
        "127.0.0.1".into(),
        rns_config.reticulum.instance_control_port,
    );
    RpcClient::connect(&rpc_addr, &auth_key)
        .map_err(|e| format!("Could not connect to rnsd: {}", e))
}

fn require_identity(identity_ref: Option<&IdentityRef>) -> &Identity {
    match identity_ref {
        Some(IdentityRef::Identity(identity)) => identity,
        Some(IdentityRef::Hash(hash)) => die(
            &format!(
                "Identity {} was specified by hash only and has no key data",
                prettyhexrep(hash)
            ),
            1,
        ),
        None => die("Could not get working identity", 1),
    }
}

fn print_identity_information(args: &Args, identity: &Identity) {
    println!("Identity Hash : {}", prettyhexrep(identity.hash()));
    if let Some(public_key) = identity.get_public_key() {
        println!("Public Key    : {}", encode_key(args, &public_key));
    }
    if identity.get_private_key().is_some() {
        if args.has("P") || args.has("print-private") {
            println!(
                "Private Key   : {}",
                encode_key(args, &identity.get_private_key().unwrap())
            );
        } else {
            println!("Private Key   : Hidden");
        }
    }
}

fn print_hash_information(aspects: &str, identity_ref: Option<&IdentityRef>) -> Result<(), String> {
    let identity_hash = match identity_ref {
        Some(IdentityRef::Identity(identity)) => *identity.hash(),
        Some(IdentityRef::Hash(hash)) => *hash,
        None => return Err("No identity or identity hash specified".into()),
    };
    let mut parts = aspects.split('.');
    let app_name = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Invalid destination aspects".to_string())?;
    let aspects: Vec<&str> = parts.collect();
    let dest_hash = destination_hash(app_name, &aspects, Some(&identity_hash));
    println!(
        "The {} destination for this Identity is {}",
        app_name_and_aspects(app_name, &aspects),
        prettyhexrep(&dest_hash)
    );
    Ok(())
}

fn app_name_and_aspects(app_name: &str, aspects: &[&str]) -> String {
    if aspects.is_empty() {
        app_name.to_string()
    } else {
        format!("{}.{}", app_name, aspects.join("."))
    }
}

fn export_public_identity(args: &Args, identity: &Identity) -> Result<(), String> {
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| "Identity does not hold a public key".to_string())?;
    println!("{}", encode_key(args, &public_key));
    Ok(())
}

fn export_private_identity(args: &Args, identity: &Identity) -> Result<(), String> {
    let private_key = identity
        .get_private_key()
        .ok_or_else(|| "Identity does not hold a private key".to_string())?;
    println!("{}", encode_key(args, &private_key));
    Ok(())
}

fn write_identity(args: &Args, identity: &Identity) -> Result<(), String> {
    let force = args.has("f") || args.has("force");
    let output = args
        .get("w")
        .or_else(|| args.get("write"))
        .ok_or_else(|| "Missing output path".to_string())?;

    if args.has("X") || args.has("export-prv") {
        let private_key = identity
            .get_private_key()
            .ok_or_else(|| "Identity does not hold a private key".to_string())?;
        write_file_checked(output, &private_key, force)?;
        println!("Wrote private identity to {}", output);
        return Ok(());
    }

    let public_key = identity
        .get_public_key()
        .ok_or_else(|| "Identity does not hold a public key".to_string())?;
    let output = if output
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", PUB_EXT))
    {
        output.to_string()
    } else {
        format!("{}.{}", output, PUB_EXT)
    };
    write_file_checked(&output, &public_key, force)?;
    println!("Wrote public identity to {}", output);
    Ok(())
}

fn sign_file(path: &str, identity: &Identity, args: &Args) -> Result<(), String> {
    let data = read_input(path, args)?;
    let output_path = args
        .get("w")
        .or_else(|| args.get("write"))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}.{}", path, SIG_EXT));
    let output_format = rsg_output_format(args);

    let signature = if args.has("raw") {
        identity.sign(&data).map(|sig| sig.to_vec()).map_err(|_| {
            format!(
                "Cannot sign {}, the identity does not hold a private key",
                path
            )
        })?
    } else {
        create_rsg(identity, &data)?
    };

    if !args.has("raw") && !matches!(output_format, RsgOutputFormat::Binary) {
        println!("{}", wrap_rsg_ascii(&encode_rsg(&signature, output_format)));
        println!(
            "Signed file {} with {}",
            path,
            prettyhexrep(identity.hash())
        );
    } else if args.has("stdout") {
        io::stdout()
            .write_all(&signature)
            .map_err(|e| format!("Error writing to stdout: {}", e))?;
    } else {
        write_file_checked(&output_path, &signature, args.has("f") || args.has("force"))?;
        println!(
            "Signed file {} with {}",
            path,
            prettyhexrep(identity.hash())
        );
    }
    Ok(())
}

fn sign_files(paths: &[&str], identity: &Identity, args: &Args) -> Result<(), String> {
    for path in paths {
        sign_file(path, identity, args)?;
    }
    Ok(())
}

fn validate_signature(
    path: &str,
    required: Option<&IdentityRef>,
    args: &Args,
) -> Result<(), String> {
    if path
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", MSG_EXT))
    {
        return validate_message_signature(path, required, args);
    }
    let sig_ext = format!(".{}", SIG_EXT);
    let (signature_path, file_path) = if path.to_ascii_lowercase().ends_with(&sig_ext) {
        (
            path.to_string(),
            path[..path.len() - sig_ext.len()].to_string(),
        )
    } else {
        (format!("{}.{}", path, SIG_EXT), path.to_string())
    };

    let message = fs::read(&file_path)
        .map_err(|e| format!("Could not read validation target {}: {}", file_path, e))?;
    let signature_input = fs::read(&signature_path)
        .map_err(|e| format!("Could not read signature {}: {}", signature_path, e))?;
    let signature = decode_rsg_data(&signature_input).ok_or_else(|| {
        format!(
            "Invalid signature {} for file {}",
            signature_path, file_path
        )
    })?;

    if signature.len() == SIG_LEN {
        let Some(IdentityRef::Identity(identity)) = required else {
            return Err(
                "Cannot validate legacy rsg signatures without an explicit required identity"
                    .into(),
            );
        };
        let sig: [u8; SIG_LEN] = signature.as_slice().try_into().unwrap();
        if identity.verify(&sig, &message) {
            println!(
                "Signature is valid, the file {} was signed by {}",
                file_path,
                prettyhexrep(identity.hash())
            );
            return Ok(());
        }
        return Err(format!(
            "Invalid signature {} for file {}",
            signature_path, file_path
        ));
    }

    let required_hash = match required {
        Some(IdentityRef::Identity(identity)) => Some(*identity.hash()),
        Some(IdentityRef::Hash(hash)) => Some(*hash),
        None => None,
    };

    match validate_rsg(&signature, &message, required_hash)? {
        RsgValidation::Valid { signer_hash } => {
            println!(
                "Signature is valid, the file {} was signed by {}",
                file_path,
                prettyhexrep(&signer_hash)
            );
            Ok(())
        }
        RsgValidation::WrongSigner { signer_hash } => {
            let required = required_hash.map(|h| prettyhexrep(&h)).unwrap_or_default();
            Err(format!(
                "Invalid signature {} for file {}\nThis file was NOT signed by {} (actual signer {})",
                signature_path,
                file_path,
                required,
                prettyhexrep(&signer_hash)
            ))
        }
        RsgValidation::Invalid => Err(format!(
            "Invalid signature {} for file {}",
            signature_path, file_path
        )),
    }
}

fn validate_message_signature(
    path: &str,
    required: Option<&IdentityRef>,
    args: &Args,
) -> Result<(), String> {
    let signature_input =
        fs::read(path).map_err(|e| format!("Could not read signature {}: {}", path, e))?;
    let signature =
        decode_rsg_data(&signature_input).ok_or_else(|| format!("Invalid signature {}", path))?;
    let value = rsg_envelope(&signature)?.ok_or_else(|| format!("Invalid signature {}", path))?;
    let Some(message) = rsg_embedded_message(&value) else {
        return Err(format!("No embedded message in {}", path));
    };
    let required_hash = match required {
        Some(IdentityRef::Identity(identity)) => Some(*identity.hash()),
        Some(IdentityRef::Hash(hash)) => Some(*hash),
        None => None,
    };

    match validate_rsg(&signature, &message, required_hash)? {
        RsgValidation::Valid { signer_hash } => {
            let text = String::from_utf8(message)
                .map_err(|e| format!("Embedded message in {} is not UTF-8: {}", path, e))?;
            if args.has("meta") {
                println!("RSM Metadata\n============\n");
                if let Some(meta) = value.map_get("meta") {
                    print_rsm_metadata(meta);
                }
                println!("\nValidation\n==========");
                println!(
                    "\nSignature is valid, the message was signed by {}\n",
                    prettyhexrep(&signer_hash)
                );
                println!("Message\n=======\n");
            } else {
                println!(
                    "\nSignature is valid, the following message was signed by {}:\n",
                    prettyhexrep(&signer_hash)
                );
            }
            println!("{}", text);
            Ok(())
        }
        RsgValidation::WrongSigner { signer_hash } => {
            let required = required_hash.map(|h| prettyhexrep(&h)).unwrap_or_default();
            Err(format!(
                "Invalid signature in {}\nThe message was NOT signed by {} (actual signer {})",
                path,
                required,
                prettyhexrep(&signer_hash)
            ))
        }
        RsgValidation::Invalid => Err(format!("Invalid signature in {}", path)),
    }
}

fn print_rsm_metadata(meta: &Value) {
    if let Some(entries) = meta.as_map() {
        for (key, value) in entries {
            let key = rsm_meta_key(key);
            if should_print_rsm_meta_entry(&key, value) {
                print_rsm_metadata_entry(value, &key, 0);
            }
        }
    } else {
        print_rsm_metadata_entry(meta, "meta", 0);
    }
}

fn print_rsm_metadata_entry(value: &Value, key: &str, level: usize) {
    let indent = "  ".repeat(level);
    if let Some(entries) = value.as_map() {
        println!("d{}{}:", indent, key);
        for (child_key, child_value) in entries {
            let child_key = rsm_meta_key(child_key);
            if should_print_rsm_meta_entry(&child_key, child_value) {
                print_rsm_metadata_entry(child_value, &child_key, level + 1);
            }
        }
        return;
    }

    println!(
        "{}{}{}={}",
        rsm_meta_type(value),
        indent,
        key,
        rsm_meta_value(value)
    );
}

fn should_print_rsm_meta_entry(key: &str, value: &Value) -> bool {
    !(key == "note" && matches!(value, Value::Nil))
}

fn rsm_meta_key(value: &Value) -> String {
    match value {
        Value::Str(value) => value.clone(),
        Value::Bin(value) => hex(value),
        Value::UInt(value) => value.to_string(),
        Value::Int(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::Nil => "nil".into(),
        Value::Array(_) => "array".into(),
        Value::Map(_) => "map".into(),
    }
}

fn rsm_meta_type(value: &Value) -> char {
    match value {
        Value::Str(_) => 's',
        Value::Bin(_) => 'b',
        Value::Array(_) => 'l',
        Value::Map(_) => 'd',
        Value::UInt(_) | Value::Int(_) => 'i',
        Value::Float(_) => 'f',
        Value::Nil => 'N',
        Value::Bool(_) => 'u',
    }
}

fn rsm_meta_value(value: &Value) -> String {
    match value {
        Value::Nil => "None".into(),
        Value::Bool(value) => value.to_string(),
        Value::UInt(value) => value.to_string(),
        Value::Int(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::Bin(value) => hex(value),
        Value::Str(value) => value.clone(),
        Value::Array(values) => format!("{:?}", values),
        Value::Map(values) => format!("{:?}", values),
    }
}

#[allow(dead_code)]
fn check_release_rsm_structure(signed_data: &Value) -> Result<(), &'static str> {
    let Some(release_meta) = signed_data.map_get("meta") else {
        return Err("No release metadata in manifest");
    };
    let release_name = release_meta.map_get("name").and_then(Value::as_str);
    let release_version = release_meta.map_get("version").and_then(Value::as_str);
    let release_origin = release_meta.map_get("origin");
    let release_origin_path = release_meta.map_get("path").and_then(Value::as_str);

    let Some(release_name) = release_name.filter(|value| !value.is_empty()) else {
        return Err("Incomplete package data in manifest");
    };
    let Some(release_version) = release_version.filter(|value| !value.is_empty()) else {
        return Err("Incomplete package data in manifest");
    };
    let Some(release_origin) = release_origin else {
        return Err("Incomplete release origin data in manifest");
    };
    let Some(_release_origin_path) = release_origin_path.filter(|value| !value.is_empty()) else {
        return Err("Incomplete release origin data in manifest");
    };

    if release_name.contains('/') || release_version.contains('/') {
        return Err("Invalid data in release manifest");
    }
    let origin_len = match release_origin {
        Value::Bin(bytes) => bytes.len(),
        Value::Str(value) => value.len(),
        _ => return Err("Invalid origin hash in manifest"),
    };
    if origin_len != 16 {
        return Err("Invalid origin hash length in manifest");
    }
    if !matches!(release_origin, Value::Bin(_)) {
        return Err("Invalid origin hash in manifest");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn validate_signatures(
    paths: &[&str],
    required: Option<&IdentityRef>,
    args: &Args,
) -> Result<(), String> {
    for path in paths {
        validate_signature(path, required, args)?;
    }
    Ok(())
}

fn create_rsg(identity: &Identity, message: &[u8]) -> Result<Vec<u8>, String> {
    create_rsg_with_embed_and_meta(identity, message, false, None)
}

fn create_rsg_with_embed_and_meta(
    identity: &Identity,
    message: &[u8],
    embed_message: bool,
    extra_meta: Option<Vec<(String, Value)>>,
) -> Result<Vec<u8>, String> {
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| "Identity does not hold a public key".to_string())?;
    let mut meta_items = vec![
        (
            Value::Str("signer".into()),
            Value::Bin(identity.hash().to_vec()),
        ),
        (Value::Str("pubkey".into()), Value::Bin(public_key.to_vec())),
    ];
    if let Some(extra_meta) = extra_meta {
        for (key, value) in extra_meta {
            if !meta_items
                .iter()
                .any(|(existing, _)| matches!(existing, Value::Str(existing) if existing == &key))
            {
                meta_items.push((Value::Str(key), value));
            }
        }
    }

    let mut envelope_items = vec![
        (Value::Str("hashtype".into()), Value::Str("sha256".into())),
        (
            Value::Str("hash".into()),
            Value::Bin(sha256(message).to_vec()),
        ),
        (Value::Str("meta".into()), Value::Map(meta_items)),
    ];
    if embed_message {
        envelope_items.push((Value::Str("message".into()), Value::Bin(message.to_vec())));
    }
    let envelope = Value::Map(envelope_items);
    let envelope = msgpack::pack(&envelope);
    let signature = identity
        .sign(&envelope)
        .map_err(|_| "Identity does not hold a private key".to_string())?;
    let mut rsg = Vec::with_capacity(SIG_LEN + envelope.len());
    rsg.extend_from_slice(&signature);
    rsg.extend_from_slice(&envelope);
    Ok(rsg)
}

#[derive(Debug, Clone)]
enum MetaNode {
    Scalar(String),
    Section(BTreeMap<String, MetaNode>),
}

fn sign_message_metadata(args: &Args) -> Result<Option<Vec<(String, Value)>>, String> {
    let Some(meta_path) = args.get("E").or_else(|| args.get("embed-meta")) else {
        return Ok(None);
    };
    if meta_path == "true" {
        return Err("No metadata path specified".into());
    }
    let mut meta = parse_configobj_file(meta_path)?;
    let spec_path = args
        .get("meta-spec")
        .filter(|path| *path != "true")
        .map(str::to_string)
        .or_else(|| {
            let candidate = format!("{meta_path}.spec");
            Path::new(&candidate).is_file().then_some(candidate)
        });
    if let Some(spec_path) = spec_path {
        let spec = parse_configobj_file(&spec_path)?;
        validate_metadata_spec(&mut meta, &spec)?;
    }
    Ok(Some(meta_nodes_to_values(meta)))
}

fn parse_configobj_file(path: &str) -> Result<BTreeMap<String, MetaNode>, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("Error reading {path}: {e}"))?;
    parse_configobj(&input)
}

fn parse_configobj(input: &str) -> Result<BTreeMap<String, MetaNode>, String> {
    let mut root = BTreeMap::new();
    let mut section: Option<String> = None;
    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line.trim_matches(&['[', ']'][..]).trim();
            if name.is_empty() {
                return Err(format!("Invalid empty section on line {}", index + 1));
            }
            section = Some(name.to_string());
            root.entry(name.to_string())
                .or_insert_with(|| MetaNode::Section(BTreeMap::new()));
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("Invalid metadata line {}", index + 1));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("Invalid empty key on line {}", index + 1));
        }
        let value = MetaNode::Scalar(unquote_config_value(value.trim()).to_string());
        if let Some(section) = section.as_ref() {
            let entry = root
                .entry(section.clone())
                .or_insert_with(|| MetaNode::Section(BTreeMap::new()));
            let MetaNode::Section(entries) = entry else {
                return Err(format!("Section {section} conflicts with scalar value"));
            };
            entries.insert(key.to_string(), value);
        } else {
            root.insert(key.to_string(), value);
        }
    }
    Ok(root)
}

fn unquote_config_value(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn validate_metadata_spec(
    meta: &mut BTreeMap<String, MetaNode>,
    spec: &BTreeMap<String, MetaNode>,
) -> Result<(), String> {
    for (key, spec_node) in spec {
        let Some(meta_node) = meta.get_mut(key) else {
            return Err(format!(
                "Metadata did not pass spec validation: missing {key}"
            ));
        };
        validate_metadata_node(key, meta_node, spec_node)?;
    }
    Ok(())
}

fn validate_metadata_node(key: &str, meta: &mut MetaNode, spec: &MetaNode) -> Result<(), String> {
    match (meta, spec) {
        (MetaNode::Scalar(value), MetaNode::Scalar(check)) => {
            let converted = validate_metadata_scalar(key, value, check)?;
            *value = converted;
            Ok(())
        }
        (MetaNode::Section(meta_entries), MetaNode::Section(spec_entries)) => {
            validate_metadata_spec(meta_entries, spec_entries)
        }
        _ => Err(format!(
            "Metadata did not pass spec validation: type mismatch for {key}"
        )),
    }
}

fn validate_metadata_scalar(key: &str, value: &str, check: &str) -> Result<String, String> {
    let (name, params) = parse_spec_check(check);
    match name.as_str() {
        "string" | "str" => {
            let len = value.chars().count() as i64;
            validate_len_or_range(key, len, params.get("min"), params.get("max"))?;
            Ok(value.to_string())
        }
        "integer" | "int" => {
            let parsed = value.parse::<i64>().map_err(|_| {
                format!("Metadata did not pass spec validation: {key} is not an integer")
            })?;
            validate_len_or_range(key, parsed, params.get("min"), params.get("max"))?;
            Ok(parsed.to_string())
        }
        "float" => {
            let parsed = value.parse::<f64>().map_err(|_| {
                format!("Metadata did not pass spec validation: {key} is not a float")
            })?;
            if let Some(min) = params.get("min").and_then(|v| v.parse::<f64>().ok()) {
                if parsed < min {
                    return Err(format!(
                        "Metadata did not pass spec validation: {key} is too small"
                    ));
                }
            }
            if let Some(max) = params.get("max").and_then(|v| v.parse::<f64>().ok()) {
                if parsed > max {
                    return Err(format!(
                        "Metadata did not pass spec validation: {key} is too big"
                    ));
                }
            }
            Ok(parsed.to_string())
        }
        "boolean" | "bool" => parse_config_bool(value)
            .map(|v| v.to_string())
            .ok_or_else(|| {
                format!("Metadata did not pass spec validation: {key} is not a boolean")
            }),
        "" | "pass" => Ok(value.to_string()),
        _ => Err(format!(
            "Metadata did not pass spec validation: unknown check {name} for {key}"
        )),
    }
}

fn parse_spec_check(check: &str) -> (String, BTreeMap<String, String>) {
    let trimmed = check.trim();
    let Some(open) = trimmed.find('(') else {
        return (trimmed.to_string(), BTreeMap::new());
    };
    let name = trimmed[..open].trim().to_string();
    let close = trimmed.rfind(')').unwrap_or(trimmed.len());
    let mut params = BTreeMap::new();
    for part in trimmed[open + 1..close].split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            params.insert(
                key.trim().to_string(),
                unquote_config_value(value.trim()).to_string(),
            );
        }
    }
    (name, params)
}

fn validate_len_or_range(
    key: &str,
    value: i64,
    min: Option<&String>,
    max: Option<&String>,
) -> Result<(), String> {
    if let Some(min) = min.and_then(|v| v.parse::<i64>().ok()) {
        if value < min {
            return Err(format!(
                "Metadata did not pass spec validation: {key} is too small"
            ));
        }
    }
    if let Some(max) = max.and_then(|v| v.parse::<i64>().ok()) {
        if value > max {
            return Err(format!(
                "Metadata did not pass spec validation: {key} is too big"
            ));
        }
    }
    Ok(())
}

fn parse_config_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn meta_nodes_to_values(nodes: BTreeMap<String, MetaNode>) -> Vec<(String, Value)> {
    nodes
        .into_iter()
        .map(|(key, node)| (key, meta_node_to_value(node)))
        .collect()
}

fn meta_node_to_value(node: MetaNode) -> Value {
    match node {
        MetaNode::Scalar(value) => Value::Str(value),
        MetaNode::Section(entries) => Value::Map(
            entries
                .into_iter()
                .map(|(key, node)| (Value::Str(key), meta_node_to_value(node)))
                .collect(),
        ),
    }
}

fn sign_message_read_path(args: &Args) -> Option<&str> {
    args.get("read").or_else(|| {
        if args.has("r") {
            args.positional.first().map(String::as_str)
        } else {
            None
        }
    })
}

fn sign_message(identity: &Identity, args: &Args) -> Result<(), String> {
    let cli_message = args
        .get("S")
        .or_else(|| args.get("sign-message"))
        .unwrap_or("true");
    let read_path = sign_message_read_path(args);
    let message = if let Some(path) = read_path {
        if cli_message != "true" {
            return Err(
                "Both an input file and command-line provided message was specified".into(),
            );
        }
        fs::read(path).map_err(|e| format!("Error reading {}: {}", path, e))?
    } else if cli_message == "true" {
        editor_content()?
    } else {
        cli_message.as_bytes().to_vec()
    };
    if message.is_empty() {
        return Err("No message specified".into());
    }

    let output_format = rsg_output_format(args);
    let extra_meta = sign_message_metadata(args)?;
    let rsg = create_rsg_with_embed_and_meta(identity, &message, true, extra_meta)?;
    if matches!(output_format, RsgOutputFormat::Binary) {
        let Some(output) = args.get("w").or_else(|| args.get("write")) else {
            return Err("No write path specified".into());
        };
        let output = if output
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", MSG_EXT))
        {
            output.to_string()
        } else {
            format!("{}.{}", output, MSG_EXT)
        };
        write_file_checked(&output, &rsg, args.has("f") || args.has("force"))?;
        println!(
            "Message signed with {} saved to {}",
            prettyhexrep(identity.hash()),
            output
        );
    } else {
        println!("{}", wrap_rsg_ascii(&encode_rsg(&rsg, output_format)));
        println!("Message signed with {}", prettyhexrep(identity.hash()));
    }
    Ok(())
}

fn rsg_output_format(args: &Args) -> RsgOutputFormat {
    if args.has("hex") {
        RsgOutputFormat::Hex
    } else if args.has("Z") || args.has("base256") {
        RsgOutputFormat::Base256
    } else if args.has("B") || args.has("base32") {
        RsgOutputFormat::Base32
    } else if args.has("b") || args.has("base64") {
        RsgOutputFormat::Base64
    } else {
        RsgOutputFormat::Binary
    }
}

fn encode_rsg(rsg: &[u8], format: RsgOutputFormat) -> String {
    match format {
        RsgOutputFormat::Binary => String::from_utf8_lossy(rsg).into_owned(),
        RsgOutputFormat::Hex => prettyhexrep(rsg),
        RsgOutputFormat::Base32 => base32_encode(rsg),
        RsgOutputFormat::Base256 => b256rep(rsg),
        RsgOutputFormat::Base64 => base64_encode(rsg),
    }
}

fn wrap_rsg_ascii(encoded: &str) -> String {
    let header = format!(
        "{}{}",
        RSG_ASCII_HEADER,
        "#".repeat(RSG_ASCII_ROW_WIDTH - RSG_ASCII_HEADER.len())
    );
    let footer = format!(
        "{}{}",
        "#".repeat(RSG_ASCII_ROW_WIDTH - RSG_ASCII_FOOTER.len()),
        RSG_ASCII_FOOTER
    );
    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');
    let mut line = String::new();
    let mut line_chars = 0usize;
    for ch in encoded.chars() {
        line.push(ch);
        line_chars += 1;
        if line_chars == RSG_ASCII_ROW_WIDTH {
            out.push_str(&line);
            out.push('\n');
            line.clear();
            line_chars = 0;
        }
    }
    if line_chars > 0 {
        if line_chars < RSG_ASCII_ROW_WIDTH {
            line.push_str(&"=".repeat(RSG_ASCII_ROW_WIDTH - line_chars));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&footer);
    out
}

fn unwrap_rsg_ascii(input: &str) -> Option<String> {
    let mut out = String::new();
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push_str(line);
    }
    if out.is_empty() {
        None
    } else {
        Some(out.trim_end_matches('=').to_string())
    }
}

fn decode_rsg_data(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() == SIG_LEN {
        return Some(input.to_vec());
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return Some(input.to_vec());
    };
    let wrapped = text.contains(RSG_ASCII_HEADER);
    let encoded = unwrap_rsg_ascii(text).unwrap_or_else(|| {
        text.chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>()
    });
    if encoded.is_empty() {
        return None;
    }
    if encoded.chars().any(|ch| !ch.is_ascii()) {
        return b256_to_bytes(&encoded)
            .or_else(|| if wrapped { None } else { Some(input.to_vec()) });
    }
    if !wrapped
        && !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '-' | '_' | '='))
    {
        return Some(input.to_vec());
    }
    let encoded = encoded.trim_end_matches('=').to_string();
    if encoded.len() % 2 == 0 && encoded.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Some(decoded) = parse_hex(&encoded) {
            return Some(decoded);
        }
    }
    if encoded
        .chars()
        .all(|ch| matches!(ch, 'A'..='Z' | 'a'..='z' | '2'..='7'))
    {
        if let Some(decoded) = base32_decode(&encoded) {
            return Some(decoded);
        }
    }
    base64_decode(&encoded).or_else(|| if wrapped { None } else { Some(input.to_vec()) })
}

enum RsgValidation {
    Valid { signer_hash: [u8; 16] },
    WrongSigner { signer_hash: [u8; 16] },
    Invalid,
}

fn rsg_envelope(rsg: &[u8]) -> Result<Option<Value>, String> {
    if rsg.len() <= SIG_LEN {
        return Ok(None);
    }
    let envelope = &rsg[SIG_LEN..];
    msgpack::unpack_exact(envelope)
        .map(Some)
        .map_err(|e| format!("Invalid rsg envelope: {}", e))
}

fn rsg_embedded_message(value: &Value) -> Option<Vec<u8>> {
    if let Some(message) = value.map_get("message").and_then(Value::as_bin) {
        Some(message.to_vec())
    } else {
        value
            .map_get("message")
            .and_then(Value::as_str)
            .map(|message| message.as_bytes().to_vec())
    }
}

fn validate_rsg(
    rsg: &[u8],
    message: &[u8],
    required_signer: Option<[u8; 16]>,
) -> Result<RsgValidation, String> {
    if rsg.len() <= SIG_LEN {
        return Ok(RsgValidation::Invalid);
    }
    let signature: [u8; SIG_LEN] = rsg[..SIG_LEN].try_into().unwrap();
    let envelope = &rsg[SIG_LEN..];
    let Some(value) = rsg_envelope(rsg)? else {
        return Ok(RsgValidation::Invalid);
    };

    if value.map_get("hashtype").and_then(Value::as_str) != Some("sha256") {
        return Ok(RsgValidation::Invalid);
    }
    let Some(signed_hash) = value.map_get("hash").and_then(Value::as_bin) else {
        return Ok(RsgValidation::Invalid);
    };
    if signed_hash != sha256(message) {
        return Ok(RsgValidation::Invalid);
    }
    let Some(meta) = value.map_get("meta") else {
        return Ok(RsgValidation::Invalid);
    };
    let Some(pubkey_bytes) = meta.map_get("pubkey").and_then(Value::as_bin) else {
        return Ok(RsgValidation::Invalid);
    };
    let Ok(public_key) = <[u8; 64]>::try_from(pubkey_bytes) else {
        return Ok(RsgValidation::Invalid);
    };
    let identity = Identity::from_public_key(&public_key);
    let signer_hash = *identity.hash();

    let Some(meta_signer) = meta.map_get("signer").and_then(Value::as_bin) else {
        return Ok(RsgValidation::Invalid);
    };
    if meta_signer != signer_hash {
        return Ok(RsgValidation::Invalid);
    }

    if let Some(required) = required_signer {
        if signer_hash != required {
            return Ok(RsgValidation::WrongSigner { signer_hash });
        }
    }

    if identity.verify(&signature, envelope) {
        Ok(RsgValidation::Valid { signer_hash })
    } else {
        Ok(RsgValidation::Invalid)
    }
}

fn encrypt_file(path: &str, identity: &Identity, args: &Args) -> Result<(), String> {
    let plaintext = read_input(path, args)?;
    let ciphertext = identity.encrypt(&plaintext, &mut OsRng).map_err(|_| {
        format!(
            "Cannot encrypt {}, the identity does not hold a public key",
            path
        )
    })?;
    let output = args
        .get("w")
        .or_else(|| args.get("write"))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}.{}", path, ENCRYPT_EXT));
    if args.has("stdout") {
        io::stdout()
            .write_all(&ciphertext)
            .map_err(|e| format!("Error writing to stdout: {}", e))?;
    } else {
        write_file_checked(&output, &ciphertext, args.has("f") || args.has("force"))?;
        println!("File {} encrypted to {}", path, output);
    }
    Ok(())
}

fn encrypt_files(paths: &[&str], identity: &Identity, args: &Args) -> Result<(), String> {
    for path in paths {
        encrypt_file(path, identity, args)?;
    }
    Ok(())
}

fn decrypt_file(path: &str, identity: &Identity, args: &Args) -> Result<(), String> {
    if !path
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", ENCRYPT_EXT))
    {
        return Err(format!(
            "The file {} does not appear to be a Reticulum encrypted file",
            path
        ));
    }
    let ciphertext = read_input(path, args)?;
    let plaintext = identity.decrypt(&ciphertext).map_err(|_| {
        format!(
            "Cannot decrypt {}, the identity does not hold a private key",
            path
        )
    })?;
    let output = args
        .get("w")
        .or_else(|| args.get("write"))
        .map(str::to_string)
        .unwrap_or_else(|| path[..path.len() - ENCRYPT_EXT.len() - 1].to_string());
    if args.has("stdout") {
        io::stdout()
            .write_all(&plaintext)
            .map_err(|e| format!("Error writing to stdout: {}", e))?;
    } else {
        write_file_checked(&output, &plaintext, args.has("f") || args.has("force"))?;
        println!("File {} decrypted to {}", path, output);
    }
    Ok(())
}

fn decrypt_files(paths: &[&str], identity: &Identity, args: &Args) -> Result<(), String> {
    for path in paths {
        decrypt_file(path, identity, args)?;
    }
    Ok(())
}

fn editor_content() -> Result<Vec<u8>, String> {
    let editor = std::env::var("EDITOR").map_err(|_| "Could not launch editor".to_string())?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System clock error: {}", e))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rnid-message-{}-{timestamp}.tmp", process::id()));
    fs::write(&path, "").map_err(|e| format!("Could not create editor buffer: {}", e))?;
    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| format!("Could not launch editor {}: {}", editor, e))?;
    if !status.success() {
        let _ = fs::remove_file(&path);
        return Err(format!("Editor exited with status {}", status));
    }
    let content = fs::read(&path).map_err(|e| format!("Could not read editor buffer: {}", e))?;
    let _ = fs::remove_file(&path);
    Ok(content)
}

fn read_input(path: &str, args: &Args) -> Result<Vec<u8>, String> {
    if args.has("stdin") {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("Error reading stdin: {}", e))?;
        return Ok(buf);
    }
    check_file_size(path);
    fs::read(path).map_err(|e| format!("Error reading {}: {}", path, e))
}

fn check_file_size(file: &str) {
    if let Ok(meta) = fs::metadata(file) {
        if meta.len() > LARGE_FILE_WARN {
            eprintln!(
                "Warning: file is {} - encryption is done in-memory",
                rns_cli::format::size_str(meta.len()),
            );
        }
    }
}

fn write_file_checked(path: &str, data: &[u8], force: bool) -> Result<(), String> {
    let p = Path::new(path);
    if p.exists() && !force {
        return Err(format!(
            "File already exists: {} (use -f to overwrite)",
            path
        ));
    }
    fs::write(p, data).map_err(|e| format!("Error writing {}: {}", path, e))
}

fn parse_identity_hash(s: &str) -> Result<[u8; 16], String> {
    let data = parse_hex(s).ok_or_else(|| "Invalid hexadecimal identity hash".to_string())?;
    data.as_slice()
        .try_into()
        .map_err(|_| "Invalid identity hash length".to_string())
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

fn encode_key(args: &Args, key: &[u8]) -> String {
    if args.has("B") || args.has("base32") {
        base32_encode(key)
    } else if args.has("b") || args.has("base64") {
        base64_encode(key)
    } else {
        prettyhexrep(key)
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut chars: Vec<char> = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if chars.len() % 4 == 1 {
        return None;
    }
    while chars.len() % 4 != 0 {
        chars.push('=');
    }

    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for chunk in chars.chunks(4) {
        let mut pad = 0usize;
        let mut sextets = [0u8; 4];
        for (i, c) in chunk.iter().copied().enumerate() {
            if c == '=' {
                pad += 1;
                sextets[i] = 0;
                continue;
            }
            if pad > 0 {
                return None;
            }
            sextets[i] = match c {
                'A'..='Z' => c as u8 - b'A',
                'a'..='z' => c as u8 - b'a' + 26,
                '0'..='9' => c as u8 - b'0' + 52,
                '+' | '-' => 62,
                '/' | '_' => 63,
                _ => return None,
            };
        }
        if pad > 2 {
            return None;
        }
        let triple = ((sextets[0] as u32) << 18)
            | ((sextets[1] as u32) << 12)
            | ((sextets[2] as u32) << 6)
            | (sextets[3] as u32);
        out.push(((triple >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((triple & 0xff) as u8);
        }
    }
    Some(out)
}

fn die(message: &str, code: i32) -> ! {
    eprintln!("{}", message);
    process::exit(code);
}

fn print_usage() {
    println!("Usage: rnid [OPTIONS]");
    println!();
    println!("Identity:");
    println!("  -g FILE            Generate private identity and save to file");
    println!("  -i FILE|HASH       Load private identity file or require identity hash");
    println!("  -m KEY|FILE        Import public identity from hex/base32/base64 or .pub file");
    println!("  -M KEY|FILE        Import private identity from hex/base32/base64 or .rid file");
    println!("  -w FILE            Write identity or operation output");
    println!("  -x                 Export public identity");
    println!("  -X                 Export private identity");
    println!("  -p                 Print identity info");
    println!("  -P                 Print private key when printing identity info");
    println!();
    println!("Operations:");
    println!("  -H APP.ASPECT      Compute destination hash");
    println!("  -e FILE...         Encrypt one or more files to .rfe");
    println!("  -d FILE.rfe...     Decrypt one or more files");
    println!("  -s FILE...         Sign one or more files to .rsg");
    println!("  -S MESSAGE         Create embedded signed message");
    println!("  -E, --embed-meta FILE  Embed ConfigObj metadata in signed message");
    println!("  -r, --read FILE    Read embedded signed message content from file");
    println!("  -V FILE[.rsg]...   Validate one or more signatures");
    println!("  --raw              Create legacy raw 64-byte signature");
    println!("  -R                 Request unknown identity from the local daemon");
    println!("  -N                 Do not use cache/network identity resolution");
    println!();
    println!("Formatting and I/O:");
    println!("  -b                 Use base64 for identity import/export");
    println!("  -B                 Use base32 for identity import/export");
    println!("  --hex              Use hex for RSG signature output");
    println!("  -Z, --base256      Use base256 for RSG output and hash display");
    println!("  -f, --force        Force overwrite existing files");
    println!("  --stdin            Read operation input from stdin");
    println!("  --stdout           Write operation output to stdout");
    println!("  --meta             Show RSM metadata when validating signed messages");
    println!("  --meta-spec FILE   Validate embedded metadata with a ConfigObj-style spec");
    println!("  --version          Print version and exit");
    println!("  --help, -h         Print this help");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::FixedRng;

    fn test_identity(seed: u8) -> Identity {
        let bytes = (0..64).map(|i| seed.wrapping_add(i)).collect::<Vec<u8>>();
        let mut rng = FixedRng::new(&bytes);
        Identity::new(&mut rng)
    }

    #[test]
    fn rsg_roundtrip_validates_without_required_signer() {
        let identity = test_identity(1);
        let message = b"message";
        let rsg = create_rsg(&identity, message).unwrap();
        match validate_rsg(&rsg, message, None).unwrap() {
            RsgValidation::Valid { signer_hash } => assert_eq!(signer_hash, *identity.hash()),
            _ => panic!("expected valid rsg"),
        }
    }

    #[test]
    fn rsg_validation_rejects_wrong_message() {
        let identity = test_identity(2);
        let rsg = create_rsg(&identity, b"message").unwrap();
        assert!(matches!(
            validate_rsg(&rsg, b"other", None).unwrap(),
            RsgValidation::Invalid
        ));
    }

    #[test]
    fn rsg_validation_reports_wrong_required_signer() {
        let identity = test_identity(3);
        let other = test_identity(4);
        let rsg = create_rsg(&identity, b"message").unwrap();
        assert!(matches!(
            validate_rsg(&rsg, b"message", Some(*other.hash())).unwrap(),
            RsgValidation::WrongSigner { .. }
        ));
    }

    #[test]
    fn created_rsg_metadata_omits_legacy_note_field() {
        let identity = test_identity(5);
        let rsg = create_rsg(&identity, b"message").unwrap();
        let envelope = rsg_envelope(&rsg).unwrap().unwrap();
        let meta = envelope.map_get("meta").unwrap();
        assert!(meta.map_get("signer").is_some());
        assert!(meta.map_get("pubkey").is_some());
        assert!(meta.map_get("note").is_none());
    }

    #[test]
    fn rsm_metadata_output_hides_legacy_nil_note() {
        assert!(!should_print_rsm_meta_entry("note", &Value::Nil));
        assert!(should_print_rsm_meta_entry(
            "note",
            &Value::Str("kept".into())
        ));
        assert!(should_print_rsm_meta_entry("other", &Value::Nil));
    }

    #[test]
    fn release_rsm_structure_accepts_canonical_manifest_metadata() {
        let manifest = Value::Map(vec![(
            Value::Str("meta".into()),
            Value::Map(vec![
                (Value::Str("name".into()), Value::Str("pkg".into())),
                (Value::Str("version".into()), Value::Str("v1".into())),
                (Value::Str("origin".into()), Value::Bin(vec![0x11; 16])),
                (Value::Str("path".into()), Value::Str("group/repo".into())),
            ]),
        )]);

        assert_eq!(check_release_rsm_structure(&manifest), Ok(()));
    }

    #[test]
    fn release_rsm_structure_rejects_incomplete_or_unsafe_metadata() {
        let valid_meta = vec![
            (Value::Str("name".into()), Value::Str("pkg".into())),
            (Value::Str("version".into()), Value::Str("v1".into())),
            (Value::Str("origin".into()), Value::Bin(vec![0x11; 16])),
            (Value::Str("path".into()), Value::Str("group/repo".into())),
        ];
        let manifest = |meta: Vec<(Value, Value)>| {
            Value::Map(vec![(Value::Str("meta".into()), Value::Map(meta))])
        };

        let mut missing_version = valid_meta.clone();
        missing_version.retain(|(key, _)| !matches!(key, Value::Str(key) if key == "version"));
        assert_eq!(
            check_release_rsm_structure(&manifest(missing_version)),
            Err("Incomplete package data in manifest")
        );

        let mut unsafe_name = valid_meta.clone();
        unsafe_name[0].1 = Value::Str("group/pkg".into());
        assert_eq!(
            check_release_rsm_structure(&manifest(unsafe_name)),
            Err("Invalid data in release manifest")
        );

        let mut short_origin = valid_meta.clone();
        short_origin[2].1 = Value::Bin(vec![0x11; 15]);
        assert_eq!(
            check_release_rsm_structure(&manifest(short_origin)),
            Err("Invalid origin hash length in manifest")
        );

        let mut string_origin = valid_meta;
        string_origin[2].1 = Value::Str("0123456789abcdef".into());
        assert_eq!(
            check_release_rsm_structure(&manifest(string_origin)),
            Err("Invalid origin hash in manifest")
        );
    }

    #[test]
    fn rsg_ascii_wrapping_pads_rows_and_decodes() {
        let wrapped = wrap_rsg_ascii("abcdef");
        let lines: Vec<&str> = wrapped.lines().collect();

        assert_eq!(lines[0].len(), RSG_ASCII_ROW_WIDTH);
        assert_eq!(lines[1].len(), RSG_ASCII_ROW_WIDTH);
        assert_eq!(lines[2].len(), RSG_ASCII_ROW_WIDTH);
        assert_eq!(unwrap_rsg_ascii(&wrapped).unwrap(), "abcdef");
    }

    #[test]
    fn rsg_validation_accepts_wrapped_ascii_formats() {
        let identity = test_identity(5);
        let message = b"message";
        let rsg = create_rsg(&identity, message).unwrap();

        for format in [
            RsgOutputFormat::Hex,
            RsgOutputFormat::Base32,
            RsgOutputFormat::Base256,
            RsgOutputFormat::Base64,
        ] {
            let encoded = encode_rsg(&rsg, format);
            let wrapped = wrap_rsg_ascii(&encoded);
            let decoded = decode_rsg_data(wrapped.as_bytes()).unwrap();
            assert!(matches!(
                validate_rsg(&decoded, message, None).unwrap(),
                RsgValidation::Valid { .. }
            ));
        }
    }

    #[test]
    fn rsg_ascii_wrapping_preserves_multibyte_base256_glyphs() {
        let raw = (0u8..=96).collect::<Vec<_>>();
        let encoded = b256rep(&raw);
        let wrapped = wrap_rsg_ascii(&encoded);
        let lines: Vec<&str> = wrapped.lines().collect();

        assert_eq!(lines[1].chars().count(), RSG_ASCII_ROW_WIDTH);
        assert_eq!(lines[2].chars().count(), RSG_ASCII_ROW_WIDTH);
        assert_eq!(decode_rsg_data(wrapped.as_bytes()).unwrap(), raw);
    }

    #[test]
    fn find_identity_entry_matches_identity_or_destination_hash() {
        let entry = KnownDestinationEntry {
            dest_hash: [0x11; 16],
            identity_hash: [0x22; 16],
            public_key: [0x33; 64],
            app_data: None,
            hops: 1,
            received_at: 0.0,
            receiving_interface: rns_core::transport::types::InterfaceId(1),
            was_used: false,
            last_used_at: None,
            retained: false,
        };
        assert!(find_identity_entry(&[entry.clone()], [0x22; 16]).is_some());
        assert!(find_identity_entry(&[entry.clone()], [0x11; 16]).is_some());
        assert!(find_identity_entry(&[entry], [0x44; 16]).is_none());
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"abcdefg";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        assert_eq!(base64_decode(&base64_encode(b"ab")).unwrap(), b"ab");
        assert_eq!(base64_decode(&base64_encode(b"a")).unwrap(), b"a");
    }

    #[test]
    fn parse_identity_hash_requires_16_bytes() {
        assert!(parse_identity_hash("000102030405060708090a0b0c0d0e0f").is_ok());
        assert!(parse_identity_hash("000102").is_err());
    }

    #[test]
    fn default_aspects_are_stable() {
        assert_eq!(DEFAULT_ASPECTS, "rns.id");
    }
}
