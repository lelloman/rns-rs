use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use rns_core::msgpack::{self, Value};
use rns_crypto::identity::Identity;
use rns_crypto::sha256::sha256;

use crate::{Error, Result};

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const NAMESPACE_GIT: &[u8] = b"git";
const HASH_ALGORITHM: &[u8] = b"sha256";
const SIG_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureStatus {
    pub signed: bool,
    pub valid: bool,
    pub signer_hash: Option<[u8; 16]>,
    pub author_match: bool,
    pub message: String,
}

#[derive(Debug, Default)]
struct Options {
    op: Option<String>,
    namespace: String,
    keyfile: Option<PathBuf>,
    sigfile: Option<PathBuf>,
    principal: Option<String>,
    file: Option<PathBuf>,
}

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = parse_options(args)?;
    match options.op.as_deref() {
        Some("sign") => {
            let keyfile = options
                .keyfile
                .as_deref()
                .ok_or_else(|| Error::msg("missing identity file"))?;
            let identity = rns_net::storage::load_identity(keyfile)?;
            let (message, output_path) = if let Some(file) = options.file.as_deref() {
                (fs::read(file)?, Some(PathBuf::from(format!("{}.sig", file.display()))))
            } else {
                let mut message = Vec::new();
                io::stdin().read_to_end(&mut message)?;
                (message, None)
            };
            let armored = sign_message(&identity, &message)?;
            if let Some(path) = output_path {
                fs::write(path, armored)?;
            } else {
                print!("{armored}");
            }
        }
        Some("find-principals") => {
            let sigfile = options
                .sigfile
                .as_deref()
                .ok_or_else(|| Error::msg("missing signature file"))?;
            let armored = fs::read_to_string(sigfile)?;
            let signer = find_principal(&armored)?;
            println!("{}", crate::util::hex(&signer));
        }
        Some("check-novalidate") => {
            let sigfile = options
                .sigfile
                .as_deref()
                .ok_or_else(|| Error::msg("missing signature file"))?;
            let armored = fs::read_to_string(sigfile)?;
            if !check_novalidate(&armored) {
                return Err(Error::msg("signature is not a valid Reticulum Git signature"));
            }
        }
        Some("verify") => {
            let sigfile = options
                .sigfile
                .as_deref()
                .ok_or_else(|| Error::msg("missing signature file"))?;
            let armored = fs::read_to_string(sigfile)?;
            let mut message = Vec::new();
            io::stdin().read_to_end(&mut message)?;
            let status = verify_message_signature(&armored, &message, options.principal.as_deref());
            if status.valid && status.author_match {
                println!("{}", status.message);
            } else {
                return Err(Error::msg(status.message));
            }
        }
        _ => return Err(Error::msg(usage())),
    }
    if options.namespace.as_bytes() != NAMESPACE_GIT {
        return Err(Error::msg("only git namespace is supported"));
    }
    Ok(())
}

fn parse_options<I>(args: I) -> Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut options = Options {
        namespace: "git".into(),
        ..Options::default()
    };
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-Y" => options.op = iter.next(),
            "-n" => {
                options.namespace = iter
                    .next()
                    .ok_or_else(|| Error::msg("missing namespace"))?;
            }
            "-f" => {
                options.keyfile = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| Error::msg("missing key/signers file"))?,
                ));
            }
            "-s" => {
                options.sigfile = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| Error::msg("missing signature file"))?,
                ));
            }
            "-I" => {
                options.principal = Some(
                    iter.next()
                        .ok_or_else(|| Error::msg("missing principal"))?,
                );
            }
            "-O" => {
                let _ = iter.next();
            }
            other if other.starts_with("-O") => {}
            "-h" | "--help" => return Err(Error::msg(usage())),
            other if other.starts_with('-') => {
                return Err(Error::msg(format!("unknown option {other}")));
            }
            other => options.file = Some(PathBuf::from(other)),
        }
    }
    Ok(options)
}

fn usage() -> &'static str {
    "usage: rngcs -Y <sign|find-principals|check-novalidate|verify> [-f KEY] [-s SIG] [-I PRINCIPAL] [FILE]"
}

pub fn sign_message(identity: &Identity, message: &[u8]) -> Result<String> {
    let rsg = create_rsg(identity, message)?;
    let ssh_pubkey = git_ssh_public_key(identity)?;
    let blob = create_ssh_signature(&ssh_pubkey, NAMESPACE_GIT, b"", HASH_ALGORITHM, &rsg);
    Ok(armor_ssh_signature(&blob))
}

pub fn find_principal(armored: &str) -> Result<[u8; 16]> {
    let sig = parse_armored_ssh_signature(armored)?;
    if sig.namespace != NAMESPACE_GIT {
        return Err(Error::msg("invalid signature namespace"));
    }
    let envelope = rsg_envelope(&sig.signature_data)?;
    let meta = envelope
        .map_get("meta")
        .ok_or_else(|| Error::msg("RSG is missing metadata"))?;
    let signer = meta
        .map_get("signer")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing signer"))?;
    signer
        .try_into()
        .map_err(|_| Error::msg("invalid signer hash length"))
}

pub fn check_novalidate(armored: &str) -> bool {
    parse_armored_ssh_signature(armored)
        .and_then(|sig| {
            if sig.namespace != NAMESPACE_GIT {
                return Err(Error::msg("invalid namespace"));
            }
            let _ = rsg_envelope(&sig.signature_data)?;
            Ok(())
        })
        .is_ok()
}

pub fn verify_message_signature(
    armored: &str,
    message: &[u8],
    principal: Option<&str>,
) -> SignatureStatus {
    match verify_message_signature_inner(armored, message, principal) {
        Ok(status) => status,
        Err(err) => SignatureStatus {
            signed: true,
            valid: false,
            signer_hash: None,
            author_match: false,
            message: err.to_string(),
        },
    }
}

fn verify_message_signature_inner(
    armored: &str,
    message: &[u8],
    principal: Option<&str>,
) -> Result<SignatureStatus> {
    let sig = parse_armored_ssh_signature(armored)?;
    if sig.namespace != NAMESPACE_GIT {
        return Err(Error::msg("invalid commit signature namespace"));
    }
    let signer_hash = validate_rsg(&sig.signature_data, message)?;
    if let Some(principal) = principal {
        if principal != crate::util::hex(&signer_hash) {
            return Ok(SignatureStatus {
                signed: true,
                valid: true,
                signer_hash: Some(signer_hash),
                author_match: false,
                message: "principal mismatch".into(),
            });
        }
    }
    let (required_signer, object_kind) = signature_required_signer(message)
        .ok_or_else(|| Error::msg("could not determine object signer"))?;
    if required_signer != crate::util::hex(&signer_hash) {
        return Ok(SignatureStatus {
            signed: true,
            valid: true,
            signer_hash: Some(signer_hash),
            author_match: false,
            message: format!(
                "{object_kind} not signed by expected identity <{}> (actual signer <{}>)",
                required_signer,
                crate::util::hex(&signer_hash)
            ),
        });
    }
    Ok(SignatureStatus {
        signed: true,
        valid: true,
        signer_hash: Some(signer_hash),
        author_match: true,
        message: format!(
            "Good \"git\" signature for commit, signed with Reticulum Identity key <{}>",
            crate::util::hex(&signer_hash)
        ),
    })
}

fn signature_required_signer(message: &[u8]) -> Option<(String, &'static str)> {
    let (tagger, is_tag) = extract_tag_tagger(message);
    if is_tag {
        tagger.map(|tagger| (tagger, "tag"))
    } else {
        extract_commit_author(message).map(|author| (author, "commit"))
    }
}

pub fn extract_commit_author(message: &[u8]) -> Option<String> {
    for line in message.split(|b| *b == b'\n') {
        if line.is_empty() {
            break;
        }
        let Some(rest) = line.strip_prefix(b"author ") else {
            continue;
        };
        let start = rest.iter().position(|b| *b == b'<')?;
        let end = rest.iter().position(|b| *b == b'>')?;
        if end <= start {
            return None;
        }
        return std::str::from_utf8(&rest[start + 1..end])
            .ok()
            .map(str::to_string);
    }
    None
}

pub fn extract_tag_tagger(message: &[u8]) -> (Option<String>, bool) {
    let mut is_tag = false;
    for line in message.split(|b| *b == b'\n') {
        if line.is_empty() {
            break;
        }
        if line.starts_with(b"tag ") {
            is_tag = true;
            continue;
        }
        let Some(rest) = line.strip_prefix(b"tagger ") else {
            continue;
        };
        let Some(start) = rest.iter().position(|b| *b == b'<') else {
            return (None, is_tag);
        };
        let Some(end) = rest.iter().position(|b| *b == b'>') else {
            return (None, is_tag);
        };
        if end <= start {
            return (None, is_tag);
        }
        return (
            std::str::from_utf8(&rest[start + 1..end])
                .ok()
                .map(str::to_string),
            is_tag,
        );
    }
    (None, is_tag)
}

fn create_rsg(identity: &Identity, message: &[u8]) -> Result<Vec<u8>> {
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("identity does not hold a public key"))?;
    let envelope = Value::Map(vec![
        (Value::Str("hashtype".into()), Value::Str("sha256".into())),
        (Value::Str("hash".into()), Value::Bin(sha256(message).to_vec())),
        (
            Value::Str("meta".into()),
            Value::Map(vec![
                (
                    Value::Str("signer".into()),
                    Value::Bin(identity.hash().to_vec()),
                ),
                (Value::Str("pubkey".into()), Value::Bin(public_key.to_vec())),
            ]),
        ),
    ]);
    let envelope = msgpack::pack(&envelope);
    let signature = identity
        .sign(&envelope)
        .map_err(|_| Error::msg("identity does not hold a private key"))?;
    let mut out = Vec::with_capacity(SIG_LEN + envelope.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&envelope);
    Ok(out)
}

fn validate_rsg(rsg: &[u8], message: &[u8]) -> Result<[u8; 16]> {
    if rsg.len() <= SIG_LEN {
        return Err(Error::msg("invalid RSG"));
    }
    let signature: [u8; SIG_LEN] = rsg[..SIG_LEN].try_into().unwrap();
    let envelope_bytes = &rsg[SIG_LEN..];
    let envelope = rsg_envelope(rsg)?;
    if envelope.map_get("hashtype").and_then(Value::as_str) != Some("sha256") {
        return Err(Error::msg("unsupported RSG hash type"));
    }
    let signed_hash = envelope
        .map_get("hash")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing hash"))?;
    if signed_hash != sha256(message).as_slice() {
        return Err(Error::msg("RSG hash does not match message"));
    }
    let meta = envelope
        .map_get("meta")
        .ok_or_else(|| Error::msg("RSG is missing metadata"))?;
    let public_key = meta
        .map_get("pubkey")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing public key"))?;
    let public_key: [u8; 64] = public_key
        .try_into()
        .map_err(|_| Error::msg("invalid public key length"))?;
    let identity = Identity::from_public_key(&public_key);
    let signer_hash = *identity.hash();
    let meta_signer = meta
        .map_get("signer")
        .and_then(Value::as_bin)
        .ok_or_else(|| Error::msg("RSG is missing signer"))?;
    if meta_signer != signer_hash {
        return Err(Error::msg("RSG signer does not match public key"));
    }
    if !identity.verify(&signature, envelope_bytes) {
        return Err(Error::msg("invalid signature"));
    }
    Ok(signer_hash)
}

fn rsg_envelope(rsg: &[u8]) -> Result<Value> {
    if rsg.len() <= SIG_LEN {
        return Err(Error::msg("invalid RSG"));
    }
    msgpack::unpack_exact(&rsg[SIG_LEN..])
        .map_err(|e| Error::msg(format!("invalid RSG envelope: {e}")))
}

fn git_ssh_public_key(identity: &Identity) -> Result<Vec<u8>> {
    let public_key = identity
        .get_public_key()
        .ok_or_else(|| Error::msg("identity does not hold a public key"))?;
    let mut out = Vec::new();
    push_ssh_string(&mut out, b"ssh-ed25519");
    push_ssh_string(&mut out, &public_key[32..]);
    Ok(out)
}

pub struct ParsedSshSignature {
    pub namespace: Vec<u8>,
    pub signature_data: Vec<u8>,
}

pub fn parse_armored_ssh_signature(armored: &str) -> Result<ParsedSshSignature> {
    let blob = unarmor_ssh_signature(armored)?;
    parse_ssh_signature(&blob)
}

fn create_ssh_signature(
    public_key_wire: &[u8],
    namespace: &[u8],
    reserved: &[u8],
    hash_algorithm: &[u8],
    signature_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SSHSIG_MAGIC);
    out.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    push_ssh_string(&mut out, public_key_wire);
    push_ssh_string(&mut out, namespace);
    push_ssh_string(&mut out, reserved);
    push_ssh_string(&mut out, hash_algorithm);
    push_ssh_string(&mut out, signature_data);
    out
}

fn parse_ssh_signature(blob: &[u8]) -> Result<ParsedSshSignature> {
    let mut offset = 0usize;
    if !blob.starts_with(SSHSIG_MAGIC) {
        return Err(Error::msg("invalid SSH signature magic"));
    }
    offset += SSHSIG_MAGIC.len();
    let version = read_u32(blob, &mut offset)?;
    if version != SSHSIG_VERSION {
        return Err(Error::msg(format!("unsupported SSH signature version {version}")));
    }
    let _public_key = read_ssh_string(blob, &mut offset)?;
    let namespace = read_ssh_string(blob, &mut offset)?;
    let _reserved = read_ssh_string(blob, &mut offset)?;
    let hash_algorithm = read_ssh_string(blob, &mut offset)?;
    if hash_algorithm != HASH_ALGORITHM {
        return Err(Error::msg("unsupported SSH signature hash algorithm"));
    }
    let signature_data = read_ssh_string(blob, &mut offset)?;
    Ok(ParsedSshSignature {
        namespace,
        signature_data,
    })
}

fn push_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32> {
    if data.len().saturating_sub(*offset) < 4 {
        return Err(Error::msg("truncated SSH signature"));
    }
    let value = u32::from_be_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(value)
}

fn read_ssh_string(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let len = read_u32(data, offset)? as usize;
    if data.len().saturating_sub(*offset) < len {
        return Err(Error::msg("truncated SSH signature string"));
    }
    let value = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

fn armor_ssh_signature(blob: &[u8]) -> String {
    let encoded = base64_encode(blob);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

fn unarmor_ssh_signature(armored: &str) -> Result<Vec<u8>> {
    let mut in_signature = false;
    let mut encoded = String::new();
    for line in armored.lines() {
        if line.contains("BEGIN SSH SIGNATURE") {
            in_signature = true;
            continue;
        }
        if line.contains("END SSH SIGNATURE") {
            break;
        }
        if in_signature {
            encoded.push_str(line.trim());
        }
    }
    if encoded.is_empty() {
        return Err(Error::msg("no SSH signature data found"));
    }
    base64_decode(&encoded).ok_or_else(|| Error::msg("invalid base64 SSH signature"))
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
        result.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
        result.push(if i + 1 < data.len() {
            CHARS[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        result.push(if i + 2 < data.len() {
            CHARS[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
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

pub fn extract_signature_from_commit_object(commit: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(commit).ok()?;
    let mut out = Vec::new();
    let mut in_signature = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("gpgsig ") {
            in_signature = true;
            out.push(rest.to_string());
        } else if in_signature && line.starts_with(' ') {
            out.push(line[1..].to_string());
        } else if in_signature {
            break;
        }
    }
    (!out.is_empty()).then(|| out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::OsRng;

    fn commit_message(author: &str) -> Vec<u8> {
        format!(
            "tree 0123456789012345678901234567890123456789\nauthor Tester <{author}> 0 +0000\ncommitter Tester <{author}> 0 +0000\n\nmessage\n"
        )
        .into_bytes()
    }

    fn tag_message(tagger: &str) -> Vec<u8> {
        format!(
            "object 0123456789012345678901234567890123456789\ntype commit\ntag v1\ntagger Tester <{tagger}> 0 +0000\n\nmessage\n"
        )
        .into_bytes()
    }

    #[test]
    fn sign_find_principal_and_verify_commit() {
        let identity = Identity::new(&mut OsRng);
        let author = crate::util::hex(identity.hash());
        let message = commit_message(&author);
        let armored = sign_message(&identity, &message).unwrap();

        assert_eq!(find_principal(&armored).unwrap(), *identity.hash());
        assert!(check_novalidate(&armored));

        let status = verify_message_signature(&armored, &message, Some(&author));
        assert!(status.valid);
        assert!(status.author_match);
        assert_eq!(status.signer_hash, Some(*identity.hash()));
    }

    #[test]
    fn verify_tag_uses_tagger_identity() {
        let identity = Identity::new(&mut OsRng);
        let tagger = crate::util::hex(identity.hash());
        let message = tag_message(&tagger);
        let armored = sign_message(&identity, &message).unwrap();

        let status = verify_message_signature(&armored, &message, Some(&tagger));
        assert!(status.valid);
        assert!(status.author_match);
        assert_eq!(extract_tag_tagger(&message), (Some(tagger), true));
    }

    #[test]
    fn verify_rejects_author_mismatch() {
        let identity = Identity::new(&mut OsRng);
        let message = commit_message("00112233445566778899aabbccddeeff");
        let armored = sign_message(&identity, &message).unwrap();

        let status = verify_message_signature(&armored, &message, None);
        assert!(status.valid);
        assert!(!status.author_match);
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let identity = Identity::new(&mut OsRng);
        let author = crate::util::hex(identity.hash());
        let message = commit_message(&author);
        let armored = sign_message(&identity, &message).unwrap();

        let status = verify_message_signature(&armored, b"tampered", None);
        assert!(!status.valid);
    }

    #[test]
    fn extracts_multiline_gpgsig_from_commit_object() {
        let commit = b"tree abc\ngpgsig -----BEGIN SSH SIGNATURE-----\n line1\n line2\n -----END SSH SIGNATURE-----\nauthor A <a> 0 +0000\n\nmsg\n";
        let sig = extract_signature_from_commit_object(commit).unwrap();
        assert!(sig.contains("BEGIN SSH SIGNATURE"));
        assert!(sig.contains("line1"));
        assert!(sig.contains("END SSH SIGNATURE"));
    }
}
