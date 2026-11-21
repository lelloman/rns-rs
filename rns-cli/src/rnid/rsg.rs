//! Reticulum signature containers: creating, wrapping and validating them.

use super::*;

/// A created signature: written as bytes, or printed as text.
pub(super) enum Rsg {
    Bin(Vec<u8>),
    Text(String),
}

/// `get_rsg_hash`.
pub(super) fn rsg_hash(message: &RsgMessage) -> Result<[u8; 32], String> {
    match message {
        RsgMessage::Bytes(bytes) => Ok(sha256(bytes)),
        RsgMessage::File(path) => {
            let mut file = fs::File::open(path).map_err(|e| io_error(&e, path))?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = file.read(&mut buf).map_err(|e| io_error(&e, path))?;
                if n == 0 {
                    break;
                }
                hasher.update(buf.get(..n).unwrap_or_default());
            }
            Ok(hasher.digest())
        }
    }
}

pub(super) fn map_get<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
        .map(|(_, v)| v)
}

pub(super) fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Nil => "NoneType",
        Value::Bool(_) => "bool",
        Value::UInt(_) | Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Bin(_) => "bytes",
        Value::Str(_) => "str",
        Value::Array(_) => "list",
        Value::Map(_) => "dict",
    }
}

pub(super) fn not_iterable(value: &Value) -> String {
    format!("argument of type '{}' is not iterable", type_name(value))
}

pub(super) fn clone_identity(identity: &Identity) -> Option<Identity> {
    match identity.get_private_key() {
        Some(private) => Some(Identity::from_private_key(&private)),
        None => Identity::from_public_key(&identity.get_public_key()?).ok(),
    }
}

/// `create_rsg`.
pub(super) fn create_rsg(
    signer: &Identity,
    message: RsgMessage,
    embed: bool,
    meta: Option<&Vec<(String, Entry)>>,
    output: &str,
) -> Result<Rsg, String> {
    let (Some(_), Some(public)) = (signer.get_private_key(), signer.get_public_key()) else {
        return Err(format!("{} does not hold a private key", id_str(signer)));
    };
    let mut meta_map = vec![
        (
            Value::Str("signer".into()),
            Value::Bin(signer.hash().to_vec()),
        ),
        (Value::Str("pubkey".into()), Value::Bin(public.to_vec())),
    ];
    if let Some(meta) = meta.filter(|m| !m.is_empty()) {
        for (key, entry) in meta {
            if key != "signer" && key != "pubkey" {
                meta_map.push((Value::Str(key.clone()), entry_value(entry)));
            }
        }
    }
    let mut signed = vec![
        (Value::Str("hashtype".into()), Value::Str("sha256".into())),
        (
            Value::Str("hash".into()),
            Value::Bin(rsg_hash(&message)?.to_vec()),
        ),
        (Value::Str("meta".into()), Value::Map(meta_map)),
    ];
    if embed {
        let bytes = match message {
            RsgMessage::Bytes(bytes) => bytes.to_vec(),
            RsgMessage::File(path) => fs::read(path).map_err(|e| io_error(&e, path))?,
        };
        signed.push((Value::Str("message".into()), Value::Bin(bytes)));
    }
    let envelope = msgpack::pack(&Value::Map(signed));
    let signature = signer.sign(&envelope).map_err(|e| format!("{e:?}"))?;
    let mut rsg_data = signature.to_vec();
    rsg_data.extend_from_slice(&envelope);
    Ok(match output {
        "hex" => Rsg::Text(hexrep(&rsg_data)),
        "base32" => Rsg::Text(b32encode(&rsg_data)),
        "base64" => Rsg::Text(urlsafe_b64encode(&rsg_data)),
        "base256" => Rsg::Text(rns_core::display::b256rep(&rsg_data)),
        _ => Rsg::Bin(rsg_data),
    })
}

/// A ConfigObj value as umsgpack packs it.
pub(super) fn entry_value(entry: &Entry) -> Value {
    match entry {
        Entry::Str(s) => Value::Str(s.clone()),
        Entry::Int(n) if *n >= 0 => Value::UInt(*n as u64),
        Entry::Int(n) => Value::Int(*n),
        Entry::Float(f) => Value::Float(*f),
        Entry::Bool(b) => Value::Bool(*b),
        Entry::List(items) => Value::Array(items.iter().map(entry_value).collect()),
        Entry::Section(section) => Value::Map(
            section
                .entries()
                .iter()
                .map(|(k, v)| (Value::Str(k.clone()), entry_value(v)))
                .collect(),
        ),
    }
}

/// `wrap_rsg`: rows of 64 characters between a header and a footer, the
/// last row padded with `=`.
pub(super) fn wrap_rsg(rsg: &str) -> String {
    let header_len = RSG_ASCII_HEADER.chars().count();
    let footer_len = RSG_ASCII_FOOTER.chars().count();
    let mut wrapped = format!(
        "{RSG_ASCII_HEADER}{}\n",
        "#".repeat(RSG_ASCII_ROW_WIDTH - header_len)
    );
    let chars: Vec<char> = rsg.chars().collect();
    for chunk in chars.chunks(RSG_ASCII_ROW_WIDTH) {
        let mut row: String = chunk.iter().collect();
        row.push_str(&"=".repeat(RSG_ASCII_ROW_WIDTH - chunk.len()));
        wrapped.push_str(&row);
        wrapped.push('\n');
    }
    wrapped.push_str(&"#".repeat(RSG_ASCII_ROW_WIDTH - footer_len));
    wrapped.push_str(RSG_ASCII_FOOTER);
    wrapped
}

/// `extract_signed_rsg_data`.
pub(super) fn extract_signed_rsg_data(rsg: &[u8]) -> Option<Value> {
    msgpack::unpack_exact(rsg.get(SIGLEN..)?).ok()
}

/// `validate_rsg`: whether the signature is valid, the signed data and
/// the identity that signed it.
pub(super) fn validate_rsg(
    rsg_data: &[u8],
    message: RsgMessage,
    required_signer: &Signer,
) -> Result<(bool, Option<Value>, Option<Identity>), String> {
    if let RsgMessage::Bytes(bytes) = &message {
        if bytes.is_empty() {
            return Err("No message specified for rsg validation".into());
        }
    }
    let rsg_hash = rsg_hash(&message)?;
    if rsg_data.len() == SIGLEN {
        return Err("Cannot validate legacy rsg format".into());
    }
    let Some((signature, envelope)) = rsg_data
        .split_first_chunk::<SIGLEN>()
        .filter(|(_, envelope)| !envelope.is_empty())
    else {
        return Ok((false, None, None));
    };
    let Ok(signed_data) = msgpack::unpack_exact(envelope) else {
        return Ok((false, None, None));
    };
    let signed = match &signed_data {
        Value::Map(entries) => entries,
        Value::Array(_) | Value::Str(_) => return Ok((false, None, None)),
        other => return Err(not_iterable(other)),
    };
    let (Some(hashtype), Some(hash)) = (map_get(signed, "hashtype"), map_get(signed, "hash"))
    else {
        return Ok((false, None, None));
    };
    if !matches!(hashtype, Value::Str(s) if s == "sha256") {
        return Ok((false, None, None));
    }
    let meta = match map_get(signed, "meta") {
        None => return Ok((false, None, None)),
        Some(Value::Map(meta)) => meta,
        Some(Value::Array(_) | Value::Str(_)) => return Ok((false, None, None)),
        Some(other) => return Err(not_iterable(other)),
    };
    if map_get(meta, "signer").is_none() {
        return Ok((false, None, None));
    }
    let Some(pubkey) = map_get(meta, "pubkey") else {
        return Ok((false, None, None));
    };
    let signing_identity = match required_signer {
        Signer::Identity(identity) => match clone_identity(identity) {
            Some(identity) => identity,
            None => return Ok((false, None, None)),
        },
        _ => {
            let Value::Bin(pubkey) = pubkey else {
                return Ok((false, None, None));
            };
            let Ok(key) = <&[u8; KEYSIZE]>::try_from(pubkey.as_slice()) else {
                return Ok((false, None, None));
            };
            match Identity::from_public_key(key) {
                Ok(identity) => identity,
                Err(_) => return Ok((false, None, None)),
            }
        }
    };
    let required_hash = match required_signer {
        Signer::Hash(hash) => hash.clone(),
        _ => signing_identity.hash().to_vec(),
    };
    if signing_identity.hash()[..] != required_hash[..] {
        return Ok((false, None, Some(signing_identity)));
    }
    if !matches!(hash, Value::Bin(h) if h[..] == rsg_hash[..]) {
        return Ok((false, None, Some(signing_identity)));
    }
    let valid = signing_identity.verify(signature, envelope);
    Ok((valid, Some(signed_data.clone()), Some(signing_identity)))
}

/// `rsg_meta_from_file`.
pub(super) fn rsg_meta_from_file(
    path: &str,
    spec_path: Option<&str>,
) -> Result<Vec<(String, Entry)>, String> {
    let read = |p: &str| fs::read_to_string(p).map_err(|e| io_error(&e, p));
    let spec = match spec_path {
        Some(spec_path) => Some(configobj::parse(&read(spec_path)?)?),
        None => None,
    };
    let mut parsed = configobj::parse(&read(path)?)?;
    if let Some(spec) = spec {
        if !configobj::validate(&mut parsed, &spec) {
            return Err("Metadata did not pass spec validation".into());
        }
    }
    Ok(parsed.entries())
}
