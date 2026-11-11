//! Device signature verification: RSA-PSS with SHA-256 over the EEPROM
//! checksum, as upstream checks it with `cryptography`'s
//! `public_key.verify(signature, checksum, PSS(MGF1(SHA256), MAX_LENGTH),
//! SHA256)`.
//!
//! Only verification is implemented here. It uses the public key alone, so
//! there is no secret for its timing to leak.

use num_bigint::BigUint;
use rns_crypto::sha256::sha256;

/// Vendor keys upstream trusts (`known_keys`), as DER SubjectPublicKeyInfo.
pub const KNOWN_KEYS: [(&str, &str); 2] = [
    (
        "unsigned.io",
        "30819f300d06092a864886f70d010101050003818d0030818902818100bf831ebd99f43b477caf1a094bec829389da40653e8f1f83fc14bf1b98a3e1cc70e759c213a43f71e5a47eb56a9ca487f241335b3e6ff7cdde0ee0a1c75c698574aeba0485726b6a9dfc046b4188e3520271ee8555a8f405cf21f81f2575771d0b0887adea5dd53c1f594f72c66b5f14904ffc2e72206a6698a490d51ba1105b0203010001",
    ),
    (
        "unsigned.io",
        "30819f300d06092a864886f70d010101050003818d0030818902818100e5d46084e445595376bf7efd9c6ccf19d39abbc59afdb763207e4ff68b8d00ebffb63847aa2fe6dd10783d3ea63b55ac66f71ad885c20e223709f0d51ed5c6c0d0b093be9e1d165bb8a483a548b67a3f7a1e4580f50e75b306593fa6067ae259d3e297717bd7ff8c8f5b07f2bed89929a9a0321026cf3699524db98e2d18fb2d020300ff39",
    ),
];

/// An RSA public key.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

/// A DER element: its tag and contents, and the bytes after it.
fn der_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first & 0x80 == 0 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, &rest[count..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;

/// `RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }`, or the start of an
/// `RSAPrivateKey`, whose version comes first.
fn rsa_key_integers(der: &[u8], skip_version: bool) -> Option<PublicKey> {
    let (tag, body, _) = der_element(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rest = body;
    if skip_version {
        let (tag, _, after) = der_element(rest)?;
        if tag != INTEGER {
            return None;
        }
        rest = after;
    }
    let (tag, n, rest) = der_element(rest)?;
    if tag != INTEGER {
        return None;
    }
    let (tag, e, _) = der_element(rest)?;
    if tag != INTEGER {
        return None;
    }
    Some(PublicKey {
        n: BigUint::from_bytes_be(n),
        e: BigUint::from_bytes_be(e),
    })
}

/// Parse a DER SubjectPublicKeyInfo holding an RSA key.
pub fn parse_public_key(der: &[u8]) -> Option<PublicKey> {
    let (tag, body, _) = der_element(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, _algorithm, rest) = der_element(body)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, bits, _) = der_element(rest)?;
    if tag != BIT_STRING || bits.first() != Some(&0) {
        return None;
    }
    rsa_key_integers(&bits[1..], false)
}

/// The public half of a DER RSA private key, in PKCS#8 or PKCS#1 form, as
/// upstream's local `signing.key` holds it.
pub fn public_key_of_private(der: &[u8]) -> Option<PublicKey> {
    if let Some(key) = rsa_key_integers(der, true) {
        // PKCS#1: SEQUENCE { version, n, e, ... }; a PKCS#8 wrapper has an
        // AlgorithmIdentifier sequence where n would be, which is not an
        // INTEGER, so this fails for it.
        return Some(key);
    }
    let (tag, body, _) = der_element(der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (_, _, rest) = der_element(body)?; // version
    let (tag, _, rest) = der_element(rest)?; // algorithm
    if tag != SEQUENCE {
        return None;
    }
    let (tag, inner, _) = der_element(rest)?;
    if tag != OCTET_STRING {
        return None;
    }
    rsa_key_integers(inner, true)
}

/// Encode a public key as DER SubjectPublicKeyInfo, the form upstream
/// compares and stores keys in.
pub fn encode_public_key(key: &PublicKey) -> Vec<u8> {
    fn length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }
    fn element(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(length(body.len()));
        out.extend_from_slice(body);
        out
    }
    fn integer(value: &BigUint) -> Vec<u8> {
        let mut bytes = value.to_bytes_be();
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            bytes.insert(0, 0);
        }
        element(INTEGER, &bytes)
    }
    let rsa_key = element(SEQUENCE, &[integer(&key.n), integer(&key.e)].concat());
    let mut bits = vec![0u8];
    bits.extend(rsa_key);
    // rsaEncryption with NULL parameters.
    let algorithm = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    element(
        SEQUENCE,
        &[algorithm.to_vec(), element(BIT_STRING, &bits)].concat(),
    )
}

/// MGF1 with SHA-256.
fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&sha256(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Verify an RSA-PSS signature over `message` with SHA-256, MGF1(SHA-256)
/// and the maximum salt length, as `cryptography` does with
/// `PSS.MAX_LENGTH` (RFC 8017, RSASSA-PSS-VERIFY).
pub fn verify_pss(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    const H_LEN: usize = 32;
    let k = key.n.to_bytes_be().len();
    if signature.len() != k {
        return false;
    }
    let s = BigUint::from_bytes_be(signature);
    if s >= key.n {
        return false;
    }
    let mod_bits = key.n.bits() as usize;
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let m = s.modpow(&key.e, &key.n).to_bytes_be();
    if m.len() > em_len {
        return false;
    }
    let mut em = vec![0u8; em_len - m.len()];
    em.extend_from_slice(&m);

    // EMSA-PSS-VERIFY with sLen = emLen - hLen - 2.
    if em_len < H_LEN + 2 {
        return false;
    }
    let s_len = em_len - H_LEN - 2;
    if em[em_len - 1] != 0xbc {
        return false;
    }
    let db_len = em_len - H_LEN - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..H_LEN];
    let unused_bits = 8 * em_len - em_bits;
    let top_mask = 0xffu8 >> unused_bits;
    if masked_db[0] & !top_mask != 0 {
        return false;
    }
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(mgf1(h, db_len))
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= top_mask;
    let ps_len = db_len - s_len - 1;
    if db[..ps_len].iter().any(|b| *b != 0) || db[ps_len] != 0x01 {
        return false;
    }
    let salt = &db[ps_len + 1..];
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&sha256(message));
    m_prime.extend_from_slice(salt);
    sha256(&m_prime) == h
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with Python `cryptography`: a 1024-bit key, and a PSS
    // signature (MGF1-SHA256, MAX_LENGTH, SHA256) over MESSAGE.
    const PUBLIC_KEY: &str = include_str!("../tests/vectors/pss_public_key.hex");
    const SIGNATURE: &str = include_str!("../tests/vectors/pss_signature.hex");
    const MESSAGE: &[u8] = b"0123456789abcdef";

    #[test]
    fn verifies_a_cryptography_pss_signature() {
        let key = parse_public_key(&unhex(PUBLIC_KEY).unwrap()).unwrap();
        let signature = unhex(SIGNATURE).unwrap();
        assert!(verify_pss(&key, MESSAGE, &signature));
        assert!(!verify_pss(&key, b"0123456789abcdeX", &signature));
        let mut tampered = signature.clone();
        tampered[5] ^= 1;
        assert!(!verify_pss(&key, MESSAGE, &tampered));
    }

    #[test]
    fn vendor_keys_parse_and_reencode() {
        for (_, key_hex) in KNOWN_KEYS {
            let der = unhex(key_hex).unwrap();
            let key = parse_public_key(&der).expect("vendor key parses");
            assert_eq!(encode_public_key(&key), der);
        }
    }
}
