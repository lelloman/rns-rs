//! SAM v3.1 protocol client for I2P.
//!
//! Implements the Simple Anonymous Messaging protocol used to communicate
//! with a local I2P router. All operations are blocking TCP-based.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// SAM protocol version we speak.
const SAM_VERSION: &str = "3.1";

/// Default connection timeout for SAM sockets.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read timeout for SAM command responses.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

// --- I2P Base64 ---

/// I2P uses a non-standard base64 alphabet: `A-Za-z0-9-~` instead of `+/`.
const I2P_BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

/// Decode table: maps ASCII byte to 6-bit value (255 = invalid).
fn i2p_base64_decode_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    for (i, &ch) in I2P_BASE64_ALPHABET.iter().enumerate() {
        table[ch as usize] = i as u8;
    }
    // Also accept '=' as padding (value irrelevant, handled separately)
    table[b'=' as usize] = 0;
    table
}

/// Encode binary data to I2P base64.
pub fn i2p_base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(I2P_BASE64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(I2P_BASE64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(I2P_BASE64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(I2P_BASE64_ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode I2P base64 string to binary data.
pub fn i2p_base64_decode(s: &str) -> Result<Vec<u8>, SamError> {
    let table = i2p_base64_decode_table();
    let bytes = s.as_bytes();

    if bytes.len() % 4 != 0 {
        return Err(SamError::InvalidResponse(format!(
            "invalid I2P base64 length: {}",
            bytes.len()
        )));
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);

    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad_count = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                pad_count += 1;
                vals[i] = 0;
            } else {
                let v = table[b as usize];
                if v == 255 {
                    return Err(SamError::InvalidResponse(format!(
                        "invalid I2P base64 character: {:?}",
                        b as char
                    )));
                }
                vals[i] = v;
            }
        }

        let triple = (vals[0] as u32) << 18
            | (vals[1] as u32) << 12
            | (vals[2] as u32) << 6
            | (vals[3] as u32);

        out.push((triple >> 16) as u8);
        if pad_count < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad_count < 1 {
            out.push(triple as u8);
        }
    }

    Ok(out)
}

// --- Error type ---

/// Errors from SAM protocol operations.
#[derive(Debug)]
pub enum SamError {
    /// Underlying I/O error.
    Io(io::Error),
    /// SAM router returned an error result (e.g., CANT_REACH_PEER).
    Protocol(String),
    /// Could not parse the SAM response.
    InvalidResponse(String),
}

impl fmt::Display for SamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SamError::Io(e) => write!(f, "SAM I/O error: {}", e),
            SamError::Protocol(msg) => write!(f, "SAM protocol error: {}", msg),
            SamError::InvalidResponse(msg) => write!(f, "SAM invalid response: {}", msg),
        }
    }
}

impl From<io::Error> for SamError {
    fn from(e: io::Error) -> Self {
        SamError::Io(e)
    }
}

// --- Types ---

/// An I2P destination (public key, typically ~387 bytes raw).
#[derive(Clone, Debug)]
pub struct Destination {
    /// Raw binary destination bytes.
    pub data: Vec<u8>,
}

impl Destination {
    /// Encode destination to I2P base64.
    pub fn to_i2p_base64(&self) -> String {
        i2p_base64_encode(&self.data)
    }

    /// Decode destination from I2P base64.
    pub fn from_i2p_base64(s: &str) -> Result<Self, SamError> {
        let data = i2p_base64_decode(s)?;
        Ok(Destination { data })
    }

    /// Compute the .b32.i2p address from this destination.
    /// SHA-256 of raw destination bytes, base32-encoded, lowercase + ".b32.i2p".
    pub fn base32_address(&self) -> String {
        let hash = rns_crypto::sha256::sha256(&self.data);
        let encoded = base32_encode(&hash);
        format!("{}.b32.i2p", encoded)
    }
}

/// A generated keypair (destination + private key material).
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub destination: Destination,
    /// Raw binary private key bytes.
    pub private_key: Vec<u8>,
}

// --- Base32 encoding (RFC 4648, lowercase, no padding) ---

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes to base32 (lowercase, no padding).
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

// --- SAM response parsing ---

/// Parse a key=value pair from a SAM response token.
fn parse_kv(token: &str) -> Option<(&str, &str)> {
    let eq = token.find('=')?;
    Some((&token[..eq], &token[eq + 1..]))
}

/// Read a single newline-terminated line from a SAM socket.
///
/// Reads byte-by-byte to avoid buffering past the newline.
/// BufReader would consume and lose data beyond the line boundary,
/// which is catastrophic for STREAM CONNECT/ACCEPT where the socket
/// transitions to a raw data pipe after the response line.
fn read_line(stream: &mut TcpStream) -> Result<String, SamError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read_exact(&mut byte) {
            Ok(()) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            Err(e) => return Err(SamError::Io(e)),
        }
    }
    String::from_utf8(line)
        .map_err(|e| SamError::InvalidResponse(format!("non-UTF8 SAM response: {}", e)))
}

/// Open a fresh TCP connection to the SAM bridge and perform HELLO handshake.
fn hello_connect(sam_addr: &SocketAddr) -> Result<TcpStream, SamError> {
    let mut stream = TcpStream::connect_timeout(sam_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(READ_TIMEOUT))?;

    // Send HELLO
    write!(stream, "HELLO VERSION MIN={v} MAX={v}\n", v = SAM_VERSION)?;
    stream.flush()?;

    // Read response
    let line = read_line(&mut stream)?;
    // Expected: "HELLO REPLY RESULT=OK VERSION=3.1"
    let resp = parse_sam_response(&line)?;
    if resp.command != "HELLO" || resp.subcommand != "REPLY" {
        return Err(SamError::InvalidResponse(format!(
            "expected HELLO REPLY, got: {}",
            line
        )));
    }
    check_result(&resp)?;

    Ok(stream)
}

/// Parsed SAM response.
struct SamResponse {
    command: String,
    subcommand: String,
    params: Vec<(String, String)>,
}

impl SamResponse {
    fn get(&self, key: &str) -> Option<&str> {
        for (k, v) in &self.params {
            if k == key {
                return Some(v);
            }
        }
        None
    }
}

/// Parse a SAM response line into command, subcommand, and key=value params.
/// Some values (like DESTINATION) can contain spaces if they are the last param,
/// but SAM v3.1 generally uses space-separated KEY=VALUE pairs.
fn parse_sam_response(line: &str) -> Result<SamResponse, SamError> {
    let mut parts = line.splitn(3, ' ');
    let command = parts
        .next()
        .ok_or_else(|| SamError::InvalidResponse("empty response".into()))?
        .to_string();
    let subcommand = parts
        .next()
        .unwrap_or("")
        .to_string();
    let rest = parts.next().unwrap_or("");

    let mut params = Vec::new();
    // Parse key=value pairs. Values can contain base64 which has no spaces,
    // so simple space-splitting works.
    for token in rest.split_whitespace() {
        if let Some((k, v)) = parse_kv(token) {
            params.push((k.to_string(), v.to_string()));
        }
    }

    Ok(SamResponse {
        command,
        subcommand,
        params,
    })
}

/// Check if SAM response has RESULT=OK, return error otherwise.
fn check_result(resp: &SamResponse) -> Result<(), SamError> {
    match resp.get("RESULT") {
        Some("OK") => Ok(()),
        Some(result) => {
            let message = resp.get("MESSAGE").unwrap_or("(no message)");
            Err(SamError::Protocol(format!(
                "RESULT={} MESSAGE={}",
                result, message
            )))
        }
        None => Ok(()), // Some responses don't have RESULT
    }
}

// --- Public API ---

/// Generate a new I2P destination keypair via SAM.
/// Uses Ed25519 (SIGNATURE_TYPE=7).
pub fn dest_generate(sam_addr: &SocketAddr) -> Result<KeyPair, SamError> {
    let mut stream = hello_connect(sam_addr)?;

    write!(stream, "DEST GENERATE SIGNATURE_TYPE=7\n")?;
    stream.flush()?;

    let line = read_line(&mut stream)?;
    let resp = parse_sam_response(&line)?;

    if resp.command != "DEST" || resp.subcommand != "REPLY" {
        return Err(SamError::InvalidResponse(format!(
            "expected DEST REPLY, got: {}",
            line
        )));
    }

    let pub_b64 = resp.get("PUB").ok_or_else(|| {
        SamError::InvalidResponse("DEST REPLY missing PUB".into())
    })?;
    let priv_b64 = resp.get("PRIV").ok_or_else(|| {
        SamError::InvalidResponse("DEST REPLY missing PRIV".into())
    })?;

    let dest_data = i2p_base64_decode(pub_b64)?;
    let priv_data = i2p_base64_decode(priv_b64)?;

    Ok(KeyPair {
        destination: Destination { data: dest_data },
        private_key: priv_data,
    })
}

/// Create a STREAM session. Returns the control socket which must remain open
/// for the session's lifetime.
pub fn session_create(
    sam_addr: &SocketAddr,
    session_id: &str,
    private_key_b64: &str,
) -> Result<TcpStream, SamError> {
    let mut stream = hello_connect(sam_addr)?;

    write!(
        stream,
        "SESSION CREATE STYLE=STREAM ID={} DESTINATION={} SIGNATURE_TYPE=7\n",
        session_id, private_key_b64,
    )?;
    stream.flush()?;

    let line = read_line(&mut stream)?;
    let resp = parse_sam_response(&line)?;

    if resp.command != "SESSION" || resp.subcommand != "STATUS" {
        return Err(SamError::InvalidResponse(format!(
            "expected SESSION STATUS, got: {}",
            line
        )));
    }
    check_result(&resp)?;

    // Control socket stays open
    Ok(stream)
}

/// Connect to a remote I2P destination via STREAM CONNECT.
/// Returns a bidirectional data stream.
pub fn stream_connect(
    sam_addr: &SocketAddr,
    session_id: &str,
    destination: &str,
) -> Result<TcpStream, SamError> {
    let mut stream = hello_connect(sam_addr)?;

    write!(
        stream,
        "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
        session_id, destination,
    )?;
    stream.flush()?;

    let line = read_line(&mut stream)?;
    let resp = parse_sam_response(&line)?;

    if resp.command != "STREAM" || resp.subcommand != "STATUS" {
        return Err(SamError::InvalidResponse(format!(
            "expected STREAM STATUS, got: {}",
            line
        )));
    }
    check_result(&resp)?;

    // After RESULT=OK, the TCP socket becomes a raw data pipe
    // Clear timeouts for the data phase
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    Ok(stream)
}

/// Accept an incoming connection on a session via STREAM ACCEPT.
/// Returns the data stream and the remote peer's destination.
pub fn stream_accept(
    sam_addr: &SocketAddr,
    session_id: &str,
) -> Result<(TcpStream, Destination), SamError> {
    let mut stream = hello_connect(sam_addr)?;

    write!(
        stream,
        "STREAM ACCEPT ID={} SILENT=false\n",
        session_id,
    )?;
    stream.flush()?;

    let line = read_line(&mut stream)?;
    let resp = parse_sam_response(&line)?;

    if resp.command != "STREAM" || resp.subcommand != "STATUS" {
        return Err(SamError::InvalidResponse(format!(
            "expected STREAM STATUS, got: {}",
            line
        )));
    }
    check_result(&resp)?;

    // After RESULT=OK, the remote destination is sent as a line of base64 + newline
    // before the data phase begins.
    let dest_line = read_line(&mut stream)?;
    let remote_dest = Destination::from_i2p_base64(dest_line.trim())?;

    // Clear timeouts for the data phase
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    Ok((stream, remote_dest))
}

/// Look up a .b32.i2p name (or other I2P name) to a full destination.
/// Opens a fresh SAM connection for the lookup.
pub fn naming_lookup(
    sam_addr: &SocketAddr,
    name: &str,
) -> Result<Destination, SamError> {
    let mut stream = hello_connect(sam_addr)?;
    naming_lookup_on(&mut stream, name)
}

/// Perform a NAMING LOOKUP on an existing SAM socket.
/// Use this for `NAME=ME` on a session control socket, since the `ME`
/// name requires a session context on the same connection.
pub fn naming_lookup_on(
    stream: &mut TcpStream,
    name: &str,
) -> Result<Destination, SamError> {
    write!(stream, "NAMING LOOKUP NAME={}\n", name)?;
    stream.flush()?;

    let line = read_line(stream)?;
    let resp = parse_sam_response(&line)?;

    if resp.command != "NAMING" || resp.subcommand != "REPLY" {
        return Err(SamError::InvalidResponse(format!(
            "expected NAMING REPLY, got: {}",
            line
        )));
    }
    check_result(&resp)?;

    let value = resp.get("VALUE").ok_or_else(|| {
        SamError::InvalidResponse("NAMING REPLY missing VALUE".into())
    })?;

    Destination::from_i2p_base64(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- I2P base64 tests ---

    #[test]
    fn base64_encode_empty() {
        assert_eq!(i2p_base64_encode(b""), "");
    }

    #[test]
    fn base64_roundtrip() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = i2p_base64_encode(&data);
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_known_value() {
        // "Hello" in standard base64 is "SGVsbG8=" using +/ alphabet
        // In I2P base64 with -~ alphabet, same result since no +/ chars involved
        let encoded = i2p_base64_encode(b"Hello");
        assert_eq!(encoded, "SGVsbG8=");
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_i2p_specific_chars() {
        // Test that -~ are used instead of +/
        // Standard base64 of [0xFB, 0xEF, 0xBE] is "++++", which in I2P is "----"
        let data = [0xFB, 0xEF, 0xBE];
        let encoded = i2p_base64_encode(&data);
        assert!(encoded.contains('-') || encoded.contains('~'));
        // roundtrip
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_all_alphabet_chars_roundtrip() {
        // Generate data that produces all 64 base64 characters
        let data: Vec<u8> = (0..48).collect();
        let encoded = i2p_base64_encode(&data);
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_padding_1() {
        // 1 byte -> 4 chars with 2 padding
        let encoded = i2p_base64_encode(&[0xFF]);
        assert_eq!(encoded.len(), 4);
        assert!(encoded.ends_with("=="));
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, vec![0xFF]);
    }

    #[test]
    fn base64_padding_2() {
        // 2 bytes -> 4 chars with 1 padding
        let encoded = i2p_base64_encode(&[0xFF, 0xFE]);
        assert_eq!(encoded.len(), 4);
        assert!(encoded.ends_with('='));
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFE]);
    }

    #[test]
    fn base64_no_padding() {
        // 3 bytes -> 4 chars, no padding
        let encoded = i2p_base64_encode(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(encoded.len(), 4);
        assert!(!encoded.contains('='));
        let decoded = i2p_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFE, 0xFD]);
    }

    #[test]
    fn base64_decode_invalid_char() {
        let result = i2p_base64_decode("!!!=");
        assert!(result.is_err());
    }

    #[test]
    fn base64_decode_invalid_length() {
        let result = i2p_base64_decode("ABC");
        assert!(result.is_err());
    }

    // --- Base32 tests ---

    #[test]
    fn base32_encode_empty() {
        assert_eq!(base32_encode(&[]), "");
    }

    #[test]
    fn base32_encode_known() {
        // "Hello" -> base32 is "jbswy3dp" (lowercase)
        let result = base32_encode(b"Hello");
        assert_eq!(result, "jbswy3dp");
    }

    #[test]
    fn base32_encode_sha256() {
        // SHA256 of empty is known, just verify it produces a 52-char string
        let hash = rns_crypto::sha256::sha256(b"");
        let encoded = base32_encode(&hash);
        // 32 bytes * 8 bits / 5 bits = 51.2 -> 52 chars
        assert_eq!(encoded.len(), 52);
        // All lowercase letters and digits 2-7
        assert!(encoded.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }

    // --- Destination tests ---

    #[test]
    fn destination_base32_address() {
        let dest = Destination {
            data: vec![0x42; 387], // dummy destination data
        };
        let addr = dest.base32_address();
        assert!(addr.ends_with(".b32.i2p"));
        // 52 chars of base32 + ".b32.i2p" = 60 chars
        assert_eq!(addr.len(), 60);
    }

    #[test]
    fn destination_roundtrip_base64() {
        let data: Vec<u8> = (0..=255).cycle().take(387).collect();
        let dest = Destination { data: data.clone() };
        let b64 = dest.to_i2p_base64();
        let dest2 = Destination::from_i2p_base64(&b64).unwrap();
        assert_eq!(dest2.data, data);
    }

    // --- SAM response parsing tests ---

    #[test]
    fn parse_hello_reply() {
        let line = "HELLO REPLY RESULT=OK VERSION=3.1";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.command, "HELLO");
        assert_eq!(resp.subcommand, "REPLY");
        assert_eq!(resp.get("RESULT"), Some("OK"));
        assert_eq!(resp.get("VERSION"), Some("3.1"));
    }

    #[test]
    fn parse_session_status_ok() {
        let line = "SESSION STATUS RESULT=OK DESTINATION=AAAA";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.command, "SESSION");
        assert_eq!(resp.subcommand, "STATUS");
        assert_eq!(resp.get("RESULT"), Some("OK"));
        assert_eq!(resp.get("DESTINATION"), Some("AAAA"));
    }

    #[test]
    fn parse_session_status_error() {
        let line = "SESSION STATUS RESULT=DUPLICATED_ID";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.get("RESULT"), Some("DUPLICATED_ID"));
        let err = check_result(&resp);
        assert!(err.is_err());
    }

    #[test]
    fn parse_stream_status_error() {
        let line = "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=unreachable";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.get("RESULT"), Some("CANT_REACH_PEER"));
        assert_eq!(resp.get("MESSAGE"), Some("unreachable"));
        let err = check_result(&resp);
        assert!(err.is_err());
        if let Err(SamError::Protocol(msg)) = err {
            assert!(msg.contains("CANT_REACH_PEER"));
        }
    }

    #[test]
    fn parse_naming_reply() {
        let line = "NAMING REPLY RESULT=OK NAME=test.b32.i2p VALUE=AAAA";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.command, "NAMING");
        assert_eq!(resp.subcommand, "REPLY");
        assert_eq!(resp.get("NAME"), Some("test.b32.i2p"));
        assert_eq!(resp.get("VALUE"), Some("AAAA"));
    }

    #[test]
    fn parse_naming_not_found() {
        let line = "NAMING REPLY RESULT=KEY_NOT_FOUND";
        let resp = parse_sam_response(line).unwrap();
        let err = check_result(&resp);
        assert!(err.is_err());
    }

    #[test]
    fn parse_dest_reply() {
        let line = "DEST REPLY PUB=AAAA PRIV=BBBB";
        let resp = parse_sam_response(line).unwrap();
        assert_eq!(resp.command, "DEST");
        assert_eq!(resp.subcommand, "REPLY");
        assert_eq!(resp.get("PUB"), Some("AAAA"));
        assert_eq!(resp.get("PRIV"), Some("BBBB"));
    }

    #[test]
    fn parse_stream_status_timeout() {
        let line = "STREAM STATUS RESULT=TIMEOUT";
        let resp = parse_sam_response(line).unwrap();
        let err = check_result(&resp);
        assert!(err.is_err());
        if let Err(SamError::Protocol(msg)) = err {
            assert!(msg.contains("TIMEOUT"));
        }
    }

    #[test]
    fn check_result_ok() {
        let line = "TEST REPLY RESULT=OK";
        let resp = parse_sam_response(line).unwrap();
        assert!(check_result(&resp).is_ok());
    }

    #[test]
    fn check_result_no_result_field() {
        let line = "TEST REPLY FOO=BAR";
        let resp = parse_sam_response(line).unwrap();
        // No RESULT field is considered OK
        assert!(check_result(&resp).is_ok());
    }

    #[test]
    fn sam_error_display() {
        let io_err = SamError::Io(io::Error::new(io::ErrorKind::Other, "test"));
        assert!(format!("{}", io_err).contains("test"));

        let proto_err = SamError::Protocol("CANT_REACH_PEER".into());
        assert!(format!("{}", proto_err).contains("CANT_REACH_PEER"));

        let inv_err = SamError::InvalidResponse("bad".into());
        assert!(format!("{}", inv_err).contains("bad"));
    }
}
