use std::io::{self, Read, Write};

use crate::encode::to_base64;
use crate::http::HttpRequest;
use crate::sha1::sha1;

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-5AB5DC11D045";

/// WebSocket frame opcodes.
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// A decoded WebSocket frame.
pub struct WsFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Check if an HTTP request is a WebSocket upgrade.
pub fn is_upgrade(req: &HttpRequest) -> bool {
    req.headers
        .get("upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Complete the WebSocket handshake (write 101 response).
pub fn do_handshake(stream: &mut dyn Write, req: &HttpRequest) -> io::Result<()> {
    let key = req
        .headers
        .get("sec-websocket-key")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing Sec-WebSocket-Key"))?;

    let accept = compute_accept(key);

    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept
    )?;
    stream.flush()
}

fn compute_accept(key: &str) -> String {
    let combined = format!("{}{}", key, WS_MAGIC);
    let hash = sha1(combined.as_bytes());
    to_base64(&hash)
}

/// Read a single WebSocket frame. Handles masking.
pub fn read_frame(stream: &mut dyn Read) -> io::Result<WsFrame> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;

    let _fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let len_byte = head[1] & 0x7F;

    let payload_len: usize = if len_byte <= 125 {
        len_byte as usize
    } else if len_byte == 126 {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        u16::from_be_bytes(buf) as usize
    } else {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf)?;
        u64::from_be_bytes(buf) as usize
    };

    let mask_key = if masked {
        let mut key = [0u8; 4];
        stream.read_exact(&mut key)?;
        Some(key)
    } else {
        None
    };

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload)?;
    }

    // Unmask
    if let Some(key) = mask_key {
        for i in 0..payload.len() {
            payload[i] ^= key[i % 4];
        }
    }

    Ok(WsFrame { opcode, payload })
}

/// Write a text frame (server→client, unmasked).
pub fn write_text_frame(stream: &mut dyn Write, text: &str) -> io::Result<()> {
    write_frame(stream, OPCODE_TEXT, text.as_bytes())
}

/// Write a close frame.
pub fn write_close_frame(stream: &mut dyn Write) -> io::Result<()> {
    write_frame(stream, OPCODE_CLOSE, &[])
}

/// Write a pong frame.
pub fn write_pong_frame(stream: &mut dyn Write, payload: &[u8]) -> io::Result<()> {
    write_frame(stream, OPCODE_PONG, payload)
}

fn write_frame(stream: &mut dyn Write, opcode: u8, data: &[u8]) -> io::Result<()> {
    // FIN bit set, given opcode
    stream.write_all(&[0x80 | opcode])?;

    let len = data.len();
    if len <= 125 {
        stream.write_all(&[len as u8])?;
    } else if len <= 65535 {
        stream.write_all(&[126])?;
        stream.write_all(&(len as u16).to_be_bytes())?;
    } else {
        stream.write_all(&[127])?;
        stream.write_all(&(len as u64).to_be_bytes())?;
    }

    stream.write_all(data)?;
    stream.flush()
}

/// Handle a WebSocket connection: read frames, respond to control frames,
/// dispatch text messages.
///
/// `on_text` is called for each text frame received.
/// Returns when the connection is closed (by either side).
pub fn run_ws_loop(
    read_stream: &mut dyn Read,
    write_stream: &mut dyn Write,
    mut on_text: impl FnMut(&str),
) -> io::Result<()> {
    loop {
        let frame = match read_frame(read_stream) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match frame.opcode {
            OPCODE_TEXT => {
                if let Ok(text) = std::str::from_utf8(&frame.payload) {
                    on_text(text);
                }
            }
            OPCODE_PING => {
                let _ = write_pong_frame(write_stream, &frame.payload);
            }
            OPCODE_CLOSE => {
                let _ = write_close_frame(write_stream);
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_accept_rfc() {
        // Verified against Python hashlib + base64
        let accept = compute_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "RyVTkfbvgIu+vAZLbuzyhbcrH/0=");
    }

    #[test]
    fn write_read_text_frame() {
        let mut buf = Vec::new();
        write_text_frame(&mut buf, "hello").unwrap();

        // Server frames are unmasked; simulate client reading by reading as-is
        let frame = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(frame.opcode, OPCODE_TEXT);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn write_read_large_frame() {
        let text = "x".repeat(300);
        let mut buf = Vec::new();
        write_text_frame(&mut buf, &text).unwrap();

        let frame = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(frame.opcode, OPCODE_TEXT);
        assert_eq!(frame.payload.len(), 300);
    }
}
