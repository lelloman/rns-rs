use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};

/// Largest request body the control plane accepts.
///
/// The biggest legitimate bodies are `/api/resource` and `/api/send` payloads
/// (base64 data, so 4 MiB covers about 3 MiB of raw resource data) and
/// `rns-server.json` documents sent to `/api/config*`, which are a few KiB.
/// Hooks are loaded by path, so no hook binary travels through the API.
pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Largest request line plus header section the control plane accepts.
pub const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

/// Size of each read while collecting a request body. The body buffer grows
/// as data arrives instead of being allocated up front from `Content-Length`.
const BODY_READ_CHUNK_BYTES: usize = 16 * 1024;

/// Parsed HTTP request.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// HTTP response.
pub struct HttpResponse {
    pub status: u16,
    pub status_text: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, status_text: &'static str, body: &serde_json::Value) -> Self {
        let body_bytes = serde_json::to_vec(body).unwrap_or_default();
        HttpResponse {
            status,
            status_text,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), body_bytes.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body: body_bytes,
        }
    }

    pub fn ok(body: serde_json::Value) -> Self {
        Self::json(200, "OK", &body)
    }

    pub fn html(body: &str) -> Self {
        Self::bytes(
            200,
            "OK",
            "text/html; charset=utf-8",
            body.as_bytes().to_vec(),
        )
    }

    pub fn created(body: serde_json::Value) -> Self {
        Self::json(201, "Created", &body)
    }

    pub fn bad_request(msg: &str) -> Self {
        Self::json(400, "Bad Request", &serde_json::json!({"error": msg}))
    }

    pub fn unauthorized(msg: &str) -> Self {
        Self::json(401, "Unauthorized", &serde_json::json!({"error": msg}))
    }

    pub fn length_required(msg: &str) -> Self {
        Self::json(411, "Length Required", &serde_json::json!({"error": msg}))
    }

    pub fn payload_too_large(msg: &str) -> Self {
        Self::json(413, "Payload Too Large", &serde_json::json!({"error": msg}))
    }

    pub fn service_unavailable(msg: &str) -> Self {
        Self::json(
            503,
            "Service Unavailable",
            &serde_json::json!({"error": msg}),
        )
    }

    pub fn conflict(msg: &str) -> Self {
        Self::json(409, "Conflict", &serde_json::json!({"error": msg}))
    }

    pub fn not_found() -> Self {
        Self::json(404, "Not Found", &serde_json::json!({"error": "Not found"}))
    }

    pub fn internal_error(msg: &str) -> Self {
        Self::json(
            500,
            "Internal Server Error",
            &serde_json::json!({"error": msg}),
        )
    }

    pub fn bytes(
        status: u16,
        status_text: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> Self {
        HttpResponse {
            status,
            status_text,
            headers: vec![
                ("Content-Type".into(), content_type.into()),
                ("Content-Length".into(), body.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body,
        }
    }
}

/// Parse an HTTP/1.1 request from a stream, including its body.
///
/// The body is bounded by [`MAX_REQUEST_BODY_BYTES`]; a request that declares
/// a larger or unusable length is reported as `InvalidData`.
pub fn parse_request(stream: &mut dyn Read) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut req = parse_request_head(&mut reader)?;
    let len = request_body_length(&req).map_err(|resp| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("request body rejected with status {}", resp.status),
        )
    })?;
    req.body = read_body(&mut reader, len)?;
    Ok(req)
}

/// Read one line, failing once the head budget is used up.
fn read_head_line(reader: &mut dyn BufRead, remaining: &mut usize) -> io::Result<String> {
    let mut line = Vec::new();
    let limit = (*remaining as u64).saturating_add(1);
    let n = (&mut *reader).take(limit).read_until(b'\n', &mut line)?;
    if n > *remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Request head too large",
        ));
    }
    *remaining -= n;
    String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Request head is not UTF-8"))
}

/// Parse the request line and headers. The returned request has an empty
/// body; the caller decides whether to read it with [`read_body`] after
/// checking [`request_body_length`] and authentication.
pub fn parse_request_head(reader: &mut dyn BufRead) -> io::Result<HttpRequest> {
    let mut remaining = MAX_REQUEST_HEAD_BYTES;

    // Read request line
    let request_line = read_head_line(reader, &mut remaining)?;
    let request_line = request_line.trim_end();

    if request_line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Empty request",
        ));
    }

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid request line",
        ));
    }

    let method = parts[0].to_string();
    let full_path = parts[1];

    let (path, query) = if let Some(pos) = full_path.find('?') {
        (
            full_path[..pos].to_string(),
            full_path[pos + 1..].to_string(),
        )
    } else {
        (full_path.to_string(), String::new())
    };

    // Read headers
    let mut headers = HashMap::new();
    loop {
        let line = read_head_line(reader, &mut remaining)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
    })
}

/// Decide how many body bytes to read for a parsed request head.
///
/// A request without `Content-Length` or `Transfer-Encoding` has no body.
/// `Transfer-Encoding` without `Content-Length` gets `411`, an unparsable
/// `Content-Length` gets `400`, and a length above
/// [`MAX_REQUEST_BODY_BYTES`] gets `413`.
pub fn request_body_length(req: &HttpRequest) -> Result<usize, HttpResponse> {
    match req.headers.get("content-length") {
        Some(len_str) => {
            let len = len_str
                .parse::<usize>()
                .map_err(|_| HttpResponse::bad_request("Invalid Content-Length"))?;
            if len > MAX_REQUEST_BODY_BYTES {
                return Err(HttpResponse::payload_too_large(&format!(
                    "Request body exceeds {} bytes",
                    MAX_REQUEST_BODY_BYTES
                )));
            }
            Ok(len)
        }
        None if req.headers.contains_key("transfer-encoding") => Err(
            HttpResponse::length_required("Content-Length is required for a request body"),
        ),
        None => Ok(0),
    }
}

/// Read exactly `len` body bytes in bounded chunks, growing the buffer as
/// data arrives.
pub fn read_body(reader: &mut dyn Read, len: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(len.min(BODY_READ_CHUNK_BYTES));
    let mut chunk = [0u8; BODY_READ_CHUNK_BYTES];
    while body.len() < len {
        let want = (len - body.len()).min(BODY_READ_CHUNK_BYTES);
        let n = match reader.read(&mut chunk[..want]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Request body ended early",
                ))
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

/// Write an HTTP response to a stream.
pub fn write_response(stream: &mut dyn Write, response: &HttpResponse) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status, response.status_text
    )?;
    for (key, value) in &response.headers {
        write!(stream, "{}: {}\r\n", key, value)?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()
}

/// Parse query string parameters.
pub fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if query.is_empty() {
        return params;
    }
    for pair in query.split('&') {
        if let Some(eq) = pair.find('=') {
            let key = pair[..eq].to_string();
            let value = pair[eq + 1..].to_string();
            params.insert(key, value);
        } else if !pair.is_empty() {
            params.insert(pair.to_string(), String::new());
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_basic() {
        let q = parse_query("foo=bar&baz=123&flag");
        assert_eq!(q.get("foo").unwrap(), "bar");
        assert_eq!(q.get("baz").unwrap(), "123");
        assert!(q.contains_key("flag"));
    }

    #[test]
    fn parse_query_empty() {
        let q = parse_query("");
        assert!(q.is_empty());
    }

    #[test]
    fn parse_request_get() {
        let raw = b"GET /api/info?verbose=true HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\r\n\r\n";
        let req = parse_request(&mut &raw[..]).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/info");
        assert_eq!(req.query, "verbose=true");
        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer abc");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_request_post_with_body() {
        let body = r#"{"key":"value"}"#;
        let raw = format!(
            "POST /api/send HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let req = parse_request(&mut raw.as_bytes()).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/send");
        assert_eq!(req.body, body.as_bytes());
    }

    fn head(raw: &str) -> HttpRequest {
        parse_request_head(&mut raw.as_bytes()).unwrap()
    }

    #[test]
    fn body_length_absent_is_zero() {
        let req = head("POST /api/announce_queues/clear HTTP/1.1\r\n\r\n");
        assert_eq!(request_body_length(&req).ok(), Some(0));
    }

    #[test]
    fn body_length_within_cap() {
        let req = head("POST /api/send HTTP/1.1\r\nContent-Length: 1024\r\n\r\n");
        assert_eq!(request_body_length(&req).ok(), Some(1024));
        let req = head(&format!(
            "POST /api/send HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_BYTES
        ));
        assert_eq!(request_body_length(&req).ok(), Some(MAX_REQUEST_BODY_BYTES));
    }

    #[test]
    fn body_length_above_cap_is_413() {
        let req = head(&format!(
            "POST /api/send HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_BYTES + 1
        ));
        assert_eq!(request_body_length(&req).err().map(|r| r.status), Some(413));
        let req = head("POST /api/send HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n");
        assert_eq!(request_body_length(&req).err().map(|r| r.status), Some(400));
    }

    #[test]
    fn body_length_invalid_is_400() {
        let req = head("POST /api/send HTTP/1.1\r\nContent-Length: twelve\r\n\r\n");
        assert_eq!(request_body_length(&req).err().map(|r| r.status), Some(400));
        let req = head("POST /api/send HTTP/1.1\r\nContent-Length: -1\r\n\r\n");
        assert_eq!(request_body_length(&req).err().map(|r| r.status), Some(400));
    }

    #[test]
    fn body_length_transfer_encoding_without_length_is_411() {
        let req = head("POST /api/send HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(request_body_length(&req).err().map(|r| r.status), Some(411));
    }

    #[test]
    fn parse_request_rejects_oversize_body_without_reading_it() {
        let raw = format!(
            "POST /api/send HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_BYTES + 1
        );
        let err = parse_request(&mut raw.as_bytes()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_request_head_rejects_long_header_section() {
        let raw = format!(
            "GET /api/info HTTP/1.1\r\nX-Note: {}\r\n\r\n",
            "a".repeat(MAX_REQUEST_HEAD_BYTES)
        );
        let err = parse_request_head(&mut raw.as_bytes()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Reader that hands out at most `step` bytes per call.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn read_body_reassembles_partial_reads() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let mut reader = Trickle {
            data: &data,
            step: 777,
        };
        let body = read_body(&mut reader, data.len()).unwrap();
        assert_eq!(body, data);
    }

    #[test]
    fn read_body_short_input_is_eof() {
        let data = b"{\"key\":";
        let err = read_body(&mut &data[..], 20).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn response_json() {
        let resp = HttpResponse::ok(serde_json::json!({"status": "ok"}));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["status"], "ok");
    }
}
