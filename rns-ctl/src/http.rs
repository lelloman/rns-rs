use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};

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

    pub fn created(body: serde_json::Value) -> Self {
        Self::json(201, "Created", &body)
    }

    pub fn bad_request(msg: &str) -> Self {
        Self::json(400, "Bad Request", &serde_json::json!({"error": msg}))
    }

    pub fn unauthorized(msg: &str) -> Self {
        Self::json(401, "Unauthorized", &serde_json::json!({"error": msg}))
    }

    pub fn not_found() -> Self {
        Self::json(404, "Not Found", &serde_json::json!({"error": "Not found"}))
    }

    pub fn internal_error(msg: &str) -> Self {
        Self::json(500, "Internal Server Error", &serde_json::json!({"error": msg}))
    }
}

/// Parse an HTTP/1.1 request from a stream.
pub fn parse_request(stream: &mut dyn Read) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);

    // Read request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_line = request_line.trim_end();

    if request_line.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Empty request"));
    }

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid request line"));
    }

    let method = parts[0].to_string();
    let full_path = parts[1];

    let (path, query) = if let Some(pos) = full_path.find('?') {
        (full_path[..pos].to_string(), full_path[pos + 1..].to_string())
    } else {
        (full_path.to_string(), String::new())
    };

    // Read headers
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
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

    // Read body based on Content-Length
    let body = if let Some(len_str) = headers.get("content-length") {
        if let Ok(len) = len_str.parse::<usize>() {
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body)?;
            body
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
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

    #[test]
    fn response_json() {
        let resp = HttpResponse::ok(serde_json::json!({"status": "ok"}));
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["status"], "ok");
    }
}
