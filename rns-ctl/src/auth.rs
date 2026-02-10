use crate::config::CtlConfig;
use crate::http::{HttpRequest, HttpResponse};

/// Check authentication on an HTTP request.
/// Returns Ok(()) if authenticated, Err(response) with 401 if not.
pub fn check_auth(req: &HttpRequest, config: &CtlConfig) -> Result<(), HttpResponse> {
    if config.disable_auth {
        return Ok(());
    }

    let expected = match &config.auth_token {
        Some(t) => t.as_str(),
        None => return Ok(()), // No token configured and auth not disabled = open (shouldn't happen)
    };

    let auth_header = req.headers.get("authorization");
    match auth_header {
        Some(val) => {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if token == expected {
                    Ok(())
                } else {
                    Err(HttpResponse::unauthorized("Invalid token"))
                }
            } else {
                Err(HttpResponse::unauthorized("Expected Bearer token"))
            }
        }
        None => Err(HttpResponse::unauthorized("Missing Authorization header")),
    }
}

/// Check WebSocket auth via query parameter `?token=...`.
pub fn check_ws_auth(query: &str, config: &CtlConfig) -> Result<(), HttpResponse> {
    if config.disable_auth {
        return Ok(());
    }

    let expected = match &config.auth_token {
        Some(t) => t.as_str(),
        None => return Ok(()),
    };

    let params = crate::http::parse_query(query);
    match params.get("token") {
        Some(token) if token == expected => Ok(()),
        _ => Err(HttpResponse::unauthorized("Missing or invalid token")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config(token: Option<&str>, disable: bool) -> CtlConfig {
        CtlConfig {
            auth_token: token.map(String::from),
            disable_auth: disable,
            ..CtlConfig::default()
        }
    }

    fn make_req(auth_header: Option<&str>) -> HttpRequest {
        let mut headers = HashMap::new();
        if let Some(val) = auth_header {
            headers.insert("authorization".into(), val.into());
        }
        HttpRequest {
            method: "GET".into(),
            path: "/api/info".into(),
            query: String::new(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn auth_disabled() {
        let config = make_config(Some("secret"), true);
        assert!(check_auth(&make_req(None), &config).is_ok());
    }

    #[test]
    fn auth_no_token_configured() {
        let config = make_config(None, false);
        assert!(check_auth(&make_req(None), &config).is_ok());
    }

    #[test]
    fn auth_valid_token() {
        let config = make_config(Some("secret"), false);
        assert!(check_auth(&make_req(Some("Bearer secret")), &config).is_ok());
    }

    #[test]
    fn auth_invalid_token() {
        let config = make_config(Some("secret"), false);
        assert!(check_auth(&make_req(Some("Bearer wrong")), &config).is_err());
    }

    #[test]
    fn auth_missing_header() {
        let config = make_config(Some("secret"), false);
        assert!(check_auth(&make_req(None), &config).is_err());
    }

    #[test]
    fn ws_auth_valid() {
        let config = make_config(Some("abc"), false);
        assert!(check_ws_auth("token=abc", &config).is_ok());
    }

    #[test]
    fn ws_auth_invalid() {
        let config = make_config(Some("abc"), false);
        assert!(check_ws_auth("token=xyz", &config).is_err());
    }
}
