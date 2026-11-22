use crate::http::{HttpRequest, HttpResponse};
use crate::state::{read_control_plane_config, ControlPlaneConfigHandle};
use subtle::ConstantTimeEq;

/// Whether `given` is the configured token `expected`, in time that does not
/// depend on where they differ.
///
/// Both are hashed first and the fixed-size digests compared in constant
/// time, so neither a differing byte nor a differing length shows up as an
/// earlier return. Hashing takes time proportional to each input's length;
/// the attacker knows their own, and the configured token's length only
/// moves the time in whole SHA-256 blocks.
fn token_matches(given: &str, expected: &str) -> bool {
    let given = rns_crypto::sha256::sha256(given.as_bytes());
    let expected = rns_crypto::sha256::sha256(expected.as_bytes());
    given.ct_eq(&expected).into()
}

/// Check authentication on an HTTP request.
/// Returns Ok(()) if authenticated, Err(response) with 401 if not.
pub fn check_auth(
    req: &HttpRequest,
    config: &ControlPlaneConfigHandle,
) -> Result<(), HttpResponse> {
    let config = read_control_plane_config(config);
    if config.disable_auth {
        return Ok(());
    }

    // Auth is enabled, so a request is accepted only when it carries the
    // configured token. Without a configured token nothing can match.
    let Some(expected) = config.auth_token.as_deref() else {
        return Err(HttpResponse::unauthorized("No auth token configured"));
    };

    let auth_header = req.headers.get("authorization");
    match auth_header {
        Some(val) => {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if token_matches(token, expected) {
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

/// Prefix of the WebSocket subprotocol that carries the bearer token:
/// a browser, which cannot set an `Authorization` header on a WebSocket,
/// offers `rns-ctl.bearer.<token>` together with [`crate::ws::PROTOCOL`].
pub const WS_BEARER_PROTOCOL_PREFIX: &str = "rns-ctl.bearer.";

/// Check auth on a WebSocket upgrade request.
///
/// The token comes from an `Authorization: Bearer <token>` header or, for
/// browsers, from an offered subprotocol `rns-ctl.bearer.<token>`. It is not
/// taken from the URL, which proxies and access logs record.
pub fn check_ws_auth(
    req: &HttpRequest,
    config: &ControlPlaneConfigHandle,
) -> Result<(), HttpResponse> {
    let config = read_control_plane_config(config);
    if config.disable_auth {
        return Ok(());
    }

    let Some(expected) = config.auth_token.as_deref() else {
        return Err(HttpResponse::unauthorized("No auth token configured"));
    };

    let token = req
        .headers
        .get("authorization")
        .and_then(|val| val.strip_prefix("Bearer "))
        .or_else(|| {
            crate::ws::offered_protocols(req)
                .find_map(|protocol| protocol.strip_prefix(WS_BEARER_PROTOCOL_PREFIX))
        });
    match token {
        Some(token) if token_matches(token, expected) => Ok(()),
        Some(_) => Err(HttpResponse::unauthorized("Invalid token")),
        None => Err(HttpResponse::unauthorized(
            "Missing token: send Authorization: Bearer <token> or offer the \
             WebSocket subprotocol rns-ctl.bearer.<token>",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config(token: Option<&str>, disable: bool) -> crate::state::ControlPlaneConfigHandle {
        std::sync::Arc::new(std::sync::RwLock::new(crate::config::CtlConfig {
            auth_token: token.map(String::from),
            disable_auth: disable,
            ..crate::config::CtlConfig::default()
        }))
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
    fn token_matches_only_the_same_token() {
        assert!(token_matches("secret", "secret"));
        assert!(token_matches("", ""));
        assert!(!token_matches("secreT", "secret"));
        assert!(!token_matches("xecret", "secret"));
        assert!(!token_matches("secre", "secret"));
        assert!(!token_matches("secrets", "secret"));
        assert!(!token_matches("", "secret"));
    }

    #[test]
    fn auth_disabled() {
        let config = make_config(Some("secret"), true);
        assert!(check_auth(&make_req(None), &config).is_ok());
    }

    #[test]
    fn auth_enabled_without_a_token_denies_every_request() {
        let config = make_config(None, false);
        assert!(check_auth(&make_req(None), &config).is_err());
        assert!(check_auth(&make_req(Some("Bearer anything")), &config).is_err());
        assert!(check_ws_auth(&make_req(Some("Bearer anything")), &config).is_err());
        assert!(check_ws_auth(&make_req(None), &config).is_err());
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

    fn make_ws_req(query: &str, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: "/ws".into(),
            query: query.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn ws_auth_accepts_bearer_header() {
        let config = make_config(Some("abc"), false);
        let req = make_ws_req("", &[("authorization", "Bearer abc")]);
        assert!(check_ws_auth(&req, &config).is_ok());
    }

    #[test]
    fn ws_auth_accepts_bearer_subprotocol() {
        let config = make_config(Some("abc"), false);
        let req = make_ws_req(
            "",
            &[("sec-websocket-protocol", "rns-ctl, rns-ctl.bearer.abc")],
        );
        assert!(check_ws_auth(&req, &config).is_ok());
    }

    #[test]
    fn ws_auth_rejects_wrong_or_missing_token() {
        let config = make_config(Some("abc"), false);
        let wrong_header = make_ws_req("", &[("authorization", "Bearer xyz")]);
        assert!(check_ws_auth(&wrong_header, &config).is_err());
        let wrong_protocol = make_ws_req(
            "",
            &[("sec-websocket-protocol", "rns-ctl, rns-ctl.bearer.xyz")],
        );
        assert!(check_ws_auth(&wrong_protocol, &config).is_err());
        let no_token = make_ws_req("", &[("sec-websocket-protocol", "rns-ctl")]);
        assert!(check_ws_auth(&no_token, &config).is_err());
        assert!(check_ws_auth(&make_ws_req("", &[]), &config).is_err());
    }

    #[test]
    fn ws_auth_ignores_query_token() {
        let config = make_config(Some("abc"), false);
        assert!(check_ws_auth(&make_ws_req("token=abc", &[]), &config).is_err());
    }
}
