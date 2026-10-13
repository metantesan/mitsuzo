//! Resolve the client IP used for rate limiting.
//!
//! Forwarded headers (`X-Forwarded-For`, `X-Real-IP`) are attacker-controlled
//! unless a trusted reverse proxy sets them, so they are only honored when the
//! deployment opts in with `MITSUZO_TRUST_PROXY`. Otherwise the socket peer
//! address is the authoritative identity.
use crate::AppState;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use std::convert::Infallible;
use std::net::SocketAddr;

/// Client identity resolved for rate limiting, available as a handler extractor.
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr);
        Ok(ClientIp(resolve_client_ip(
            &parts.headers,
            peer,
            state.config.trust_proxy,
        )))
    }
}

/// Pick the rate-limit identity: the leftmost (client) forwarded address when
/// the deployment trusts a proxy, otherwise the socket peer address.
fn resolve_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(ip) = forwarded_header(headers, "X-Forwarded-For") {
            return ip;
        }
        if let Some(ip) = forwarded_header(headers, "X-Real-IP") {
            return ip;
        }
    }
    match peer {
        Some(addr) => addr.ip().to_string(),
        None => "unknown".to_string(),
    }
}

fn forwarded_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    // X-Forwarded-For is a comma-separated chain; the client is leftmost.
    let first = value.split(',').next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn untrusted_ignores_forwarded_headers() {
        let peer: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let headers = headers_with("X-Forwarded-For", "1.2.3.4");
        // Spoofed header must not change the identity when the proxy is untrusted.
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), false),
            "203.0.113.9"
        );
    }

    #[test]
    fn trusted_uses_leftmost_forwarded_address() {
        let peer: SocketAddr = "10.0.0.1:5555".parse().unwrap();
        let headers = headers_with("X-Forwarded-For", "1.2.3.4, 10.0.0.1");
        assert_eq!(resolve_client_ip(&headers, Some(peer), true), "1.2.3.4");
    }

    #[test]
    fn trusted_falls_back_to_peer_without_header() {
        let peer: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), Some(peer), true),
            "203.0.113.9"
        );
    }

    #[test]
    fn trusted_uses_x_real_ip_when_xff_missing() {
        let headers = headers_with("X-Real-IP", "198.51.100.7");
        assert_eq!(resolve_client_ip(&headers, None, true), "198.51.100.7");
    }
}
