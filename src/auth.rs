use crate::config::Config;
use crate::error::{RelayError, RelayResult};
use crate::protocol::HEADER_AUTH;
use axum::http::HeaderMap;
use std::sync::Arc;

pub fn check_auth(config: &Config, headers: &HeaderMap) -> RelayResult<()> {
    if !config.auth_required() {
        return Ok(());
    }
    let provided = headers
        .get(HEADER_AUTH)
        .or_else(|| headers.get(axum::http::header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().strip_prefix("Bearer ").unwrap_or(s).to_string());

    match provided {
        Some(token) if token == config.auth_token => Ok(()),
        _ => Err(RelayError::Unauthorized),
    }
}

pub fn check_auth_query(config: &Arc<Config>, token: Option<&str>) -> RelayResult<()> {
    if !config.auth_required() {
        return Ok(());
    }
    match token {
        Some(t) if t == config.auth_token => Ok(()),
        _ => Err(RelayError::Unauthorized),
    }
}
