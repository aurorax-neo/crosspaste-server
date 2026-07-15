//! Transparent HTTP reverse proxy into a device tunnel.
//!
//! Incoming request path/query/headers/body are forwarded as-is (opaque).
//! Response status/headers/body from the target device are returned as-is.

use crate::error::{RelayError, RelayResult};
use crate::protocol::{
    TunnelFrame, HEADER_APP_INSTANCE_ID, HEADER_TARGET_APP_INSTANCE_ID,
};
use crate::registry::Registry;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Headers that should not be blindly copied when building the proxied request.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

pub async fn proxy_to_device(
    registry: &Registry,
    target_app_instance_id: &str,
    req: Request,
    max_body_bytes: usize,
) -> RelayResult<Response> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let path = match uri.query() {
        Some(q) => format!("{}?{}", uri.path(), q),
        None => uri.path().to_string(),
    };

    let mut headers = header_map_to_plain(req.headers());
    // Ensure target header is set for CrossPaste peer semantics.
    headers
        .entry(HEADER_TARGET_APP_INSTANCE_ID.to_string())
        .or_insert_with(|| target_app_instance_id.to_string());

    let body_bytes = axum::body::to_bytes(req.into_body(), max_body_bytes)
        .await
        .map_err(|e| RelayError::BadRequest(format!("read body: {e}")))?;

    let body_b64 = if body_bytes.is_empty() {
        None
    } else {
        Some(B64.encode(&body_bytes))
    };

    debug!(
        %method,
        %path,
        target = %target_app_instance_id,
        body_len = body_bytes.len(),
        "proxy request"
    );

    let frame = registry
        .proxy_http(target_app_instance_id, method, path, headers, body_b64)
        .await?;

    match frame {
        TunnelFrame::HttpResponse {
            status,
            headers,
            body_b64,
            error,
            ..
        } => {
            if let Some(err) = error {
                warn!(%err, "device reported proxy error");
                return Err(RelayError::Internal(err));
            }
            let status = StatusCode::from_u16(status)
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let body = match body_b64 {
                Some(b) => B64
                    .decode(b.as_bytes())
                    .map_err(|e| RelayError::Internal(format!("bad body b64: {e}")))?,
                None => Vec::new(),
            };
            let mut builder = Response::builder().status(status);
            if let Some(hdrs) = builder.headers_mut() {
                for (k, v) in headers {
                    if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(&k)) {
                        continue;
                    }
                    if let (Ok(name), Ok(val)) = (
                        HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_str(&v),
                    ) {
                        hdrs.insert(name, val);
                    }
                }
            }
            builder
                .body(Body::from(body))
                .map_err(|e| RelayError::Internal(e.to_string()))
        }
        TunnelFrame::Error { message } => Err(RelayError::Internal(message)),
        other => Err(RelayError::Internal(format!(
            "unexpected tunnel frame: {other:?}"
        ))),
    }
}

pub fn resolve_target(headers: &HeaderMap, path_target: Option<&str>) -> RelayResult<String> {
    if let Some(t) = path_target {
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    headers
        .get(HEADER_TARGET_APP_INSTANCE_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(RelayError::BadRequest(
            "missing targetAppInstanceId (header or path)".into(),
        ))
}

pub fn require_source_app_instance(headers: &HeaderMap) -> RelayResult<String> {
    headers
        .get(HEADER_APP_INSTANCE_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(RelayError::MissingAppInstanceId)
}

fn header_map_to_plain(headers: &HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        if HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(&key)) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            out.insert(key, v.to_string());
        }
    }
    out
}
