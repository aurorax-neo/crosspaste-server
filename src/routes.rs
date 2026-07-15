use crate::auth::check_auth;
use crate::error::{RelayError, RelayResult};
use crate::protocol::{CreateRoomResponse, HealthResponse, PairingQrResponse, SYNC_API_VERSION};
use crate::proxy::{proxy_to_device, require_source_app_instance, resolve_target};
use crate::qr::render_qr_png;
use crate::secure::{KeyExchangeRequest, TrustConfirmRequest, TrustRequest};
use crate::sync_info::{
    build_server_sync_info, decode_qr_payload, encode_qr_payload, encode_sync_info_header,
    encode_txt_record, SyncInfo,
};
use crate::tunnel::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

pub fn build_router(state: AppState) -> Router {
    let max_body = state.config.max_body_bytes;

    Router::new()
        .merge(crate::admin::router())
        // Relay control plane
        .route("/health", get(health))
        .route("/sync/heartbeat", get(server_heartbeat))
        .route("/sync/heartbeat/syncInfo", post(server_heartbeat_sync_info))
        .route("/sync/syncInfo", get(server_sync_info))
        .route("/sync/telnet", get(server_telnet))
        .route("/sync/showToken", get(server_show_token))
        .route("/sync/trust", post(sync_trust))
        .route("/sync/trust/v2/exchange", post(sync_trust_v2_exchange))
        .route("/sync/trust/v2/confirm", post(sync_trust_v2_confirm))
        .route("/sync/paste", post(sync_paste))
        .route("/sync/file/push", post(sync_file_push))
        .route("/sync/paste/push/complete", post(sync_push_complete))
        .route("/sync/icon/push/{source}", post(sync_icon_push))
        .route("/pull/file", post(pull_file))
        .route("/pull/icon/{source}", get(pull_icon))
        .route("/pull/paste", get(pull_paste))
        .route("/pull/pasteBatch", get(pull_paste_batch))
        .route("/sync/{*path}", any(proxy_original_path))
        .route("/pull/{*path}", any(proxy_original_path))
        .route("/v1/discovery/sync-info", get(discovery_sync_info))
        .route("/v1/discovery/txt-record", get(discovery_txt_record))
        .route("/v1/pairing/qr", get(pairing_qr_payload))
        .route("/v1/pairing/qr.png", get(pairing_qr_png))
        .route("/v1/pairing/decode", get(decode_pairing_qr))
        .route("/v1/clients", get(list_paired_clients))
        .route("/v1/devices", get(list_devices))
        .route("/v1/rooms", post(create_room))
        .route("/v1/rooms/{code}", get(get_room))
        .route("/v1/rooms/{code}/join", post(join_room))
        .route("/v1/rooms/{code}/leave", post(leave_room))
        // Device long-lived tunnel
        .route("/v1/tunnel", get(crate::tunnel::tunnel_ws))
        // Transparent CrossPaste peer proxy:
        //   /r/{targetAppInstanceId}/{*path}
        // e.g. POST /r/abc-123/sync/paste
        .route("/r/{target}/{*path}", any(proxy_path))
        // Header-only targeting: targetAppInstanceId header required
        //   /p/{*path}  e.g. POST /p/sync/paste
        .route("/p/{*path}", any(proxy_header_target))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(state.clone(), log_request))
        .with_state(state)
}

async fn log_request(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let client_id = header_text(req.headers(), crate::protocol::HEADER_APP_INSTANCE_ID).to_string();
    let target_id = header_text(
        req.headers(),
        crate::protocol::HEADER_TARGET_APP_INSTANCE_ID,
    )
    .to_string();
    let secure = req.headers().contains_key(crate::protocol::HEADER_SECURE);
    let remote = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let started = Instant::now();
    let crosspaste_path = ["/sync/", "/pull/", "/r/", "/p/"]
        .iter()
        .any(|prefix| path.starts_with(prefix));
    if crosspaste_path && client_id != "-" && state.hub.is_paired(&client_id) {
        state.hub.touch_client(&client_id);
    }
    let response = next.run(req).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();

    if !path.starts_with("/api/admin/logs") {
        let _ = state.database.request_log(
            method.as_str(),
            &path,
            status.as_u16(),
            &remote,
            (client_id != "-").then_some(client_id.as_str()),
            (target_id != "-").then_some(target_id.as_str()),
            secure,
            elapsed_ms as i64,
        );
    }

    if !status.is_success() {
        warn!(%method, %path, %status, %remote, client_id, target_id, secure, elapsed_ms, "request failed");
    } else if path.starts_with("/sync/") || path.starts_with("/pull/") {
        info!(%method, %path, %status, %remote, client_id, target_id, secure, elapsed_ms, "crosspaste request");
    } else {
        debug!(%method, %path, %status, %remote, elapsed_ms, "http request");
    }
    response
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> RelayResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| RelayError::BadRequest(format!("missing {name} header")))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    state.registry.gc_rooms();
    Json(HealthResponse {
        ok: true,
        service: "crosspaste-server".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        sync_api_version: SYNC_API_VERSION,
        online_devices: state.registry.online_count(),
        paired_clients: state.hub.paired_count(),
        rooms: state.registry.room_count(),
    })
}

async fn server_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<Response> {
    let client_id = require_paired_client(&state, &headers)?;
    state.hub.touch_client(client_id);
    debug!(
        client_id,
        secure = headers.contains_key(crate::protocol::HEADER_SECURE),
        "heartbeat received"
    );
    secure_json_response(&state, &headers, &SYNC_API_VERSION)
}

async fn server_sync_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<Response> {
    info!(
        client_id = header_text(&headers, crate::protocol::HEADER_APP_INSTANCE_ID),
        "syncInfo requested"
    );
    secure_json_response(&state, &headers, &build_server_sync_info(&state.config))
}

async fn server_heartbeat_sync_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let body = maybe_decrypt_body(&state, &headers, app_instance_id, &body)?;
    let sync_info = serde_json::from_slice::<SyncInfo>(&body)
        .map_err(|e| RelayError::BadRequest(e.to_string()))?;
    info!(client_id = %app_instance_id, device_name = %sync_info.endpoint_info.device_name, hosts = sync_info.endpoint_info.host_info_list.len(), port = sync_info.endpoint_info.port, "client heartbeat SyncInfo accepted");
    state
        .hub
        .update_client_sync_info(app_instance_id, sync_info)
        .map_err(|e| RelayError::BadRequest(e.to_string()))?;
    secure_json_response(&state, &headers, &SYNC_API_VERSION)
}

async fn server_telnet(State(state): State<AppState>) -> RelayResult<Response> {
    let sync_info = build_server_sync_info(&state.config);
    let header_value =
        encode_sync_info_header(&sync_info).map_err(|e| RelayError::Internal(e.to_string()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(
            crate::protocol::HEADER_APP_INSTANCE_ID,
            &sync_info.app_info.app_instance_id,
        )
        .header(crate::protocol::HEADER_SYNC_INFO, header_value)
        .body(Body::from(SYNC_API_VERSION.to_string()))
        .map_err(|e| RelayError::Internal(e.to_string()))
}

async fn server_show_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<Response> {
    let app_instance_id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown-client");
    let token = state.hub.issue_pairing_token_for(Some(app_instance_id));
    info!(client_id = %app_instance_id, token = %format!("{token:06}"), valid_seconds = 30, "pairing code issued");
    println!("CrossPaste pairing code: {token:06} (requested by {app_instance_id}, valid for 30 seconds)");
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|error| RelayError::Internal(error.to_string()))
}

async fn discovery_sync_info(State(state): State<AppState>) -> Json<SyncInfo> {
    Json(build_server_sync_info(&state.config))
}

async fn discovery_txt_record(
    State(state): State<AppState>,
) -> RelayResult<Json<HashMap<String, String>>> {
    let sync_info = build_server_sync_info(&state.config);
    let txt =
        encode_txt_record(&sync_info, 128).map_err(|e| RelayError::Internal(e.to_string()))?;
    Ok(Json(txt))
}

#[derive(Debug, Deserialize)]
struct QrQuery {
    token: Option<u32>,
}

async fn pairing_qr_payload(
    State(state): State<AppState>,
    Query(q): Query<QrQuery>,
) -> RelayResult<Json<PairingQrResponse>> {
    let token = q.token.unwrap_or_else(generate_token);
    state.hub.set_pairing_token(token);
    let sync_info = build_server_sync_info(&state.config);
    let payload =
        encode_qr_payload(&sync_info, token).map_err(|e| RelayError::Internal(e.to_string()))?;
    Ok(Json(PairingQrResponse {
        token,
        payload,
        png_path: format!("/v1/pairing/qr.png?token={token:06}"),
        sync_info,
    }))
}

async fn pairing_qr_png(
    State(state): State<AppState>,
    Query(q): Query<QrQuery>,
) -> RelayResult<Response> {
    let token = q.token.unwrap_or_else(generate_token);
    state.hub.set_pairing_token(token);
    let sync_info = build_server_sync_info(&state.config);
    let payload =
        encode_qr_payload(&sync_info, token).map_err(|e| RelayError::Internal(e.to_string()))?;
    let png = render_qr_png(&payload).map_err(|e| RelayError::Internal(e.to_string()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(png))
        .map_err(|e| RelayError::Internal(e.to_string()))
}

#[derive(Debug, Deserialize)]
struct DecodeQrQuery {
    payload: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeQrResponse {
    token: u32,
    sync_info: crate::sync_info::SyncInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullFileRequest {
    id: i64,
    chunk_index: usize,
}

async fn decode_pairing_qr(Query(q): Query<DecodeQrQuery>) -> RelayResult<Json<DecodeQrResponse>> {
    let (sync_info, token) =
        decode_qr_payload(&q.payload).map_err(|e| RelayError::BadRequest(e.to_string()))?;
    Ok(Json(DecodeQrResponse { token, sync_info }))
}

async fn sync_trust(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TrustRequest>,
) -> RelayResult<impl IntoResponse> {
    let app_instance_id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or(RelayError::MissingAppInstanceId)?;
    info!(client_id = %app_instance_id, token = %format!("{:06}", request.pairing_request.token), "pairing verification requested");
    let response = match state.hub.trust_v1(app_instance_id, request) {
        Ok(response) => response,
        Err(error) => {
            warn!(client_id = %app_instance_id, %error, "pairing verification rejected");
            return Err(RelayError::BadRequest(error.to_string()));
        }
    };
    info!(client_id = %app_instance_id, "pairing completed");
    Ok(Json(response))
}

async fn sync_trust_v2_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<KeyExchangeRequest>,
) -> RelayResult<impl IntoResponse> {
    let app_instance_id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|value| value.to_str().ok())
        .ok_or(RelayError::MissingAppInstanceId)?;
    let (response, sas) = match state.hub.exchange_keys_v2(app_instance_id, request) {
        Ok(result) => result,
        Err(error) => {
            warn!(client_id = %app_instance_id, %error, "v2 key exchange rejected");
            return Err(RelayError::BadRequest(error.to_string()));
        }
    };
    info!(client_id = %app_instance_id, sas = %format!("{sas:06}"), valid_seconds = 30, "v2 pairing code issued");
    println!(
        "CrossPaste pairing code: {sas:06} (requested by {app_instance_id}, valid for 30 seconds)"
    );
    Ok(Json(response))
}

async fn sync_trust_v2_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TrustConfirmRequest>,
) -> RelayResult<impl IntoResponse> {
    let app_instance_id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|value| value.to_str().ok())
        .ok_or(RelayError::MissingAppInstanceId)?;
    let response = match state.hub.confirm_trust_v2(app_instance_id, request) {
        Ok(response) => response,
        Err(error) => {
            warn!(client_id = %app_instance_id, %error, "v2 pairing confirmation rejected");
            return Err(RelayError::BadRequest(error.to_string()));
        }
    };
    info!(client_id = %app_instance_id, "v2 pairing completed");
    Ok(Json(response))
}

async fn sync_paste(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let body = maybe_decrypt_body(&state, &headers, app_instance_id, &body)?;
    let mut paste = serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|e| RelayError::BadRequest(e.to_string()))?;
    enforce_sync_settings(&state, &paste)?;
    if header_text(&headers, "X-Sync-Mode") == "push" {
        let response = state
            .hub
            .prepare_push(app_instance_id, paste)
            .map_err(|error| RelayError::BadRequest(error.to_string()))?;
        return secure_json_response(&state, &headers, &response);
    }
    let paste_type = paste
        .get("pasteType")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(-1);
    if paste_type == 3 || paste_type == 4 {
        let hub = state.hub.clone();
        let server_id = state.config.server_instance_id.clone();
        let source_id = app_instance_id.to_string();
        tokio::spawn(async move {
            let server_paste_id = match hub
                .cache_pull_file_from_client(&source_id, &server_id, &paste)
                .await
            {
                Ok(paste_id) => paste_id,
                Err(error) => {
                    warn!(client_id = %source_id, %error, "failed to cache pull-mode file paste");
                    return;
                }
            };
            if let Some(object) = paste.as_object_mut() {
                object.insert("id".to_string(), server_paste_id.into());
            }
            cache_paste_icon(&hub, &source_id, &server_id, &paste).await;
            if let Err(error) = hub.receive_paste(&source_id, paste.clone()) {
                warn!(client_id = %source_id, %error, "failed to store file paste metadata");
                return;
            }
            let report = hub.broadcast_paste(&source_id, &server_id, &paste).await;
            info!(client_id = %source_id, attempted = report.attempted, delivered = report.delivered, failed = report.failed, "pull-mode file broadcast completed");
        });
        return secure_json_response(&state, &headers, &"");
    }
    cache_paste_icon(
        &state.hub,
        app_instance_id,
        &state.config.server_instance_id,
        &paste,
    )
    .await;
    state
        .hub
        .receive_paste(app_instance_id, paste.clone())
        .map_err(|e| RelayError::BadRequest(e.to_string()))?;
    let server_id = state.config.server_instance_id.clone();
    let report = state
        .hub
        .broadcast_paste(app_instance_id, &server_id, &paste)
        .await;
    info!(client_id = %app_instance_id, attempted = report.attempted, delivered = report.delivered, failed = report.failed, "paste broadcast completed");
    secure_json_response(&state, &headers, &"")
}

fn enforce_sync_settings(state: &AppState, paste: &serde_json::Value) -> RelayResult<()> {
    let settings = state
        .database
        .settings()
        .map_err(|error| RelayError::Internal(error.to_string()))?;
    if settings
        .get("clipboard_relay")
        .is_some_and(|value| value == "false")
    {
        return Err(RelayError::BadRequest("clipboard relay is disabled".into()));
    }
    let paste_type = paste
        .get("pasteType")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(-1);
    let setting = match paste_type {
        0 => "sync_text",
        1 => "sync_url",
        2 => "sync_html",
        3 => "sync_file",
        4 => "sync_image",
        5 => "sync_rtf",
        6 => "sync_color",
        _ => return Err(RelayError::BadRequest("unknown paste type".into())),
    };
    if settings.get(setting).is_some_and(|value| value == "false") {
        return Err(RelayError::BadRequest(format!("{setting} is disabled")));
    }
    if paste_type == 3 || paste_type == 4 {
        if settings
            .get("limit_file_size")
            .is_none_or(|value| value == "true")
        {
            let max_mb = settings
                .get("max_file_size_mb")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(512);
            let size = paste
                .get("size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if size > max_mb * 1024 * 1024 {
                return Err(RelayError::BadRequest(format!(
                    "file exceeds the configured {max_mb} MB limit"
                )));
            }
        }
    }
    Ok(())
}

async fn sync_file_push(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let paste_id = required_header(&headers, "X-Paste-Id")?
        .parse::<i64>()
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    let chunk_index = required_header(&headers, "X-Chunk-Index")?
        .parse::<usize>()
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    let token = required_header(&headers, "X-Session-Token")?;
    let body = maybe_decrypt_body(&state, &headers, app_instance_id, &body)?;
    state
        .hub
        .store_push_chunk(app_instance_id, paste_id, chunk_index, token, &body)
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    debug!(client_id = %app_instance_id, paste_id, chunk_index, bytes = body.len(), "file push chunk accepted");
    secure_json_response(&state, &headers, &"")
}

async fn sync_push_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let paste_id = required_header(&headers, "X-Paste-Id")?
        .parse::<i64>()
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    let token = required_header(&headers, "X-Session-Token")?;
    let (response, completed) = state
        .hub
        .complete_push(app_instance_id, paste_id, token)
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    if let Some(completed) = completed {
        let hub = state.hub.clone();
        let server_id = state.config.server_instance_id.clone();
        tokio::spawn(async move {
            let report = hub.broadcast_completed_push(completed, &server_id).await;
            info!(
                attempted = report.attempted,
                delivered = report.delivered,
                failed = report.failed,
                "file push broadcast completed"
            );
        });
    }
    secure_json_response(&state, &headers, &response)
}

async fn pull_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let body = maybe_decrypt_body(&state, &headers, app_instance_id, &body)?;
    let request: PullFileRequest =
        serde_json::from_slice(&body).map_err(|error| RelayError::BadRequest(error.to_string()))?;
    let bytes = state
        .hub
        .read_file_chunk(request.id, request.chunk_index)
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    let body = if headers.contains_key(crate::protocol::HEADER_SECURE) {
        state
            .hub
            .encrypt_stream_for_client(app_instance_id, &bytes)
            .map_err(|error| RelayError::Internal(error.to_string()))?
    } else {
        bytes
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .map_err(|error| RelayError::Internal(error.to_string()))
}

async fn sync_icon_push(
    State(state): State<AppState>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> RelayResult<Response> {
    let app_instance_id = require_paired_client(&state, &headers)?;
    let body = maybe_decrypt_body(&state, &headers, app_instance_id, &body)?;
    state
        .hub
        .store_icon(&source, &body)
        .map_err(|error| RelayError::BadRequest(error.to_string()))?;
    secure_json_response(&state, &headers, &"")
}

async fn pull_icon(
    State(state): State<AppState>,
    Path(source): Path<String>,
) -> RelayResult<Response> {
    let bytes = state
        .hub
        .read_icon(&source)
        .map_err(|_| RelayError::ResourceNotFound(source.clone()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .map_err(|error| RelayError::Internal(error.to_string()))
}

async fn cache_paste_icon(
    hub: &crate::hub::Hub,
    app_instance_id: &str,
    server_app_instance_id: &str,
    paste: &serde_json::Value,
) {
    let Some(source) = paste.get("source").and_then(serde_json::Value::as_str) else {
        return;
    };
    if let Err(error) = hub
        .cache_icon_from_client(app_instance_id, server_app_instance_id, source)
        .await
    {
        debug!(client_id = %app_instance_id, %source, %error, "source icon was not cached");
    }
}

async fn pull_paste(State(state): State<AppState>, headers: HeaderMap) -> RelayResult<Response> {
    require_paired_client(&state, &headers)?;
    let mut paste = state
        .database
        .recent_pastes(None, 1)
        .map_err(|error| RelayError::Internal(error.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| RelayError::BadRequest("no paste data available".into()))?;
    set_paste_server_id(&mut paste, &state.config.server_instance_id);
    secure_json_response(&state, &headers, &paste)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasteBatchQuery {
    create_time: Option<i64>,
    limit: Option<usize>,
}

async fn pull_paste_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PasteBatchQuery>,
) -> RelayResult<Response> {
    require_paired_client(&state, &headers)?;
    let mut pastes = state
        .database
        .recent_pastes(query.create_time, query.limit.unwrap_or(10).min(50))
        .map_err(|error| RelayError::Internal(error.to_string()))?;
    for paste in &mut pastes {
        set_paste_server_id(paste, &state.config.server_instance_id);
    }
    secure_json_response(&state, &headers, &pastes)
}

fn set_paste_server_id(paste: &mut serde_json::Value, server_id: &str) {
    if let Some(object) = paste.as_object_mut() {
        object.insert(
            "appInstanceId".to_string(),
            serde_json::Value::String(server_id.to_string()),
        );
    }
}

async fn list_paired_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    Ok(Json(state.hub.list_clients()))
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    Ok(Json(state.registry.list_devices()))
}

async fn create_room(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    let info = state.registry.create_room();
    Ok(Json(CreateRoomResponse {
        room_code: info.room_code,
        expires_at_ms: info.expires_at_ms,
    }))
}

async fn get_room(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    Ok(Json(state.registry.room_info(&code)?))
}

#[derive(Debug, Deserialize)]
struct JoinBody {
    app_instance_id: String,
}

async fn join_room(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<JoinBody>,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    if body.app_instance_id.trim().is_empty() {
        return Err(RelayError::MissingAppInstanceId);
    }
    let id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&body.app_instance_id)
        .to_string();
    Ok(Json(state.registry.join_room(&code, &id)?))
}

async fn leave_room(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<JoinBody>,
) -> RelayResult<impl IntoResponse> {
    check_auth(&state.config, &headers)?;
    let id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&body.app_instance_id)
        .to_string();
    state.registry.leave_room(&code, &id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct PathParams {
    target: String,
    path: String,
}

async fn proxy_path(
    State(state): State<AppState>,
    Path(params): Path<PathParams>,
    req: Request,
) -> RelayResult<Response> {
    check_auth(&state.config, req.headers())?;
    let path = normalize_path(&params.path, req.uri().query());
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = axum::body::to_bytes(req.into_body(), state.config.max_body_bytes)
        .await
        .map_err(|e| RelayError::BadRequest(format!("read body: {e}")))?;
    proxy_reconstructed(
        &state,
        &params.target,
        method,
        path,
        headers,
        body_bytes.to_vec(),
    )
    .await
}

async fn proxy_header_target(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request,
) -> RelayResult<Response> {
    check_auth(&state.config, req.headers())?;
    let target = resolve_target(req.headers(), None)?;
    let _source = require_source_app_instance(req.headers())?;
    let full_path = normalize_path(&path, req.uri().query());
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = axum::body::to_bytes(req.into_body(), state.config.max_body_bytes)
        .await
        .map_err(|e| RelayError::BadRequest(format!("read body: {e}")))?;
    proxy_reconstructed(
        &state,
        &target,
        method,
        full_path,
        headers,
        body_bytes.to_vec(),
    )
    .await
}

async fn proxy_original_path(State(state): State<AppState>, req: Request) -> RelayResult<Response> {
    let target = resolve_target(req.headers(), None)?;
    let _source = require_source_app_instance(req.headers())?;
    let full_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = axum::body::to_bytes(req.into_body(), state.config.max_body_bytes)
        .await
        .map_err(|e| RelayError::BadRequest(format!("read body: {e}")))?;
    proxy_reconstructed(
        &state,
        &target,
        method,
        full_path,
        headers,
        body_bytes.to_vec(),
    )
    .await
}

fn normalize_path(path: &str, query: Option<&str>) -> String {
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    match query {
        Some(q) => format!("{p}?{q}"),
        None => p,
    }
}

fn generate_token() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % 1_000_000
}

fn maybe_decrypt_body(
    state: &AppState,
    headers: &HeaderMap,
    app_instance_id: &str,
    body: &[u8],
) -> RelayResult<Vec<u8>> {
    if headers.get(crate::protocol::HEADER_SECURE).is_some() {
        state
            .hub
            .decrypt_from_client(app_instance_id, body)
            .map_err(|error| {
                warn!(client_id = %app_instance_id, %error, "secure request decryption failed");
                RelayError::DecryptFail
            })
    } else {
        Ok(body.to_vec())
    }
}

fn require_paired_client<'a>(state: &AppState, headers: &'a HeaderMap) -> RelayResult<&'a str> {
    let app_instance_id = headers
        .get(crate::protocol::HEADER_APP_INSTANCE_ID)
        .and_then(|value| value.to_str().ok())
        .ok_or(RelayError::MissingAppInstanceId)?;
    let target_app_instance_id = headers
        .get(crate::protocol::HEADER_TARGET_APP_INSTANCE_ID)
        .and_then(|value| value.to_str().ok())
        .ok_or(RelayError::AppInstanceMismatch)?;
    if target_app_instance_id != state.config.server_instance_id {
        warn!(client_id = %app_instance_id, target_id = %target_app_instance_id, expected_target_id = %state.config.server_instance_id, "request target does not match server");
        return Err(RelayError::AppInstanceMismatch);
    }
    if !state.hub.is_paired(app_instance_id) {
        info!(client_id = %app_instance_id, "heartbeat rejected because client has no active pairing key");
        return Err(RelayError::DecryptFail);
    }
    Ok(app_instance_id)
}

fn secure_json_response<T: Serialize>(
    state: &AppState,
    headers: &HeaderMap,
    value: &T,
) -> RelayResult<Response> {
    let mut body = serde_json::to_vec(value).map_err(|e| RelayError::Internal(e.to_string()))?;
    if headers.get(crate::protocol::HEADER_SECURE).is_some() {
        let app_instance_id = headers
            .get(crate::protocol::HEADER_APP_INSTANCE_ID)
            .and_then(|v| v.to_str().ok())
            .ok_or(RelayError::MissingAppInstanceId)?;
        body = state
            .hub
            .encrypt_for_client(app_instance_id, &body)
            .map_err(|e| RelayError::BadRequest(e.to_string()))?;
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|e| RelayError::Internal(e.to_string()))
}

async fn proxy_reconstructed(
    state: &AppState,
    target: &str,
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
) -> RelayResult<Response> {
    let mut builder = Request::builder().method(method).uri(&path);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    let req = builder
        .body(Body::from(body))
        .map_err(|e| RelayError::Internal(e.to_string()))?;
    proxy_to_device(&state.registry, target, req, state.config.max_body_bytes).await
}
