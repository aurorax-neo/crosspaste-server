use crate::auth::check_auth;
use crate::error::{RelayError, RelayResult};
use crate::protocol::{CreateRoomResponse, HealthResponse, SYNC_API_VERSION};
use crate::proxy::{proxy_to_device, require_source_app_instance, resolve_target};
use crate::tunnel::AppState;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub fn build_router(state: AppState) -> Router {
    let max_body = state.config.max_body_bytes;

    Router::new()
        // Relay control plane
        .route("/health", get(health))
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
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    state.registry.gc_rooms();
    Json(HealthResponse {
        ok: true,
        service: "crosspaste-relay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        sync_api_version: SYNC_API_VERSION,
        online_devices: state.registry.online_count(),
        rooms: state.registry.room_count(),
    })
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
    proxy_to_device(
        &state.registry,
        target,
        req,
        state.config.max_body_bytes,
    )
    .await
}
