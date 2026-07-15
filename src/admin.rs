use crate::database::{verify_password, AdminUser, Database, DEFAULT_ADMIN_PASSWORD};
use crate::qr::render_qr_png;
use crate::sync_info::{build_server_sync_info, encode_qr_payload, SyncInfo};
use crate::tunnel::AppState;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;

const SESSION_COOKIE: &str = "crosspaste_admin_session";
const SESSION_TTL_MS: i64 = 12 * 60 * 60 * 1000;
const CLIENT_ONLINE_WINDOW_MS: i64 = 45_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Redirect::temporary("/admin") }))
        .route("/admin", get(admin_page))
        .route("/admin/", get(admin_page))
        .route("/admin/app.css", get(admin_css))
        .route("/admin/app.js", get(admin_js))
        .route("/api/admin/login", post(login))
        .route("/api/admin/logout", post(logout))
        .route("/api/admin/me", get(me))
        .route("/api/admin/password", post(change_password))
        .route("/api/admin/mfa/setup", post(mfa_setup))
        .route("/api/admin/mfa/enable", post(mfa_enable))
        .route("/api/admin/mfa/disable", post(mfa_disable))
        .route("/api/admin/dashboard", get(dashboard))
        .route(
            "/api/admin/settings",
            get(get_settings).put(update_settings),
        )
        .route("/api/admin/clients", get(clients))
        .route("/api/admin/clients/{id}", delete(remove_client))
        .route("/api/admin/audit", get(audit_logs))
        .route("/api/admin/logs", get(request_logs))
        .route(
            "/api/admin/pairing",
            get(pairing_status).post(create_pairing),
        )
}

async fn admin_page() -> Response {
    html(include_str!("../assets/admin/index.html"))
}

async fn admin_css() -> Response {
    asset(
        "text/css; charset=utf-8",
        include_str!("../assets/admin/app.css"),
    )
}

async fn admin_js() -> Response {
    asset(
        "application/javascript; charset=utf-8",
        include_str!("../assets/admin/app.js"),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: String,
    password: String,
    mfa_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    user: AdminUser,
    mfa_required: bool,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(request): Json<LoginRequest>,
) -> Response {
    let remote = remote.to_string();
    let Some(user) = state
        .database
        .get_admin_user(request.username.trim())
        .ok()
        .flatten()
    else {
        let _ = state
            .database
            .audit(None, "login_failed", "unknown username", Some(&remote));
        return api_error(StatusCode::UNAUTHORIZED, "用户名或密码错误");
    };
    if !verify_password(&request.password, &user.password_hash) {
        let _ = state.database.audit(
            Some(&user.user.username),
            "login_failed",
            "invalid password",
            Some(&remote),
        );
        return api_error(StatusCode::UNAUTHORIZED, "用户名或密码错误");
    }
    if user.user.mfa_enabled {
        let Some(code) = request
            .mfa_code
            .as_deref()
            .filter(|code| !code.trim().is_empty())
        else {
            return Json(LoginResponse {
                user: user.user,
                mfa_required: true,
            })
            .into_response();
        };
        if !user
            .mfa_secret
            .as_deref()
            .is_some_and(|secret| verify_totp(secret, code))
        {
            return api_error(StatusCode::UNAUTHORIZED, "MFA 验证码错误");
        }
    }
    let token = random_token();
    let token_hash = token_hash(&token);
    if let Err(error) = state.database.create_session(
        &user.user.username,
        &token_hash,
        now_ms() + SESSION_TTL_MS,
        Some(&remote),
    ) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state.database.audit(
        Some(&user.user.username),
        "login",
        "admin login",
        Some(&remote),
    );
    let mut response = Json(LoginResponse {
        user: user.user,
        mfa_required: false,
    })
    .into_response();
    set_session_cookie(response.headers_mut(), &token);
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie(&headers, SESSION_COOKIE) {
        let _ = state.database.delete_session(&token_hash(token));
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "crosspaste_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticated(&state.database, &headers) {
        Ok(user) => Json(user).into_response(),
        Err(response) => response,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordRequest {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(request): Json<PasswordRequest>,
) -> Response {
    let user = match authenticated(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(secret) = state.database.get_admin_user(&user.username).ok().flatten() else {
        return api_error(StatusCode::UNAUTHORIZED, "登录状态无效");
    };
    if !verify_password(&request.current_password, &secret.password_hash) {
        return api_error(StatusCode::BAD_REQUEST, "当前密码错误");
    }
    if let Err(message) = validate_password(
        &user.username,
        &request.new_password,
        &request.confirm_password,
    ) {
        return api_error(StatusCode::BAD_REQUEST, message);
    }
    if verify_password(&request.new_password, &secret.password_hash) {
        return api_error(StatusCode::BAD_REQUEST, "新密码不能与当前密码相同");
    }
    if let Err(error) = state
        .database
        .update_password(&user.username, &request.new_password)
    {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state.database.audit(
        Some(&user.username),
        "password_changed",
        "password updated",
        Some(&remote.to_string()),
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "crosspaste_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    response
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MfaSetupResponse {
    secret: String,
    otpauth_uri: String,
    qr_data_uri: String,
}

async fn mfa_setup(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let secret = random_mfa_secret();
    if let Err(error) = state.database.set_mfa(&user.username, Some(&secret), false) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let account = url_encode(&format!("CrossPaste Server:{}", user.username));
    let uri = format!("otpauth://totp/{account}?secret={secret}&issuer=CrossPaste%20Server&algorithm=SHA1&digits=6&period=30");
    let qr_data_uri = match render_qr_png(&uri) {
        Ok(png) => format!("data:image/png;base64,{}", B64.encode(png)),
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    Json(MfaSetupResponse {
        secret,
        otpauth_uri: uri,
        qr_data_uri,
    })
    .into_response()
}

#[derive(Deserialize)]
struct MfaCodeRequest {
    code: String,
}

async fn mfa_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MfaCodeRequest>,
) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(secret) = state
        .database
        .get_admin_user(&user.username)
        .ok()
        .flatten()
        .and_then(|value| value.mfa_secret)
    else {
        return api_error(StatusCode::BAD_REQUEST, "请先生成 MFA 密钥");
    };
    if !verify_totp(&secret, &request.code) {
        return api_error(StatusCode::BAD_REQUEST, "验证码错误");
    }
    if let Err(error) = state.database.set_mfa(&user.username, Some(&secret), true) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state
        .database
        .audit(Some(&user.username), "mfa_enabled", "TOTP enabled", None);
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MfaDisableRequest {
    password: String,
    code: String,
}

async fn mfa_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MfaDisableRequest>,
) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(secret) = state.database.get_admin_user(&user.username).ok().flatten() else {
        return api_error(StatusCode::UNAUTHORIZED, "登录状态无效");
    };
    if !verify_password(&request.password, &secret.password_hash)
        || !secret
            .mfa_secret
            .as_deref()
            .is_some_and(|value| verify_totp(value, &request.code))
    {
        return api_error(StatusCode::BAD_REQUEST, "密码或验证码错误");
    }
    if let Err(error) = state.database.set_mfa(&user.username, None, false) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state
        .database
        .audit(Some(&user.username), "mfa_disabled", "TOTP disabled", None);
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardResponse {
    paired_clients: usize,
    online_clients: usize,
    database_path: String,
    version: String,
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    let active_since_ms = now_ms() - CLIENT_ONLINE_WINDOW_MS;
    let mut online_ids: std::collections::HashSet<String> =
        match state.database.online_client_ids(active_since_ms) {
            Ok(ids) => ids.into_iter().collect(),
            Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    online_ids.extend(
        state
            .registry
            .list_devices()
            .into_iter()
            .map(|device| device.app_instance_id),
    );
    Json(DashboardResponse {
        paired_clients: state.hub.paired_count(),
        online_clients: online_ids.len(),
        database_path: state.database.path().display().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
    .into_response()
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    match state.database.settings() {
        Ok(settings) => Json(settings).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(settings): Json<HashMap<String, String>>,
) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(message) = validate_settings(&settings) {
        return api_error(StatusCode::BAD_REQUEST, message);
    }
    if let Err(error) = state.database.update_settings(&settings) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state.database.audit(
        Some(&user.username),
        "settings_updated",
        &serde_json::to_string(&settings).unwrap_or_default(),
        None,
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    let now = now_ms();
    let mut devices = vec![AdminClient::server(&state)];
    let stored_clients = match state.database.load_clients() {
        Ok(clients) => clients,
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    devices.extend(stored_clients.into_iter().map(|client| {
        let sync_info = client
            .sync_info_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<SyncInfo>(json).ok())
            .or_else(|| state.hub.client_sync_info(&client.app_instance_id));
        let tunnel = state.registry.get_device(&client.app_instance_id);
        let online = tunnel.is_some()
            || client
                .last_seen_ms
                .is_some_and(|last_seen| now.saturating_sub(last_seen) <= CLIENT_ONLINE_WINDOW_MS);
        AdminClient::from_client(client, sync_info, tunnel.as_deref(), online)
    }));
    devices.sort_by(|left, right| {
        right
            .is_server
            .cmp(&left.is_server)
            .then_with(|| right.online.cmp(&left.online))
            .then_with(|| left.device_name.cmp(&right.device_name))
    });
    Json(devices).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminClient {
    app_instance_id: String,
    device_name: String,
    device_id: Option<String>,
    platform_name: String,
    platform_version: String,
    architecture: String,
    app_version: String,
    user_name: Option<String>,
    addresses: Vec<String>,
    port: Option<i32>,
    paired_at_ms: Option<i64>,
    last_seen_ms: Option<i64>,
    online: bool,
    is_server: bool,
}

impl AdminClient {
    fn server(state: &AppState) -> Self {
        let info = build_server_sync_info(&state.config);
        Self {
            app_instance_id: info.app_info.app_instance_id,
            device_name: info.endpoint_info.device_name,
            device_id: Some(info.endpoint_info.device_id),
            platform_name: info.endpoint_info.platform.name,
            platform_version: info.endpoint_info.platform.version,
            architecture: info.endpoint_info.platform.arch,
            app_version: info.app_info.app_version,
            user_name: Some(info.app_info.user_name),
            addresses: info
                .endpoint_info
                .host_info_list
                .into_iter()
                .map(|host| host.host_address)
                .collect(),
            port: Some(info.endpoint_info.port),
            paired_at_ms: None,
            last_seen_ms: Some(now_ms()),
            online: true,
            is_server: true,
        }
    }

    fn from_client(
        client: crate::database::StoredClient,
        sync_info: Option<SyncInfo>,
        tunnel: Option<&crate::registry::DeviceSession>,
        online: bool,
    ) -> Self {
        let endpoint = sync_info.as_ref().map(|info| &info.endpoint_info);
        let app = sync_info.as_ref().map(|info| &info.app_info);
        Self {
            app_instance_id: client.app_instance_id.clone(),
            device_name: endpoint
                .map(|value| value.device_name.clone())
                .or_else(|| tunnel.and_then(|value| value.device_name.clone()))
                .unwrap_or_else(|| client.app_instance_id.clone()),
            device_id: endpoint.map(|value| value.device_id.clone()),
            platform_name: endpoint
                .map(|value| value.platform.name.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            platform_version: endpoint
                .map(|value| value.platform.version.clone())
                .unwrap_or_default(),
            architecture: endpoint
                .map(|value| value.platform.arch.clone())
                .unwrap_or_default(),
            app_version: app
                .map(|value| value.app_version.clone())
                .or_else(|| tunnel.and_then(|value| value.app_version.clone()))
                .unwrap_or_default(),
            user_name: app.map(|value| value.user_name.clone()),
            addresses: endpoint
                .map(|value| {
                    value
                        .host_info_list
                        .iter()
                        .map(|host| host.host_address.clone())
                        .collect()
                })
                .unwrap_or_default(),
            port: endpoint.map(|value| value.port),
            paired_at_ms: Some(client.paired_at_ms),
            last_seen_ms: tunnel
                .map(|value| {
                    value
                        .last_seen_ms
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .or(client.last_seen_ms),
            online,
            is_server: false,
        }
    }
}

async fn remove_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(error) = state.hub.remove_client(&id) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let _ = state
        .database
        .audit(Some(&user.username), "client_removed", &id, None);
    StatusCode::NO_CONTENT.into_response()
}

async fn audit_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    match state.database.audit_logs(200) {
        Ok(logs) => Json(logs).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn request_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    match state.database.request_logs(500) {
        Ok(logs) => Json(logs).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingStatusResponse {
    challenges: Vec<crate::hub::PairingChallenge>,
}

async fn pairing_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_ready_user(&state.database, &headers) {
        return response;
    }
    Json(PairingStatusResponse {
        challenges: state.hub.pairing_challenges(),
    })
    .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePairingResponse {
    code: String,
    expires_at_ms: i64,
    qr_data_uri: String,
}

async fn create_pairing(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match require_ready_user(&state.database, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let token = state.hub.issue_pairing_token();
    let sync_info = build_server_sync_info(&state.config);
    let payload = match encode_qr_payload(&sync_info, token) {
        Ok(payload) => payload,
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let png = match render_qr_png(&payload) {
        Ok(png) => png,
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let expires_at_ms = now_ms() + 30_000;
    let _ = state.database.audit(
        Some(&user.username),
        "pairing_code_created",
        &format!("token {token:06}"),
        None,
    );
    Json(CreatePairingResponse {
        code: format!("{token:06}"),
        expires_at_ms,
        qr_data_uri: format!("data:image/png;base64,{}", B64.encode(png)),
    })
    .into_response()
}

fn authenticated(database: &Database, headers: &HeaderMap) -> Result<AdminUser, Response> {
    let token = cookie(headers, SESSION_COOKIE)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "请先登录"))?;
    database
        .session_user(&token_hash(token))
        .ok()
        .flatten()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "登录已过期"))
}

fn require_ready_user(database: &Database, headers: &HeaderMap) -> Result<AdminUser, Response> {
    let user = authenticated(database, headers)?;
    if user.must_change_password {
        return Err(api_error(StatusCode::FORBIDDEN, "首次登录必须修改密码"));
    }
    Ok(user)
}

fn validate_password(
    username: &str,
    password: &str,
    confirmation: &str,
) -> Result<(), &'static str> {
    if password != confirmation {
        return Err("两次输入的新密码不一致");
    }
    if password.len() < 12 || password.len() > 128 {
        return Err("密码长度必须为 12 到 128 个字符");
    }
    if password == DEFAULT_ADMIN_PASSWORD
        || password
            .to_ascii_lowercase()
            .contains(&username.to_ascii_lowercase())
    {
        return Err("密码不能使用默认密码或包含用户名");
    }
    let checks = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ];
    if checks.into_iter().any(|value| !value) {
        return Err("密码必须同时包含大小写字母、数字和特殊字符");
    }
    Ok(())
}

fn validate_settings(settings: &HashMap<String, String>) -> Result<(), &'static str> {
    let allowed = [
        "encrypt_sync",
        "limit_file_size",
        "max_file_size_mb",
        "clipboard_relay",
        "sync_text",
        "sync_url",
        "sync_html",
        "sync_rtf",
        "sync_image",
        "sync_file",
        "sync_color",
        "log_retention_count",
    ];
    if settings.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("包含未知设置项");
    }
    if let Some(value) = settings.get("max_file_size_mb") {
        if value
            .parse::<u64>()
            .ok()
            .filter(|value| (1..=102400).contains(value))
            .is_none()
        {
            return Err("最大文件大小必须在 1 到 102400 MB 之间");
        }
    }
    if let Some(value) = settings.get("log_retention_count") {
        if value
            .parse::<usize>()
            .ok()
            .filter(|value| (1000..=1_000_000).contains(value))
            .is_none()
        {
            return Err("日志存储上限必须在 1000 到 1000000 条之间");
        }
    }
    for (key, value) in settings {
        if key != "max_file_size_mb"
            && key != "log_retention_count"
            && value != "true"
            && value != "false"
        {
            return Err("开关值必须为 true 或 false");
        }
    }
    Ok(())
}

fn verify_totp(secret: &str, code: &str) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|value| value.is_ascii_digit()) {
        return false;
    }
    let current = (now_ms() / 1000) / 30;
    (-1i64..=1)
        .any(|offset| totp(secret, (current + offset) as u64).is_some_and(|value| value == code))
}

fn totp(secret: &str, counter: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret.as_bytes()).ok()?;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    Some(format!("{:06}", binary % 1_000_000))
}

fn random_mfa_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}
fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            part.trim()
                .split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
}
fn set_session_cookie(headers: &mut HeaderMap, token: &str) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_TTL_MS / 1000
    )) {
        headers.insert(header::SET_COOKIE, value);
    }
}
fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
fn api_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"message":message}))).into_response()
}
fn html(value: &'static str) -> Response {
    asset("text/html; charset=utf-8", value)
}
fn asset(content_type: &'static str, value: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(value))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_policy_rejects_default() {
        assert!(
            validate_password("admin", DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_PASSWORD).is_err()
        );
    }
    #[test]
    fn totp_matches_rfc_vector() {
        assert_eq!(
            totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1).unwrap(),
            "287082"
        );
    }
}
