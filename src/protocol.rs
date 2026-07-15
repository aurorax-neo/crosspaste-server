//! Wire protocol between relay and device-side tunnel agents.
//!
//! Payload bodies are opaque bytes (already E2E encrypted by CrossPaste peers).
//! The relay never inspects or decrypts them.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CrossPaste Sync API version advertised by this relay.
pub const SYNC_API_VERSION: i32 = 3;
pub const PAIRING_VERSION: i32 = 2;

/// Headers used by CrossPaste desktop/web clients.
pub const HEADER_APP_INSTANCE_ID: &str = "appInstanceId";
pub const HEADER_TARGET_APP_INSTANCE_ID: &str = "targetAppInstanceId";
pub const HEADER_SECURE: &str = "secure";
pub const HEADER_SYNC_INFO: &str = "crosspaste-sync-info";
pub const HEADER_AUTH: &str = "x-relay-token";

/// Known CrossPaste peer HTTP paths (for documentation / allowlist optional use).
pub const CROSSPASTE_PATHS: &[&str] = &[
    "/sync/heartbeat",
    "/sync/heartbeat/syncInfo",
    "/sync/notifyExit",
    "/sync/notifyRemove",
    "/sync/showToken",
    "/sync/showPairingCode",
    "/sync/syncInfo",
    "/sync/telnet",
    "/sync/trust",
    "/sync/trust/v2/exchange",
    "/sync/trust/v2/confirm",
    "/sync/paste",
    "/sync/file/push",
    "/sync/paste/push/complete",
    "/sync/icon/push/{source}",
    "/pull/file",
    "/pull/icon/{source}",
    "/pull/paste",
    "/pull/pasteBatch",
    "/ws",
];

/// Control / data frames on the device WebSocket tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunnelFrame {
    /// Device → Relay: register / heartbeat identity
    Hello {
        app_instance_id: String,
        device_name: Option<String>,
        app_version: Option<String>,
        /// Optional Base64 SyncInfo JSON (same shape as CrossPaste SyncInfo)
        sync_info_b64: Option<String>,
    },
    /// Relay → Device: registration accepted
    HelloAck {
        session_id: String,
        relay_version: String,
    },
    /// Either direction keep-alive
    Ping { ts: i64 },
    Pong { ts: i64 },
    /// Relay → Device: execute this HTTP request against the local paste server
    HttpRequest {
        request_id: String,
        method: String,
        /// Absolute path + query, e.g. `/sync/paste`
        path: String,
        headers: HashMap<String, String>,
        /// Base64 body (opaque). Empty / omitted means no body.
        #[serde(default)]
        body_b64: Option<String>,
    },
    /// Device → Relay: response for a proxied request
    HttpResponse {
        request_id: String,
        status: u16,
        headers: HashMap<String, String>,
        #[serde(default)]
        body_b64: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    /// Relay → Device: peer presence update (optional)
    PeerEvent {
        event: PeerEventKind,
        app_instance_id: String,
    },
    /// Error notice
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerEventKind {
    Online,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicInfo {
    pub app_instance_id: String,
    pub device_name: Option<String>,
    pub app_version: Option<String>,
    pub online: bool,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomInfo {
    pub room_code: String,
    pub members: Vec<DevicePublicInfo>,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoomResponse {
    pub room_code: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
    pub version: String,
    pub sync_api_version: i32,
    pub online_devices: usize,
    pub rooms: usize,
}
