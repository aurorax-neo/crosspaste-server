use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// CrossPaste central hub server configuration.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "crosspaste-server",
    about = "CrossPaste-compatible central hub: clients pair with this server and sync through it"
)]
pub struct Config {
    /// HTTP listen address
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_LISTEN",
        default_value = "0.0.0.0:39445"
    )]
    pub listen: SocketAddr,

    /// Shared secret required when a device registers / opens a tunnel.
    /// Empty string disables auth (dev only).
    #[arg(long, env = "CROSSPASTE_SERVER_AUTH_TOKEN", default_value = "")]
    pub auth_token: String,

    /// Max body size proxied per request (bytes)
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_MAX_BODY_BYTES",
        default_value_t = 64 * 1024 * 1024
    )]
    pub max_body_bytes: usize,

    /// How long an idle device session is kept (seconds)
    #[arg(long, env = "CROSSPASTE_SERVER_DEVICE_TTL_SECS", default_value_t = 120)]
    pub device_ttl_secs: u64,

    /// How long a room pairing code lives (seconds)
    #[arg(long, env = "CROSSPASTE_SERVER_ROOM_TTL_SECS", default_value_t = 600)]
    pub room_ttl_secs: u64,

    /// Max concurrent in-flight proxied requests per device
    #[arg(long, env = "CROSSPASTE_SERVER_MAX_INFLIGHT", default_value_t = 64)]
    pub max_inflight: usize,

    /// Proxy request timeout (seconds)
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_REQUEST_TIMEOUT_SECS",
        default_value_t = 60
    )]
    pub request_timeout_secs: u64,

    /// Advertise this server on LAN with CrossPaste-compatible mDNS.
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_ENABLE_MDNS",
        default_value_t = true,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub enable_mdns: bool,

    /// Public host/IP encoded in QR and advertised SyncInfo. Defaults to listen IP or first LAN IP.
    #[arg(long, env = "CROSSPASTE_SERVER_PUBLIC_HOST")]
    pub public_host: Option<IpAddr>,

    /// Network interface used for LAN discovery, for example en0 or eth0.
    /// When unset, the preferred active IPv4 interface is selected.
    #[arg(long, env = "CROSSPASTE_SERVER_NETWORK_INTERFACE")]
    pub network_interface: Option<String>,

    /// Persistent server state directory for keys and transferred files.
    #[arg(long, env = "CROSSPASTE_SERVER_DATA_DIR", default_value = "data")]
    pub data_dir: PathBuf,

    /// Stable server appInstanceId shown to CrossPaste clients.
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_INSTANCE_ID",
        default_value = "crosspaste-server"
    )]
    pub server_instance_id: String,

    /// Device name shown in discovery and QR flows.
    #[arg(
        long,
        env = "CROSSPASTE_SERVER_DEVICE_NAME",
        default_value = "CrossPaste Server"
    )]
    pub server_device_name: String,

    /// Username field in CrossPaste SyncInfo.
    #[arg(long, env = "CROSSPASTE_SERVER_USER_NAME", default_value = "server")]
    pub server_user_name: String,

    /// Log filter, e.g. info,crosspaste_server=debug
    #[arg(long, env = "RUST_LOG", default_value = "info,crosspaste_server=debug")]
    pub log: String,
}

impl Config {
    pub fn device_ttl(&self) -> Duration {
        Duration::from_secs(self.device_ttl_secs)
    }

    pub fn room_ttl(&self) -> Duration {
        Duration::from_secs(self.room_ttl_secs)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn auth_required(&self) -> bool {
        !self.auth_token.is_empty()
    }
}
