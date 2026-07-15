use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;

/// CrossPaste pure relay server configuration.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "crosspaste-relay",
    about = "Transparent CrossPaste relay: routes encrypted peer traffic without decrypting payloads"
)]
pub struct Config {
    /// HTTP listen address
    #[arg(long, env = "RELAY_LISTEN", default_value = "0.0.0.0:39445")]
    pub listen: SocketAddr,

    /// Shared secret required when a device registers / opens a tunnel.
    /// Empty string disables auth (dev only).
    #[arg(long, env = "RELAY_AUTH_TOKEN", default_value = "")]
    pub auth_token: String,

    /// Max body size proxied per request (bytes)
    #[arg(long, env = "RELAY_MAX_BODY_BYTES", default_value_t = 64 * 1024 * 1024)]
    pub max_body_bytes: usize,

    /// How long an idle device session is kept (seconds)
    #[arg(long, env = "RELAY_DEVICE_TTL_SECS", default_value_t = 120)]
    pub device_ttl_secs: u64,

    /// How long a room pairing code lives (seconds)
    #[arg(long, env = "RELAY_ROOM_TTL_SECS", default_value_t = 600)]
    pub room_ttl_secs: u64,

    /// Max concurrent in-flight proxied requests per device
    #[arg(long, env = "RELAY_MAX_INFLIGHT", default_value_t = 64)]
    pub max_inflight: usize,

    /// Proxy request timeout (seconds)
    #[arg(long, env = "RELAY_REQUEST_TIMEOUT_SECS", default_value_t = 60)]
    pub request_timeout_secs: u64,

    /// Log filter, e.g. info,crosspaste_relay=debug
    #[arg(long, env = "RUST_LOG", default_value = "info,crosspaste_relay=debug")]
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
