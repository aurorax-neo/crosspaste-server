use crate::config::Config;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use if_addrs::{get_if_addrs, IfAddr, IfOperStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub app_instance_id: String,
    pub app_version: String,
    pub app_revision: String,
    pub user_name: String,
    pub pairing_version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub network_prefix_length: i16,
    pub host_address: String,
    #[serde(default)]
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    pub name: String,
    pub arch: String,
    pub bit_mode: i32,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointInfo {
    pub device_id: String,
    pub device_name: String,
    pub platform: PlatformInfo,
    pub host_info_list: Vec<HostInfo>,
    pub port: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncInfo {
    pub app_info: AppInfo,
    pub endpoint_info: EndpointInfo,
}

pub fn build_server_sync_info(config: &Config) -> SyncInfo {
    let host_info_list = server_host_infos(config);

    SyncInfo {
        app_info: AppInfo {
            app_instance_id: config.server_instance_id.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            app_revision: "server".to_string(),
            user_name: config.server_user_name.clone(),
            pairing_version: Some(crate::protocol::PAIRING_VERSION),
        },
        endpoint_info: EndpointInfo {
            device_id: config.server_instance_id.clone(),
            device_name: config.server_device_name.clone(),
            platform: PlatformInfo {
                name: platform_name().to_string(),
                arch: std::env::consts::ARCH.to_string(),
                bit_mode: (std::mem::size_of::<usize>() * 8) as i32,
                version: std::env::consts::OS.to_string(),
            },
            host_info_list,
            port: config.listen.port() as i32,
        },
    }
}

pub fn server_host_infos(config: &Config) -> Vec<HostInfo> {
    if let Some(host) = config.public_host {
        return vec![HostInfo {
            network_prefix_length: default_prefix(host),
            host_address: host.to_string(),
            last_seen: 0,
        }];
    }
    if !config.listen.ip().is_unspecified() {
        return vec![HostInfo {
            network_prefix_length: default_prefix(config.listen.ip()),
            host_address: config.listen.ip().to_string(),
            last_seen: 0,
        }];
    }

    let mut addresses: Vec<(String, IpAddr, i16)> = get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|interface| {
            interface.oper_status == IfOperStatus::Up
                && !interface.is_loopback()
                && !interface.is_link_local()
                && !interface.is_p2p
                && config
                    .network_interface
                    .as_ref()
                    .is_none_or(|name| name == &interface.name)
        })
        .filter_map(|interface| match interface.addr {
            IfAddr::V4(address) => Some((
                interface.name,
                IpAddr::V4(address.ip),
                address.prefixlen as i16,
            )),
            IfAddr::V6(_) => None,
        })
        .collect();
    addresses.sort_by_key(|(name, address, prefix)| interface_rank(name, *address, *prefix));
    addresses.dedup_by_key(|(_, address, _)| *address);
    addresses
        .into_iter()
        .take(1)
        .map(|(_, address, prefix)| HostInfo {
            network_prefix_length: prefix,
            host_address: address.to_string(),
            last_seen: 0,
        })
        .collect()
}

fn interface_rank(name: &str, address: IpAddr, prefix: i16) -> (u8, u8, std::cmp::Reverse<i16>) {
    let name = name.to_ascii_lowercase();
    let interface_type = if name.starts_with("en")
        || name.starts_with("eth")
        || name.starts_with("wlan")
        || name.starts_with("wl")
    {
        0
    } else if name.starts_with("utun")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("docker")
        || name.starts_with("bridge")
        || name.starts_with("veth")
    {
        2
    } else {
        1
    };
    let subnet = match address {
        IpAddr::V4(address) if address.octets()[0] == 192 && address.octets()[1] == 168 => 0,
        IpAddr::V4(address)
            if address.octets()[0] == 172 && (16..=31).contains(&address.octets()[1]) =>
        {
            1
        }
        IpAddr::V4(address) if address.octets()[0] == 10 => 2,
        _ => 3,
    };
    (interface_type, subnet, std::cmp::Reverse(prefix))
}

pub fn encode_sync_info_header(sync_info: &SyncInfo) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(sync_info)?;
    Ok(B64.encode(bytes))
}

pub fn encode_txt_record(
    sync_info: &SyncInfo,
    chunk_size: usize,
) -> anyhow::Result<HashMap<String, String>> {
    let json = serde_json::to_string(sync_info)?;
    let encoded = B64.encode(json.as_bytes());
    let mut out = HashMap::new();
    for (index, chunk) in encoded.as_bytes().chunks(chunk_size).enumerate() {
        out.insert(
            index.to_string(),
            String::from_utf8_lossy(chunk).to_string(),
        );
    }
    Ok(out)
}

pub fn encode_qr_payload(sync_info: &SyncInfo, token: u32) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(sync_info)?;
    if bytes.is_empty() {
        return Ok(B64.encode(token.to_be_bytes()));
    }
    let offset = (token as usize) % bytes.len();
    let mut rotated = rotate_right(&bytes, offset);
    rotated.extend_from_slice(&token.to_be_bytes());
    Ok(B64.encode(rotated))
}

pub fn decode_qr_payload(encoded: &str) -> anyhow::Result<(SyncInfo, u32)> {
    let decoded = B64.decode(encoded)?;
    anyhow::ensure!(decoded.len() >= 5, "QR payload too short");
    let token_bytes = &decoded[decoded.len() - 4..];
    let token = u32::from_be_bytes(token_bytes.try_into()?);
    let rotated = &decoded[..decoded.len() - 4];
    let offset = (token as usize) % rotated.len();
    let original = rotate_right(rotated, (rotated.len() - offset) % rotated.len());
    let sync_info = serde_json::from_slice(&original)?;
    Ok((sync_info, token))
}

fn rotate_right(bytes: &[u8], offset: usize) -> Vec<u8> {
    if bytes.is_empty() || offset == 0 {
        return bytes.to_vec();
    }
    let len = bytes.len();
    (0..len).map(|i| bytes[(i + len - offset) % len]).collect()
}

fn default_prefix(host: IpAddr) -> i16 {
    match host {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 64,
    }
}

fn platform_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "Macos",
        "windows" => "Windows",
        "linux" => "Linux",
        _ => "Unknown",
    }
}
