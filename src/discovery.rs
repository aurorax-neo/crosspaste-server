use crate::config::Config;
use crate::sync_info::{build_server_sync_info, encode_txt_record};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use std::sync::Arc;
use tracing::{info, warn};

pub const CROSSPASTE_SERVICE_TYPE: &str = "_crosspasteService._tcp.local.";

pub struct DiscoveryHandle {
    #[allow(dead_code)]
    daemon: ServiceDaemon,
    #[allow(dead_code)]
    fullnames: Vec<String>,
}

impl Drop for DiscoveryHandle {
    fn drop(&mut self) {
        for fullname in &self.fullnames {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.shutdown();
    }
}

pub fn start_mdns(config: Arc<Config>) -> anyhow::Result<Option<DiscoveryHandle>> {
    if !config.enable_mdns {
        return Ok(None);
    }

    let sync_info = build_server_sync_info(&config);
    let txt = encode_txt_record(&sync_info, 128)?;
    let host_name = format!("{}.local.", sanitize_host_label(&config.server_instance_id));
    let properties: Vec<(&str, &str)> = txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    anyhow::ensure!(
        !sync_info.endpoint_info.host_info_list.is_empty(),
        "no routable network interface found; set CROSSPASTE_SERVER_PUBLIC_HOST"
    );
    let daemon = ServiceDaemon::new()?;
    daemon.set_service_name_len_max(30)?;
    let mut fullnames = Vec::new();
    for host_info in &sync_info.endpoint_info.host_info_list {
        let host = &host_info.host_address;
        let address = host.parse()?;
        let instance = format!(
            "crosspaste@{}@{}",
            sync_info.app_info.app_instance_id,
            host.replace('.', "_").replace(':', "_")
        );
        let mut service_info = ServiceInfo::new(
            CROSSPASTE_SERVICE_TYPE,
            &instance,
            &host_name,
            host.as_str(),
            config.listen.port(),
            &properties[..],
        )?;
        service_info.set_interfaces(vec![IfKind::Addr(address)]);
        let fullname = service_info.get_fullname().to_string();
        if let Err(error) = daemon.register(service_info) {
            warn!(%error, %host, "failed to register mDNS discovery interface");
            continue;
        }
        info!(service = %fullname, %host, prefix = host_info.network_prefix_length, port = config.listen.port(), "mDNS discovery registered");
        fullnames.push(fullname);
    }
    anyhow::ensure!(
        !fullnames.is_empty(),
        "failed to register mDNS on all interfaces"
    );
    Ok(Some(DiscoveryHandle { daemon, fullnames }))
}

fn sanitize_host_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "crosspaste-server".to_string()
    } else {
        out
    }
}
