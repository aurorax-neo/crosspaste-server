use crate::config::Config;
use crate::error::{RelayError, RelayResult};
use crate::protocol::{DevicePublicInfo, RoomInfo, TunnelFrame};
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub type FrameTx = mpsc::UnboundedSender<TunnelFrame>;

#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingRequest {
    pub responder: oneshot::Sender<TunnelFrame>,
    pub created_at: SystemTime,
}

#[derive(Debug)]
pub struct DeviceSession {
    pub app_instance_id: String,
    pub session_id: String,
    pub device_name: Option<String>,
    pub app_version: Option<String>,
    #[allow(dead_code)]
    pub sync_info_b64: Option<String>,
    pub last_seen_ms: AtomicI64,
    pub frame_tx: FrameTx,
    pub pending: DashMap<String, PendingRequest>,
    pub room_code: Option<String>,
}

impl DeviceSession {
    pub fn touch(&self) {
        self.last_seen_ms.store(now_ms(), Ordering::Relaxed);
    }

    pub fn public(&self) -> DevicePublicInfo {
        DevicePublicInfo {
            app_instance_id: self.app_instance_id.clone(),
            device_name: self.device_name.clone(),
            app_version: self.app_version.clone(),
            online: true,
            last_seen_ms: self.last_seen_ms.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Room {
    pub code: String,
    pub members: HashSet<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Clone)]
pub struct Registry {
    config: Arc<Config>,
    devices: Arc<DashMap<String, Arc<DeviceSession>>>,
    rooms: Arc<DashMap<String, Room>>,
}

impl Registry {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            devices: Arc::new(DashMap::new()),
            rooms: Arc::new(DashMap::new()),
        }
    }

    pub fn online_count(&self) -> usize {
        self.devices.len()
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    pub fn list_devices(&self) -> Vec<DevicePublicInfo> {
        self.devices.iter().map(|e| e.value().public()).collect()
    }

    pub fn get_device(&self, app_instance_id: &str) -> Option<Arc<DeviceSession>> {
        self.devices.get(app_instance_id).map(|e| e.clone())
    }

    pub fn register_device(
        &self,
        app_instance_id: String,
        device_name: Option<String>,
        app_version: Option<String>,
        sync_info_b64: Option<String>,
        frame_tx: FrameTx,
    ) -> Arc<DeviceSession> {
        let session_id = Uuid::new_v4().to_string();
        if let Some((_, old)) = self.devices.remove(&app_instance_id) {
            warn!(
                app_instance_id = %app_instance_id,
                old_session = %old.session_id,
                "replacing existing device tunnel"
            );
            let _ = old.frame_tx.send(TunnelFrame::Error {
                message: "session replaced by a new connection".into(),
            });
        }

        let session = Arc::new(DeviceSession {
            app_instance_id: app_instance_id.clone(),
            session_id: session_id.clone(),
            device_name,
            app_version,
            sync_info_b64,
            last_seen_ms: AtomicI64::new(now_ms()),
            frame_tx,
            pending: DashMap::new(),
            room_code: None,
        });
        self.devices
            .insert(app_instance_id.clone(), session.clone());
        info!(
            app_instance_id = %app_instance_id,
            session_id = %session_id,
            "device online"
        );
        session
    }

    pub fn unregister_device(&self, app_instance_id: &str, session_id: &str) {
        let matches = self
            .devices
            .get(app_instance_id)
            .map(|e| e.session_id == session_id)
            .unwrap_or(false);
        if !matches {
            return;
        }
        if let Some((_, session)) = self.devices.remove(app_instance_id) {
            let pending_keys: Vec<String> =
                session.pending.iter().map(|e| e.key().clone()).collect();
            for key in pending_keys {
                if let Some((_, pending)) = session.pending.remove(&key) {
                    let _ = pending.responder.send(TunnelFrame::Error {
                        message: "device disconnected".into(),
                    });
                }
            }
            if let Some(code) = &session.room_code {
                self.leave_room(code, app_instance_id);
            }
            info!(app_instance_id = %app_instance_id, "device offline");
        }
    }

    pub fn touch_device(&self, app_instance_id: &str) {
        if let Some(session) = self.devices.get(app_instance_id) {
            session.touch();
        }
    }

    pub fn complete_request(&self, app_instance_id: &str, frame: TunnelFrame) {
        let request_id = match &frame {
            TunnelFrame::HttpResponse { request_id, .. } => request_id.clone(),
            _ => return,
        };
        if let Some(session) = self.devices.get(app_instance_id) {
            if let Some((_, pending)) = session.pending.remove(&request_id) {
                let _ = pending.responder.send(frame);
            } else {
                debug!(%request_id, "no pending request for response");
            }
        }
    }

    pub async fn proxy_http(
        &self,
        target_app_instance_id: &str,
        method: String,
        path: String,
        headers: std::collections::HashMap<String, String>,
        body_b64: Option<String>,
    ) -> RelayResult<TunnelFrame> {
        let session = self
            .get_device(target_app_instance_id)
            .ok_or_else(|| RelayError::DeviceOffline(target_app_instance_id.to_string()))?;

        if session.pending.len() >= self.config.max_inflight {
            return Err(RelayError::DeviceBusy);
        }

        session.touch();
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        session.pending.insert(
            request_id.clone(),
            PendingRequest {
                responder: tx,
                created_at: SystemTime::now(),
            },
        );

        let frame = TunnelFrame::HttpRequest {
            request_id: request_id.clone(),
            method,
            path,
            headers,
            body_b64,
        };

        if session.frame_tx.send(frame).is_err() {
            session.pending.remove(&request_id);
            return Err(RelayError::DeviceOffline(
                target_app_instance_id.to_string(),
            ));
        }

        match tokio::time::timeout(self.config.request_timeout(), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                session.pending.remove(&request_id);
                Err(RelayError::Internal("response channel closed".into()))
            }
            Err(_) => {
                session.pending.remove(&request_id);
                Err(RelayError::ProxyTimeout)
            }
        }
    }

    pub fn create_room(&self) -> RoomInfo {
        let code = generate_room_code();
        let now = SystemTime::now();
        let expires_at = now + self.config.room_ttl();
        let room = Room {
            code: code.clone(),
            members: HashSet::new(),
            created_at: now,
            expires_at,
        };
        self.rooms.insert(code.clone(), room);
        RoomInfo {
            room_code: code,
            members: vec![],
            expires_at_ms: system_time_ms(expires_at),
        }
    }

    pub fn join_room(&self, room_code: &str, app_instance_id: &str) -> RelayResult<RoomInfo> {
        self.gc_rooms();
        let mut room = self
            .rooms
            .get_mut(room_code)
            .ok_or(RelayError::RoomNotFound)?;
        if room.expires_at < SystemTime::now() {
            drop(room);
            self.rooms.remove(room_code);
            return Err(RelayError::RoomNotFound);
        }
        if room.members.len() >= 32 {
            return Err(RelayError::RoomFull);
        }
        room.members.insert(app_instance_id.to_string());
        let expires_at_ms = system_time_ms(room.expires_at);
        let members: Vec<_> = room
            .members
            .iter()
            .filter_map(|id| self.get_device(id).map(|d| d.public()))
            .collect();
        Ok(RoomInfo {
            room_code: room_code.to_string(),
            members,
            expires_at_ms,
        })
    }

    pub fn leave_room(&self, room_code: &str, app_instance_id: &str) {
        if let Some(mut room) = self.rooms.get_mut(room_code) {
            room.members.remove(app_instance_id);
            let empty = room.members.is_empty();
            drop(room);
            if empty {
                self.rooms.remove(room_code);
            }
        }
    }

    pub fn room_info(&self, room_code: &str) -> RelayResult<RoomInfo> {
        self.gc_rooms();
        let room = self.rooms.get(room_code).ok_or(RelayError::RoomNotFound)?;
        let members: Vec<_> = room
            .members
            .iter()
            .filter_map(|id| self.get_device(id).map(|d| d.public()))
            .collect();
        Ok(RoomInfo {
            room_code: room_code.to_string(),
            members,
            expires_at_ms: system_time_ms(room.expires_at),
        })
    }

    pub fn gc_rooms(&self) {
        let now = SystemTime::now();
        self.rooms.retain(|_, room| room.expires_at > now);
    }

    pub fn gc_stale_devices(&self) {
        let ttl_ms = self.config.device_ttl().as_millis() as i64;
        let now = now_ms();
        let stale: Vec<(String, String)> = self
            .devices
            .iter()
            .filter_map(|e| {
                let s = e.value();
                if now - s.last_seen_ms.load(Ordering::Relaxed) > ttl_ms {
                    Some((s.app_instance_id.clone(), s.session_id.clone()))
                } else {
                    None
                }
            })
            .collect();
        for (id, sid) in stale {
            warn!(app_instance_id = %id, "evicting stale device");
            self.unregister_device(&id, &sid);
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn system_time_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn generate_room_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(6);
    let bytes = Uuid::new_v4().into_bytes();
    for b in bytes.iter().take(6) {
        out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    out
}
