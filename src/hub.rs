use crate::database::Database;
use crate::secure::{
    build_key_exchange_response, build_trust_confirm_response, client_crypt_public_key,
    compute_sas, decode_public_key_b64, sign_pairing_response, verify_key_exchange_request,
    verify_pairing_request, verify_trust_confirm, KeyExchangeRequest, KeyExchangeResponse,
    PairingResponse, ServerKeys, TrustConfirmRequest, TrustConfirmResponse, TrustRequest,
    TrustResponse,
};
use crate::sync_info::SyncInfo;
use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const PAIRING_TOKEN_TTL_MS: i64 = 30_000;
pub const FILE_CHUNK_SIZE: u64 = 1024 * 1024;
const ENCRYPT_STREAM_CHUNK_SIZE: usize = 256 * 1024;

#[derive(Default)]
struct PairingToken {
    value: u32,
    expires_at_ms: i64,
    client_id: Option<String>,
}

struct PendingKeyExchange {
    sign_public_key: String,
    crypt_public_key: Vec<u8>,
    sas: u32,
    expires_at_ms: i64,
}

struct PushSession {
    paste_id: i64,
    from_app_instance_id: String,
    paste: serde_json::Value,
    token: String,
    chunk_count: usize,
    received: RwLock<Vec<bool>>,
    directory: PathBuf,
}

struct StoredFile {
    directory: PathBuf,
    chunk_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushPrepareResponse {
    pub paste_id: i64,
    pub chunk_count: usize,
    pub chunk_size: u64,
    pub session_token: String,
    pub need_icon: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushCompleteResponse {
    pub missing_chunks: Vec<usize>,
}

pub struct CompletedPush {
    paste_id: i64,
    from_app_instance_id: String,
    paste: serde_json::Value,
    chunk_count: usize,
    directory: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedClient {
    pub app_instance_id: String,
    pub paired_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingChallenge {
    pub client_id: String,
    pub code: String,
    pub kind: String,
    pub expires_at_ms: i64,
}

#[derive(Clone)]
pub struct Hub {
    keys: Arc<ServerKeys>,
    database: Database,
    transfer_dir: Arc<PathBuf>,
    icon_dir: Arc<PathBuf>,
    pairing_token: Arc<RwLock<PairingToken>>,
    clients: Arc<DashMap<String, PairedClient>>,
    client_crypt_keys: Arc<DashMap<String, Vec<u8>>>,
    pending_key_exchanges: Arc<DashMap<String, PendingKeyExchange>>,
    client_sync_infos: Arc<DashMap<String, SyncInfo>>,
    pastes: Arc<DashMap<String, serde_json::Value>>,
    push_sessions: Arc<DashMap<i64, Arc<PushSession>>>,
    stored_files: Arc<DashMap<i64, StoredFile>>,
}

impl Hub {
    pub fn load_or_create(data_dir: &Path, database: Database) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let transfer_dir = data_dir.join("transfers");
        let icon_dir = data_dir.join("icons");
        std::fs::create_dir_all(&transfer_dir)?;
        std::fs::create_dir_all(&icon_dir)?;
        let keys = database.load_or_create_server_keys()?;
        let persisted_clients = database.load_clients()?;
        let clients = Arc::new(DashMap::new());
        let client_crypt_keys = Arc::new(DashMap::new());
        let client_sync_infos = Arc::new(DashMap::new());
        for client in persisted_clients {
            if let Some(sync_info) = client
                .sync_info_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<SyncInfo>(json).ok())
            {
                client_sync_infos.insert(client.app_instance_id.clone(), sync_info);
            }
            client_crypt_keys.insert(client.app_instance_id.clone(), client.crypt_public_key);
            clients.insert(
                client.app_instance_id.clone(),
                PairedClient {
                    app_instance_id: client.app_instance_id,
                    paired_at_ms: client.paired_at_ms,
                },
            );
        }
        let hub = Self {
            keys: Arc::new(keys),
            database,
            transfer_dir: Arc::new(transfer_dir),
            icon_dir: Arc::new(icon_dir),
            pairing_token: Arc::new(RwLock::new(PairingToken::default())),
            clients,
            client_crypt_keys,
            pending_key_exchanges: Arc::new(DashMap::new()),
            client_sync_infos,
            pastes: Arc::new(DashMap::new()),
            push_sessions: Arc::new(DashMap::new()),
            stored_files: Arc::new(DashMap::new()),
        };
        Ok(hub)
    }

    pub fn set_pairing_token(&self, token: u32) {
        self.set_pairing_token_for(token, None);
    }

    pub fn set_pairing_token_for(&self, token: u32, client_id: Option<&str>) {
        let mut pairing_token = self
            .pairing_token
            .write()
            .expect("pairing token lock poisoned");
        pairing_token.value = token;
        pairing_token.expires_at_ms = now_ms() + PAIRING_TOKEN_TTL_MS;
        pairing_token.client_id = client_id.map(str::to_string);
    }

    pub fn issue_pairing_token(&self) -> u32 {
        self.issue_pairing_token_for(None)
    }

    pub fn issue_pairing_token_for(&self, client_id: Option<&str>) -> u32 {
        let token = 100_000 + OsRng.next_u32() % 900_000;
        self.set_pairing_token_for(token, client_id);
        token
    }

    pub fn pairing_challenges(&self) -> Vec<PairingChallenge> {
        let now = now_ms();
        let mut challenges: Vec<PairingChallenge> = self
            .pending_key_exchanges
            .iter()
            .filter(|entry| entry.expires_at_ms >= now)
            .map(|entry| PairingChallenge {
                client_id: entry.key().clone(),
                code: format!("{:06}", entry.sas),
                kind: "sas-v2".to_string(),
                expires_at_ms: entry.expires_at_ms,
            })
            .collect();
        let token = self
            .pairing_token
            .read()
            .expect("pairing token lock poisoned");
        if token.value != 0 && token.expires_at_ms >= now {
            challenges.push(PairingChallenge {
                client_id: token
                    .client_id
                    .clone()
                    .unwrap_or_else(|| "扫码配对".to_string()),
                code: format!("{:06}", token.value),
                kind: "token-v1".to_string(),
                expires_at_ms: token.expires_at_ms,
            });
        }
        challenges.sort_by_key(|challenge| std::cmp::Reverse(challenge.expires_at_ms));
        challenges
    }

    pub fn is_paired(&self, app_instance_id: &str) -> bool {
        self.clients.contains_key(app_instance_id)
    }

    pub fn paired_count(&self) -> usize {
        self.clients.len()
    }

    pub fn list_clients(&self) -> Vec<PairedClient> {
        self.clients
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn client_sync_info(&self, app_instance_id: &str) -> Option<SyncInfo> {
        self.client_sync_infos
            .get(app_instance_id)
            .map(|entry| entry.value().clone())
    }

    pub fn touch_client(&self, app_instance_id: &str) {
        let _ = self.database.touch_client(app_instance_id, now_ms());
    }

    pub fn trust_v1(
        &self,
        app_instance_id: &str,
        request: TrustRequest,
    ) -> anyhow::Result<TrustResponse> {
        anyhow::ensure!(
            verify_pairing_request(&request)?,
            "invalid pairing signature"
        );
        let pairing_token = self
            .pairing_token
            .read()
            .expect("pairing token lock poisoned");
        anyhow::ensure!(pairing_token.value != 0, "pairing token was not requested");
        anyhow::ensure!(
            pairing_token.expires_at_ms >= now_ms(),
            "pairing token expired"
        );
        anyhow::ensure!(
            request.pairing_request.token == pairing_token.value,
            "pairing token mismatch"
        );
        drop(pairing_token);

        let client_key = client_crypt_public_key(&request)?;
        self.client_crypt_keys
            .insert(app_instance_id.to_string(), client_key.clone());
        let paired_at_ms = now_ms();
        self.clients.insert(
            app_instance_id.to_string(),
            PairedClient {
                app_instance_id: app_instance_id.to_string(),
                paired_at_ms,
            },
        );
        self.database
            .save_client(app_instance_id, paired_at_ms, &client_key)?;
        info!(client_id = %app_instance_id, "client pairing accepted");

        let response = PairingResponse {
            sign_public_key: self.keys.sign_public_key_der_b64()?,
            crypt_public_key: self.keys.crypt_public_key_der_b64()?,
            timestamp: now_ms(),
        };
        let signature = sign_pairing_response(&self.keys, &response);
        Ok(TrustResponse {
            pairing_response: response,
            signature,
        })
    }

    pub fn exchange_keys_v2(
        &self,
        app_instance_id: &str,
        request: KeyExchangeRequest,
    ) -> anyhow::Result<(KeyExchangeResponse, u32)> {
        anyhow::ensure!(
            verify_key_exchange_request(&request)?,
            "invalid key exchange signature"
        );
        let client_crypt_public_key = decode_public_key_b64(&request.crypt_public_key)?;
        let server_crypt_public_key =
            decode_public_key_b64(&self.keys.crypt_public_key_der_b64()?)?;
        let sas = compute_sas(&server_crypt_public_key, &client_crypt_public_key);
        self.pending_key_exchanges.insert(
            app_instance_id.to_string(),
            PendingKeyExchange {
                sign_public_key: request.sign_public_key,
                crypt_public_key: client_crypt_public_key,
                sas,
                expires_at_ms: now_ms() + PAIRING_TOKEN_TTL_MS,
            },
        );
        Ok((build_key_exchange_response(&self.keys)?, sas))
    }

    pub fn confirm_trust_v2(
        &self,
        app_instance_id: &str,
        request: TrustConfirmRequest,
    ) -> anyhow::Result<TrustConfirmResponse> {
        let pending = self
            .pending_key_exchanges
            .get(app_instance_id)
            .ok_or_else(|| anyhow::anyhow!("key exchange not found or expired"))?;
        anyhow::ensure!(pending.expires_at_ms >= now_ms(), "key exchange expired");
        anyhow::ensure!(
            verify_trust_confirm(&pending.sign_public_key, &request)?,
            "invalid trust confirmation signature"
        );
        let client_key = pending.crypt_public_key.clone();
        let sas = pending.sas;
        drop(pending);
        self.pending_key_exchanges.remove(app_instance_id);
        self.client_crypt_keys
            .insert(app_instance_id.to_string(), client_key.clone());
        let paired_at_ms = now_ms();
        self.clients.insert(
            app_instance_id.to_string(),
            PairedClient {
                app_instance_id: app_instance_id.to_string(),
                paired_at_ms,
            },
        );
        self.database
            .save_client(app_instance_id, paired_at_ms, &client_key)?;
        info!(client_id = %app_instance_id, sas = %format!("{sas:06}"), "client v2 pairing accepted");
        Ok(build_trust_confirm_response(&self.keys))
    }

    pub fn receive_paste(
        &self,
        app_instance_id: &str,
        paste: serde_json::Value,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.is_paired(app_instance_id), "unpaired client");
        let paste_id = paste
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(now_ms);
        self.database.save_paste(
            paste_id,
            app_instance_id,
            paste.get("pasteType").and_then(serde_json::Value::as_i64),
            paste.get("size").and_then(serde_json::Value::as_i64),
            &serde_json::to_string(&paste)?,
        )?;
        self.pastes
            .insert(format!("{}:{paste_id}", app_instance_id), paste);
        Ok(())
    }

    pub fn prepare_push(
        &self,
        app_instance_id: &str,
        paste: serde_json::Value,
    ) -> anyhow::Result<PushPrepareResponse> {
        anyhow::ensure!(self.is_paired(app_instance_id), "unpaired client");
        let size = paste
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("file paste is missing size"))?;
        anyhow::ensure!(size > 0, "file paste size must be positive");
        let paste_id = now_ms();
        let chunk_count = size.div_ceil(FILE_CHUNK_SIZE) as usize;
        let token = uuid::Uuid::new_v4().to_string();
        let directory = self.transfer_dir.join(paste_id.to_string());
        std::fs::create_dir_all(&directory)?;
        self.push_sessions.insert(
            paste_id,
            Arc::new(PushSession {
                paste_id,
                from_app_instance_id: app_instance_id.to_string(),
                paste,
                token: token.clone(),
                chunk_count,
                received: RwLock::new(vec![false; chunk_count]),
                directory,
            }),
        );
        info!(client_id = %app_instance_id, paste_id, chunk_count, size, "file push session prepared");
        Ok(PushPrepareResponse {
            paste_id,
            chunk_count,
            chunk_size: FILE_CHUNK_SIZE,
            session_token: token,
            need_icon: false,
        })
    }

    pub fn store_push_chunk(
        &self,
        app_instance_id: &str,
        paste_id: i64,
        chunk_index: usize,
        token: &str,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        let session = self
            .push_sessions
            .get(&paste_id)
            .ok_or_else(|| anyhow::anyhow!("push session not found"))?;
        anyhow::ensure!(
            session.from_app_instance_id == app_instance_id,
            "push session owner mismatch"
        );
        anyhow::ensure!(session.token == token, "invalid push session token");
        anyhow::ensure!(
            chunk_index < session.chunk_count,
            "chunk index out of range"
        );
        std::fs::write(
            session.directory.join(format!("{chunk_index}.chunk")),
            bytes,
        )?;
        self.database
            .save_file_chunk(paste_id, chunk_index, bytes)?;
        session
            .received
            .write()
            .expect("push session lock poisoned")[chunk_index] = true;
        Ok(())
    }

    pub fn complete_push(
        &self,
        app_instance_id: &str,
        paste_id: i64,
        token: &str,
    ) -> anyhow::Result<(PushCompleteResponse, Option<CompletedPush>)> {
        let session = self
            .push_sessions
            .get(&paste_id)
            .ok_or_else(|| anyhow::anyhow!("push session not found"))?;
        anyhow::ensure!(
            session.from_app_instance_id == app_instance_id,
            "push session owner mismatch"
        );
        anyhow::ensure!(session.token == token, "invalid push session token");
        let missing_chunks: Vec<usize> = session
            .received
            .read()
            .expect("push session lock poisoned")
            .iter()
            .enumerate()
            .filter_map(|(index, received)| (!received).then_some(index))
            .collect();
        if !missing_chunks.is_empty() {
            return Ok((PushCompleteResponse { missing_chunks }, None));
        }
        let completed = CompletedPush {
            paste_id: session.paste_id,
            from_app_instance_id: session.from_app_instance_id.clone(),
            paste: session.paste.clone(),
            chunk_count: session.chunk_count,
            directory: session.directory.clone(),
        };
        drop(session);
        self.push_sessions.remove(&paste_id);
        Ok((PushCompleteResponse { missing_chunks }, Some(completed)))
    }

    pub fn update_client_sync_info(
        &self,
        app_instance_id: &str,
        sync_info: SyncInfo,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.is_paired(app_instance_id), "unpaired client");
        self.database.update_client_sync_info(
            app_instance_id,
            &serde_json::to_string(&sync_info)?,
            now_ms(),
        )?;
        self.client_sync_infos
            .insert(app_instance_id.to_string(), sync_info);
        Ok(())
    }

    pub async fn broadcast_paste(
        &self,
        from_app_instance_id: &str,
        server_app_instance_id: &str,
        paste: &serde_json::Value,
    ) -> BroadcastReport {
        let paste = normalize_paste(paste, server_app_instance_id, None);
        let body = match serde_json::to_vec(&paste) {
            Ok(body) => body,
            Err(error) => {
                warn!(%error, "failed to serialize paste for broadcast");
                return BroadcastReport::default();
            }
        };
        let client = reqwest::Client::new();
        let targets: Vec<(String, SyncInfo)> = self
            .client_sync_infos
            .iter()
            .filter_map(|e| {
                if e.key() == from_app_instance_id {
                    None
                } else {
                    Some((e.key().clone(), e.value().clone()))
                }
            })
            .collect();

        let mut report = BroadcastReport {
            attempted: targets.len(),
            ..BroadcastReport::default()
        };
        for (target_id, sync_info) in targets {
            let Some(host) = sync_info
                .endpoint_info
                .host_info_list
                .first()
                .map(|h| h.host_address.clone())
            else {
                report.failed += 1;
                warn!(target_id = %target_id, "paste target has no reachable host");
                continue;
            };
            let url = format!(
                "http://{}:{}/sync/paste",
                host, sync_info.endpoint_info.port
            );
            let encrypted = match self.encrypt_for_client(&target_id, &body) {
                Ok(encrypted) => encrypted,
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "failed to encrypt paste for target");
                    continue;
                }
            };
            match client
                .post(url)
                .header("appInstanceId", server_app_instance_id)
                .header("targetAppInstanceId", &target_id)
                .header("secure", "1")
                .header("content-type", "application/json")
                .body(encrypted)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    report.delivered += 1;
                    debug!(target_id = %target_id, "paste delivered to client");
                }
                Ok(response) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, status = %response.status(), "paste target rejected request");
                }
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "paste delivery failed");
                }
            }
        }
        report
    }

    pub async fn broadcast_completed_push(
        &self,
        completed: CompletedPush,
        server_app_instance_id: &str,
    ) -> BroadcastReport {
        let paste = normalize_paste(
            &completed.paste,
            server_app_instance_id,
            Some(completed.paste_id),
        );
        let body = match serde_json::to_vec(&paste) {
            Ok(body) => body,
            Err(error) => {
                warn!(%error, "failed to serialize file paste for broadcast");
                return BroadcastReport::default();
            }
        };
        let targets: Vec<(String, SyncInfo)> = self
            .client_sync_infos
            .iter()
            .filter_map(|entry| {
                (entry.key() != &completed.from_app_instance_id)
                    .then(|| (entry.key().clone(), entry.value().clone()))
            })
            .collect();
        let client = reqwest::Client::new();
        let mut report = BroadcastReport {
            attempted: targets.len(),
            ..BroadcastReport::default()
        };

        for (target_id, sync_info) in targets {
            let Some(base_url) = client_base_url(&sync_info) else {
                report.failed += 1;
                continue;
            };
            let encrypted_paste = match self.encrypt_for_client(&target_id, &body) {
                Ok(body) => body,
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "failed to encrypt file paste metadata");
                    continue;
                }
            };
            let prepare_response = match client
                .post(format!("{base_url}/sync/paste"))
                .header("appInstanceId", server_app_instance_id)
                .header("targetAppInstanceId", &target_id)
                .header("secure", "1")
                .header("X-Sync-Mode", "push")
                .header("content-type", "application/json")
                .body(encrypted_paste)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => response,
                Ok(response) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, status = %response.status(), "file push prepare rejected");
                    continue;
                }
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "file push prepare failed");
                    continue;
                }
            };
            let encrypted_prepare = match prepare_response.bytes().await {
                Ok(bytes) => bytes,
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "failed to read file push prepare response");
                    continue;
                }
            };
            let prepare: PushPrepareResponse = match self
                .decrypt_from_client(&target_id, &encrypted_prepare)
                .and_then(|bytes| Ok(serde_json::from_slice(&bytes)?))
            {
                Ok(prepare) => prepare,
                Err(error) => {
                    report.failed += 1;
                    warn!(target_id = %target_id, %error, "invalid file push prepare response");
                    continue;
                }
            };
            if let Err(error) = self
                .upload_completed_push_to_target(
                    &client,
                    &base_url,
                    &target_id,
                    server_app_instance_id,
                    &completed,
                    &prepare,
                )
                .await
            {
                report.failed += 1;
                warn!(target_id = %target_id, %error, "file push delivery failed");
                continue;
            }
            report.delivered += 1;
        }
        self.stored_files.insert(
            completed.paste_id,
            StoredFile {
                directory: completed.directory,
                chunk_count: completed.chunk_count,
            },
        );
        report
    }

    pub async fn cache_pull_file_from_client(
        &self,
        app_instance_id: &str,
        server_app_instance_id: &str,
        paste: &serde_json::Value,
    ) -> anyhow::Result<i64> {
        let source_paste_id = paste
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("file paste is missing id"))?;
        let size = paste
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("file paste is missing size"))?;
        let sync_info = self
            .client_sync_infos
            .get(app_instance_id)
            .ok_or_else(|| anyhow::anyhow!("source client has no SyncInfo"))?
            .clone();
        let base_url = client_base_url(&sync_info)
            .ok_or_else(|| anyhow::anyhow!("source client has no reachable host"))?;
        let paste_id = now_ms();
        let directory = self.transfer_dir.join(format!("pull-{paste_id}"));
        std::fs::create_dir_all(&directory)?;
        let chunk_count = size.div_ceil(FILE_CHUNK_SIZE) as usize;
        let client = reqwest::Client::new();
        for chunk_index in 0..chunk_count {
            let request = serde_json::to_vec(&serde_json::json!({
                "id": source_paste_id,
                "chunkIndex": chunk_index
            }))?;
            let encrypted = self.encrypt_for_client(app_instance_id, &request)?;
            let response = client
                .post(format!("{base_url}/pull/file"))
                .header("appInstanceId", server_app_instance_id)
                .header("targetAppInstanceId", app_instance_id)
                .header("secure", "1")
                .header("content-type", "application/json")
                .body(encrypted)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "source rejected file chunk {chunk_index}"
            );
            let encrypted = response.bytes().await?;
            let bytes = self.decrypt_stream_from_client(app_instance_id, &encrypted)?;
            std::fs::write(directory.join(format!("{chunk_index}.chunk")), bytes)?;
        }
        self.stored_files.insert(
            paste_id,
            StoredFile {
                directory,
                chunk_count,
            },
        );
        Ok(paste_id)
    }

    pub fn read_file_chunk(&self, paste_id: i64, chunk_index: usize) -> anyhow::Result<Vec<u8>> {
        if let Some(bytes) = self.database.load_file_chunk(paste_id, chunk_index)? {
            return Ok(bytes);
        }
        let stored = self
            .stored_files
            .get(&paste_id)
            .ok_or_else(|| anyhow::anyhow!("stored file not found"))?;
        anyhow::ensure!(chunk_index < stored.chunk_count, "chunk index out of range");
        Ok(std::fs::read(
            stored.directory.join(format!("{chunk_index}.chunk")),
        )?)
    }

    pub fn encrypt_stream_for_client(
        &self,
        app_instance_id: &str,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut output = Vec::new();
        for chunk in plaintext.chunks(ENCRYPT_STREAM_CHUNK_SIZE) {
            let encrypted = self.encrypt_for_client(app_instance_id, chunk)?;
            output.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
            output.extend_from_slice(&encrypted);
        }
        Ok(output)
    }

    pub fn store_icon(&self, source: &str, bytes: &[u8]) -> anyhow::Result<()> {
        std::fs::write(self.icon_path(source)?, bytes)?;
        Ok(())
    }

    pub fn read_icon(&self, source: &str) -> anyhow::Result<Vec<u8>> {
        Ok(std::fs::read(self.icon_path(source)?)?)
    }

    pub async fn cache_icon_from_client(
        &self,
        app_instance_id: &str,
        server_app_instance_id: &str,
        source: &str,
    ) -> anyhow::Result<()> {
        if self.icon_path(source)?.exists() {
            return Ok(());
        }
        let sync_info = self
            .client_sync_infos
            .get(app_instance_id)
            .ok_or_else(|| anyhow::anyhow!("source client has no SyncInfo"))?
            .clone();
        let base_url = client_base_url(&sync_info)
            .ok_or_else(|| anyhow::anyhow!("source client has no reachable host"))?;
        let encoded_source = percent_encode_path_segment(source);
        let response = reqwest::Client::new()
            .get(format!("{base_url}/pull/icon/{encoded_source}"))
            .header("appInstanceId", server_app_instance_id)
            .send()
            .await?;
        anyhow::ensure!(response.status().is_success(), "source icon request failed");
        self.store_icon(source, &response.bytes().await?)
    }

    fn icon_path(&self, source: &str) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            !source.is_empty() && source.len() <= 1024,
            "invalid icon source"
        );
        let digest = sha2::Sha256::digest(source.as_bytes());
        let file_name: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(self.icon_dir.join(file_name))
    }

    fn decrypt_stream_from_client(
        &self,
        app_instance_id: &str,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut offset = 0;
        let mut output = Vec::new();
        while offset < ciphertext.len() {
            anyhow::ensure!(
                offset + 4 <= ciphertext.len(),
                "truncated encrypted stream length"
            );
            let size = u32::from_be_bytes(ciphertext[offset..offset + 4].try_into()?) as usize;
            offset += 4;
            anyhow::ensure!(
                offset + size <= ciphertext.len(),
                "truncated encrypted stream chunk"
            );
            output.extend(
                self.decrypt_from_client(app_instance_id, &ciphertext[offset..offset + size])?,
            );
            offset += size;
        }
        Ok(output)
    }

    async fn upload_completed_push_to_target(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        target_id: &str,
        server_app_instance_id: &str,
        completed: &CompletedPush,
        prepare: &PushPrepareResponse,
    ) -> anyhow::Result<()> {
        let source = read_completed_push(completed)?;
        let target_chunk_size: usize = prepare.chunk_size.try_into()?;
        anyhow::ensure!(target_chunk_size > 0, "target chunk size is zero");
        let target_chunk_count = source.len().div_ceil(target_chunk_size);
        anyhow::ensure!(
            target_chunk_count == prepare.chunk_count,
            "target chunk count mismatch: expected {}, got {}",
            prepare.chunk_count,
            target_chunk_count
        );
        for (chunk_index, chunk) in source.chunks(target_chunk_size).enumerate() {
            let encrypted = self.encrypt_for_client(target_id, chunk)?;
            let response = client
                .post(format!("{base_url}/sync/file/push"))
                .header("appInstanceId", server_app_instance_id)
                .header("targetAppInstanceId", target_id)
                .header("secure", "1")
                .header("X-Paste-Id", prepare.paste_id.to_string())
                .header("X-Chunk-Index", chunk_index.to_string())
                .header("X-Session-Token", &prepare.session_token)
                .header("content-type", "application/json")
                .body(encrypted)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "target rejected chunk {chunk_index}"
            );
        }
        let encrypted_empty = self.encrypt_for_client(target_id, &[])?;
        let response = client
            .post(format!("{base_url}/sync/paste/push/complete"))
            .header("appInstanceId", server_app_instance_id)
            .header("targetAppInstanceId", target_id)
            .header("secure", "1")
            .header("X-Paste-Id", prepare.paste_id.to_string())
            .header("X-Session-Token", &prepare.session_token)
            .header("content-type", "application/json")
            .body(encrypted_empty)
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "target rejected file push completion"
        );
        Ok(())
    }

    pub fn decrypt_from_client(
        &self,
        app_instance_id: &str,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let client_key = self
            .client_crypt_keys
            .get(app_instance_id)
            .ok_or_else(|| anyhow::anyhow!("missing client crypt key"))?;
        self.keys
            .decrypt_from_client(client_key.value(), ciphertext)
    }

    pub fn encrypt_for_client(
        &self,
        app_instance_id: &str,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let client_key = self
            .client_crypt_keys
            .get(app_instance_id)
            .ok_or_else(|| anyhow::anyhow!("missing client crypt key"))?;
        self.keys.encrypt_for_client(client_key.value(), plaintext)
    }

    pub fn remove_client(&self, app_instance_id: &str) -> anyhow::Result<()> {
        self.clients.remove(app_instance_id);
        self.client_crypt_keys.remove(app_instance_id);
        self.client_sync_infos.remove(app_instance_id);
        self.database.remove_client(app_instance_id)
    }
}

#[derive(Debug, Default)]
pub struct BroadcastReport {
    pub attempted: usize,
    pub delivered: usize,
    pub failed: usize,
}

fn normalize_paste(
    paste: &serde_json::Value,
    server_app_instance_id: &str,
    paste_id: Option<i64>,
) -> serde_json::Value {
    let mut paste = paste.clone();
    if let Some(object) = paste.as_object_mut() {
        object.insert(
            "appInstanceId".to_string(),
            serde_json::Value::String(server_app_instance_id.to_string()),
        );
        if let Some(paste_id) = paste_id {
            object.insert("id".to_string(), serde_json::Value::Number(paste_id.into()));
        }
    }
    paste
}

fn client_base_url(sync_info: &SyncInfo) -> Option<String> {
    let host = &sync_info.endpoint_info.host_info_list.first()?.host_address;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    Some(format!("http://{host}:{}", sync_info.endpoint_info.port))
}

fn read_completed_push(completed: &CompletedPush) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for chunk_index in 0..completed.chunk_count {
        bytes.extend(std::fs::read(
            completed.directory.join(format!("{chunk_index}.chunk")),
        )?);
    }
    Ok(bytes)
}

fn percent_encode_path_segment(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
                (*byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "crosspaste-server-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn persisted_keys_and_clients_survive_restart() {
        let directory = temporary_dir("persistence");
        let database = Database::open(&directory).unwrap();
        let hub = Hub::load_or_create(&directory, database.clone()).unwrap();
        let original_public_key = hub.keys.crypt_public_key_der_b64().unwrap();
        database.save_client("client-a", 123, &[1, 2, 3]).unwrap();
        drop(hub);

        let restored = Hub::load_or_create(&directory, database).unwrap();
        assert_eq!(
            restored.keys.crypt_public_key_der_b64().unwrap(),
            original_public_key
        );
        assert!(restored.is_paired("client-a"));
        assert_eq!(
            restored.client_crypt_keys.get("client-a").unwrap().value(),
            &[1, 2, 3]
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn file_push_session_tracks_and_stores_chunks() {
        let directory = temporary_dir("file-push");
        let database = Database::open(&directory).unwrap();
        let hub = Hub::load_or_create(&directory, database).unwrap();
        hub.clients.insert(
            "source".to_string(),
            PairedClient {
                app_instance_id: "source".to_string(),
                paired_at_ms: 123,
            },
        );
        let size = FILE_CHUNK_SIZE + 3;
        let paste = serde_json::json!({
            "id": 42,
            "appInstanceId": "source",
            "pasteType": 3,
            "size": size,
            "hash": "test"
        });
        let prepared = hub.prepare_push("source", paste).unwrap();
        assert_eq!(prepared.chunk_count, 2);
        hub.store_push_chunk(
            "source",
            prepared.paste_id,
            0,
            &prepared.session_token,
            &vec![7; FILE_CHUNK_SIZE as usize],
        )
        .unwrap();
        let (incomplete, completed) = hub
            .complete_push("source", prepared.paste_id, &prepared.session_token)
            .unwrap();
        assert_eq!(incomplete.missing_chunks, vec![1]);
        assert!(completed.is_none());

        hub.store_push_chunk(
            "source",
            prepared.paste_id,
            1,
            &prepared.session_token,
            &[8, 9, 10],
        )
        .unwrap();
        let (complete, completed) = hub
            .complete_push("source", prepared.paste_id, &prepared.session_token)
            .unwrap();
        assert!(complete.missing_chunks.is_empty());
        let report = hub
            .broadcast_completed_push(completed.unwrap(), "crosspaste-server")
            .await;
        assert_eq!(report.attempted, 0);
        assert_eq!(
            hub.read_file_chunk(prepared.paste_id, 1).unwrap(),
            vec![8, 9, 10]
        );
        let _ = std::fs::remove_dir_all(directory);
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
