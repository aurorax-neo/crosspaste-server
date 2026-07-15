use crate::secure::ServerKeys;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const DEFAULT_ADMIN_PASSWORD: &str = "CrossPaste@123";

#[derive(Clone)]
pub struct Database {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct StoredClient {
    pub app_instance_id: String,
    pub paired_at_ms: i64,
    pub crypt_public_key: Vec<u8>,
    pub sync_info_json: Option<String>,
    pub last_seen_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    pub username: String,
    pub must_change_password: bool,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AdminUserSecret {
    pub user: AdminUser,
    pub password_hash: String,
    pub mfa_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    pub id: i64,
    pub username: Option<String>,
    pub action: String,
    pub detail: String,
    pub remote_addr: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLog {
    pub id: i64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub remote_addr: String,
    pub client_id: Option<String>,
    pub target_id: Option<String>,
    pub secure: bool,
    pub elapsed_ms: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyHub {
    sign_private_key: String,
    crypt_private_key: String,
    clients: Vec<LegacyClient>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyClient {
    app_instance_id: String,
    paired_at_ms: i64,
    crypt_public_key: String,
}

impl Database {
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("crosspaste.db");
        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(path),
        };
        database.migrate()?;
        database.ensure_default_admin()?;
        database.ensure_default_settings()?;
        database.import_legacy_state(data_dir)?;
        Ok(database)
    }

    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute_batch(
            "
            CREATE TABLE IF NOT EXISTS server_keys (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                sign_private_key BLOB NOT NULL,
                crypt_private_key BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS paired_clients (
                app_instance_id TEXT PRIMARY KEY,
                paired_at_ms INTEGER NOT NULL,
                crypt_public_key BLOB NOT NULL,
                sync_info_json TEXT,
                last_seen_ms INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                mfa_secret TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES admin_users(username) ON DELETE CASCADE,
                expires_at_ms INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                remote_addr TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                remote_addr TEXT,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                remote_addr TEXT NOT NULL,
                client_id TEXT,
                target_id TEXT,
                secure INTEGER NOT NULL,
                elapsed_ms INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS paste_records (
                id INTEGER PRIMARY KEY,
                source_app_instance_id TEXT NOT NULL,
                paste_type INTEGER,
                size INTEGER,
                metadata_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_chunks (
                paste_id INTEGER NOT NULL,
                chunk_index INTEGER NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (paste_id, chunk_index)
            );
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_request_logs_created ON request_logs(created_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at_ms);
            ",
        )?;
        Ok(())
    }

    fn ensure_default_admin(&self) -> anyhow::Result<()> {
        let exists: bool = self.connection.lock().unwrap().query_row(
            "SELECT EXISTS(SELECT 1 FROM admin_users)",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            let hash = hash_password(DEFAULT_ADMIN_PASSWORD)?;
            let now = now_ms();
            self.connection.lock().unwrap().execute(
                "INSERT INTO admin_users(username,password_hash,must_change_password,created_at_ms,updated_at_ms) VALUES(?1,?2,1,?3,?3)",
                params![DEFAULT_ADMIN_USERNAME, hash, now],
            )?;
        }
        Ok(())
    }

    fn ensure_default_settings(&self) -> anyhow::Result<()> {
        let defaults = [
            ("encrypt_sync", "true"),
            ("limit_file_size", "true"),
            ("max_file_size_mb", "512"),
            ("clipboard_relay", "true"),
            ("sync_text", "true"),
            ("sync_url", "true"),
            ("sync_html", "true"),
            ("sync_rtf", "true"),
            ("sync_image", "true"),
            ("sync_file", "true"),
            ("sync_color", "true"),
            ("log_retention_count", "10000"),
        ];
        let connection = self.connection.lock().unwrap();
        for (key, value) in defaults {
            connection.execute(
                "INSERT OR IGNORE INTO settings(key,value,updated_at_ms) VALUES(?1,?2,?3)",
                params![key, value, now_ms()],
            )?;
        }
        Ok(())
    }

    fn import_legacy_state(&self, data_dir: &Path) -> anyhow::Result<()> {
        if self.load_server_keys()?.is_some() {
            return Ok(());
        }
        let legacy_path = data_dir.join("hub-state.json");
        if !legacy_path.exists() {
            return Ok(());
        }
        let legacy: LegacyHub = serde_json::from_slice(&std::fs::read(&legacy_path)?)?;
        self.save_server_keys(
            &B64.decode(legacy.sign_private_key)?,
            &B64.decode(legacy.crypt_private_key)?,
        )?;
        for client in legacy.clients {
            self.save_client(
                &client.app_instance_id,
                client.paired_at_ms,
                &B64.decode(client.crypt_public_key)?,
            )?;
        }
        std::fs::rename(&legacy_path, data_dir.join("hub-state.json.migrated"))?;
        Ok(())
    }

    pub fn load_or_create_server_keys(&self) -> anyhow::Result<ServerKeys> {
        if let Some((sign, crypt)) = self.load_server_keys()? {
            return ServerKeys::from_pkcs8(&sign, &crypt);
        }
        let keys = ServerKeys::generate();
        let (sign, crypt) = keys.private_keys_pkcs8()?;
        self.save_server_keys(&sign, &crypt)?;
        Ok(keys)
    }

    fn load_server_keys(&self) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT sign_private_key, crypt_private_key FROM server_keys WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    fn save_server_keys(&self, sign: &[u8], crypt: &[u8]) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "INSERT INTO server_keys(id,sign_private_key,crypt_private_key,updated_at_ms) VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET sign_private_key=excluded.sign_private_key,crypt_private_key=excluded.crypt_private_key,updated_at_ms=excluded.updated_at_ms",
            params![sign, crypt, now_ms()],
        )?;
        Ok(())
    }

    pub fn load_clients(&self) -> anyhow::Result<Vec<StoredClient>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare("SELECT app_instance_id,paired_at_ms,crypt_public_key,sync_info_json,last_seen_ms FROM paired_clients WHERE enabled=1")?;
        let clients = statement
            .query_map([], |row| {
                Ok(StoredClient {
                    app_instance_id: row.get(0)?,
                    paired_at_ms: row.get(1)?,
                    crypt_public_key: row.get(2)?,
                    sync_info_json: row.get(3)?,
                    last_seen_ms: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(clients)
    }

    pub fn save_client(&self, id: &str, paired_at_ms: i64, key: &[u8]) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "INSERT INTO paired_clients(app_instance_id,paired_at_ms,crypt_public_key,enabled) VALUES(?1,?2,?3,1) ON CONFLICT(app_instance_id) DO UPDATE SET paired_at_ms=excluded.paired_at_ms,crypt_public_key=excluded.crypt_public_key,enabled=1",
            params![id, paired_at_ms, key],
        )?;
        Ok(())
    }

    pub fn update_client_sync_info(
        &self,
        id: &str,
        json: &str,
        last_seen_ms: i64,
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "UPDATE paired_clients SET sync_info_json=?2,last_seen_ms=?3 WHERE app_instance_id=?1",
            params![id, json, last_seen_ms],
        )?;
        Ok(())
    }

    pub fn touch_client(&self, id: &str, last_seen_ms: i64) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "UPDATE paired_clients SET last_seen_ms=?2 WHERE app_instance_id=?1",
            params![id, last_seen_ms],
        )?;
        Ok(())
    }

    pub fn online_client_ids(&self, active_since_ms: i64) -> anyhow::Result<Vec<String>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT app_instance_id FROM paired_clients WHERE enabled=1 AND last_seen_ms>=?1",
        )?;
        let client_ids = statement
            .query_map(params![active_since_ms], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(client_ids)
    }

    pub fn remove_client(&self, id: &str) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "DELETE FROM paired_clients WHERE app_instance_id=?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn save_paste(
        &self,
        id: i64,
        source: &str,
        paste_type: Option<i64>,
        size: Option<i64>,
        metadata: &str,
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "INSERT OR REPLACE INTO paste_records(id,source_app_instance_id,paste_type,size,metadata_json,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
            params![id,source,paste_type,size,metadata,now_ms()],
        )?;
        Ok(())
    }

    pub fn recent_pastes(
        &self,
        create_time: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let connection = self.connection.lock().unwrap();
        let sql = if create_time.is_some() {
            "SELECT metadata_json FROM paste_records WHERE created_at_ms > ?1 ORDER BY created_at_ms DESC LIMIT ?2"
        } else {
            "SELECT metadata_json FROM paste_records ORDER BY created_at_ms DESC LIMIT ?2"
        };
        let mut statement = connection.prepare(sql)?;
        let values = if let Some(create_time) = create_time {
            statement
                .query_map(params![create_time, limit as i64], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            statement
                .query_map(params![rusqlite::types::Null, limit as i64], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        values
            .into_iter()
            .map(|value| Ok(serde_json::from_str(&value)?))
            .collect()
    }

    pub fn save_file_chunk(
        &self,
        paste_id: i64,
        chunk_index: usize,
        data: &[u8],
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "INSERT OR REPLACE INTO file_chunks(paste_id,chunk_index,data) VALUES(?1,?2,?3)",
            params![paste_id, chunk_index as i64, data],
        )?;
        Ok(())
    }

    pub fn load_file_chunk(
        &self,
        paste_id: i64,
        chunk_index: usize,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT data FROM file_chunks WHERE paste_id=?1 AND chunk_index=?2",
                params![paste_id, chunk_index as i64],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn get_admin_user(&self, username: &str) -> anyhow::Result<Option<AdminUserSecret>> {
        Ok(self.connection.lock().unwrap().query_row(
            "SELECT username,password_hash,must_change_password,mfa_secret,mfa_enabled FROM admin_users WHERE username=?1",
            params![username],
            |row| Ok(AdminUserSecret { user: AdminUser { username: row.get(0)?, must_change_password: row.get::<_,i64>(2)? != 0, mfa_enabled: row.get::<_,i64>(4)? != 0 }, password_hash: row.get(1)?, mfa_secret: row.get(3)? }),
        ).optional()?)
    }

    pub fn update_password(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let hash = hash_password(password)?;
        self.connection.lock().unwrap().execute("UPDATE admin_users SET password_hash=?2,must_change_password=0,updated_at_ms=?3 WHERE username=?1", params![username,hash,now_ms()])?;
        self.delete_user_sessions(username)?;
        Ok(())
    }

    pub fn set_mfa(
        &self,
        username: &str,
        secret: Option<&str>,
        enabled: bool,
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute("UPDATE admin_users SET mfa_secret=?2,mfa_enabled=?3,updated_at_ms=?4 WHERE username=?1", params![username,secret,enabled as i64,now_ms()])?;
        Ok(())
    }

    pub fn create_session(
        &self,
        username: &str,
        token_hash: &str,
        expires_at_ms: i64,
        remote: Option<&str>,
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute("INSERT INTO admin_sessions(token_hash,username,expires_at_ms,created_at_ms,remote_addr) VALUES(?1,?2,?3,?4,?5)", params![token_hash,username,expires_at_ms,now_ms(),remote])?;
        Ok(())
    }

    pub fn session_user(&self, token_hash: &str) -> anyhow::Result<Option<AdminUser>> {
        self.connection.lock().unwrap().execute(
            "DELETE FROM admin_sessions WHERE expires_at_ms < ?1",
            params![now_ms()],
        )?;
        Ok(self.connection.lock().unwrap().query_row(
            "SELECT u.username,u.must_change_password,u.mfa_enabled FROM admin_sessions s JOIN admin_users u ON u.username=s.username WHERE s.token_hash=?1 AND s.expires_at_ms>=?2",
            params![token_hash,now_ms()],
            |row| Ok(AdminUser { username: row.get(0)?, must_change_password: row.get::<_,i64>(1)? != 0, mfa_enabled: row.get::<_,i64>(2)? != 0 }),
        ).optional()?)
    }

    pub fn delete_session(&self, token_hash: &str) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "DELETE FROM admin_sessions WHERE token_hash=?1",
            params![token_hash],
        )?;
        Ok(())
    }

    fn delete_user_sessions(&self, username: &str) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute(
            "DELETE FROM admin_sessions WHERE username=?1",
            params![username],
        )?;
        Ok(())
    }

    pub fn settings(&self) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare("SELECT key,value FROM settings")?;
        let settings = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(settings)
    }

    pub fn update_settings(
        &self,
        settings: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction()?;
        for (key, value) in settings {
            transaction.execute("INSERT INTO settings(key,value,updated_at_ms) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at_ms=excluded.updated_at_ms", params![key,value,now_ms()])?;
        }
        if settings.contains_key("log_retention_count") {
            let retention = transaction
                .query_row(
                    "SELECT value FROM settings WHERE key='log_retention_count'",
                    [],
                    |row| row.get::<_, String>(0),
                )?
                .parse::<usize>()
                .unwrap_or(10_000);
            prune_request_logs(&transaction, retention)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn audit(
        &self,
        username: Option<&str>,
        action: &str,
        detail: &str,
        remote: Option<&str>,
    ) -> anyhow::Result<()> {
        self.connection.lock().unwrap().execute("INSERT INTO audit_logs(username,action,detail,remote_addr,created_at_ms) VALUES(?1,?2,?3,?4,?5)", params![username,action,detail,remote,now_ms()])?;
        Ok(())
    }

    pub fn audit_logs(&self, limit: usize) -> anyhow::Result<Vec<AuditLog>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare("SELECT id,username,action,detail,remote_addr,created_at_ms FROM audit_logs ORDER BY id DESC LIMIT ?1")?;
        let logs = statement
            .query_map(params![limit as i64], |row| {
                Ok(AuditLog {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    action: row.get(2)?,
                    detail: row.get(3)?,
                    remote_addr: row.get(4)?,
                    created_at_ms: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(logs)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_log(
        &self,
        method: &str,
        path: &str,
        status: u16,
        remote: &str,
        client_id: Option<&str>,
        target_id: Option<&str>,
        secure: bool,
        elapsed_ms: i64,
    ) -> anyhow::Result<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO request_logs(method,path,status,remote_addr,client_id,target_id,secure,elapsed_ms,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![method,path,status,remote,client_id,target_id,secure as i64,elapsed_ms,now_ms()],
        )?;
        let retention = transaction
            .query_row(
                "SELECT value FROM settings WHERE key='log_retention_count'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10_000);
        prune_request_logs(&transaction, retention)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn request_logs(&self, limit: usize) -> anyhow::Result<Vec<RequestLog>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare("SELECT id,method,path,status,remote_addr,client_id,target_id,secure,elapsed_ms,created_at_ms FROM request_logs ORDER BY id DESC LIMIT ?1")?;
        let logs = statement
            .query_map(params![limit.min(1000) as i64], |row| {
                Ok(RequestLog {
                    id: row.get(0)?,
                    method: row.get(1)?,
                    path: row.get(2)?,
                    status: row.get::<_, u16>(3)?,
                    remote_addr: row.get(4)?,
                    client_id: row.get(5)?,
                    target_id: row.get(6)?,
                    secure: row.get::<_, i64>(7)? != 0,
                    elapsed_ms: row.get(8)?,
                    created_at_ms: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(logs)
    }
}

fn prune_request_logs(
    transaction: &rusqlite::Transaction<'_>,
    retention: usize,
) -> anyhow::Result<()> {
    transaction.execute(
        "DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY id DESC LIMIT ?1)",
        params![retention as i64],
    )?;
    Ok(())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temporary_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "crosspaste-database-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn creates_default_admin_with_forced_password_change() {
        let directory = temporary_dir("admin");
        let database = Database::open(&directory).unwrap();
        let user = database
            .get_admin_user(DEFAULT_ADMIN_USERNAME)
            .unwrap()
            .unwrap();
        assert!(user.user.must_change_password);
        assert!(verify_password(DEFAULT_ADMIN_PASSWORD, &user.password_hash));
        database
            .update_password(DEFAULT_ADMIN_USERNAME, "A-Strong-New-Pass9!")
            .unwrap();
        let updated = database
            .get_admin_user(DEFAULT_ADMIN_USERNAME)
            .unwrap()
            .unwrap();
        assert!(!updated.user.must_change_password);
        assert!(verify_password(
            "A-Strong-New-Pass9!",
            &updated.password_hash
        ));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn settings_survive_reopen() {
        let directory = temporary_dir("settings");
        let database = Database::open(&directory).unwrap();
        database
            .update_settings(&HashMap::from([(
                "max_file_size_mb".to_string(),
                "2048".to_string(),
            )]))
            .unwrap();
        drop(database);
        let reopened = Database::open(&directory).unwrap();
        assert_eq!(reopened.settings().unwrap()["max_file_size_mb"], "2048");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn request_logs_respect_configured_retention() {
        let directory = temporary_dir("request-log-retention");
        let database = Database::open(&directory).unwrap();
        database
            .update_settings(&HashMap::from([(
                "log_retention_count".to_string(),
                "1000".to_string(),
            )]))
            .unwrap();
        for index in 0..1005 {
            database
                .request_log(
                    "GET",
                    &format!("/test/{index}"),
                    200,
                    "127.0.0.1:1",
                    None,
                    None,
                    false,
                    1,
                )
                .unwrap();
        }
        let logs = database.request_logs(1000).unwrap();
        assert_eq!(logs.len(), 1000);
        assert_eq!(logs.first().unwrap().path, "/test/1004");
        assert_eq!(logs.last().unwrap().path, "/test/5");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn imports_legacy_hub_state_once() {
        let directory = temporary_dir("legacy");
        let keys = ServerKeys::generate();
        let (sign, crypt) = keys.private_keys_pkcs8().unwrap();
        std::fs::write(
            directory.join("hub-state.json"),
            serde_json::to_vec(&serde_json::json!({
                "signPrivateKey": B64.encode(sign),
                "cryptPrivateKey": B64.encode(crypt),
                "clients": [{
                    "appInstanceId": "legacy-client",
                    "pairedAtMs": 123,
                    "cryptPublicKey": B64.encode([1,2,3])
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let database = Database::open(&directory).unwrap();
        assert_eq!(
            database.load_clients().unwrap()[0].app_instance_id,
            "legacy-client"
        );
        assert!(directory.join("hub-state.json.migrated").exists());
        let _ = std::fs::remove_dir_all(directory);
    }
}
