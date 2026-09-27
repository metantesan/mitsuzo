use bitcode::{decode, encode};
use eyre::Context;
use mitsuzo_types::{
    AccountRecord, LegacyPasteMeta, PasteInboxListing, PasteListing, PasteMeta, RecipientEnvelope,
};
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::MigratorTrait;
use sled::Db;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::info;

/// Bump whenever the persisted `PasteMeta`/account encodings change shape.
/// bitcode is not self-describing, so existing rows must be migrated.
const SCHEMA_VERSION: u32 = 2;

/// One-time migration of sled `meta:` rows to the current `PasteMeta` shape.
/// Reads each row with the frozen `LegacyPasteMeta` and re-encodes it as the
/// new struct with `recipient_pub`/`recipient_kid = None`. Idempotent on a
/// fresh database (no rows). Runs once, then records `schema:version`.
fn migrate_schema(db: &Db) {
    let stored_version = db
        .get("schema:version")
        .ok()
        .flatten()
        .and_then(|v| v.as_ref().try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);

    if stored_version == SCHEMA_VERSION {
        return;
    }

    let mut migrated = 0usize;
    for item in db.scan_prefix(b"meta:") {
        let Ok((key, value)) = item else { continue };
        let Ok(legacy) = decode::<LegacyPasteMeta>(&value) else {
            continue;
        };
        let meta = PasteMeta {
            try_count: legacy.try_count,
            expiration_timestamp: legacy.expiration_timestamp,
            data_type: legacy.data_type,
            filename: legacy.filename,
            content_type: legacy.content_type,
            total_chunks: legacy.total_chunks,
            allow_download: legacy.allow_download,
            burn_after_read: legacy.burn_after_read,
            recipient_pub: None,
            recipient_kid: None,
        };
        let _ = db.insert(key, encode(&meta));
        migrated += 1;
    }

    let _ = db.insert("schema:version", &SCHEMA_VERSION.to_le_bytes()[..]);
    let _ = db.flush();
    if migrated > 0 {
        eprintln!(
            "[mitsuzo] migrated {} paste metadata rows to schema v{}",
            migrated, SCHEMA_VERSION
        );
    }
}

#[derive(Clone)]
pub struct DataStore {
    db: Db,
    stats: Db,
    files_dir: PathBuf,
    deletion_lock: Arc<Mutex<()>>,
}

impl DataStore {
    pub fn new() -> eyre::Result<Self> {
        let database_dir = Path::new("database");
        std::fs::create_dir_all(database_dir).wrap_err("Failed to create database directory")?;
        let sqlite_path = database_dir.join("mitsuzo.sqlite");
        let sqlite_url = format!("sqlite://{}?mode=rwc", sqlite_path.display());
        let migration_runtime =
            tokio::runtime::Runtime::new().wrap_err("Failed to create SQLite migration runtime")?;
        migration_runtime.block_on(async {
            let mut options = ConnectOptions::new(sqlite_url);
            options.sqlx_logging(false);
            let connection = Database::connect(options)
                .await
                .wrap_err("Failed to connect to SQLite")?;
            mitsuzo_migration::Migrator::up(&connection, None)
                .await
                .wrap_err("Failed to apply SeaORM migrations")?;
            Ok::<_, eyre::Report>(())
        })?;
        info!(path = %sqlite_path.display(), "SeaORM SQLite migrations applied");

        let db =
            sled::open(Path::new("database/db")).wrap_err("Failed to open Sled database/db")?;
        migrate_schema(&db);
        let stats = sled::open(Path::new("database/stats"))
            .wrap_err("Failed to open Sled database/stats")?;
        let files_dir = PathBuf::from("database/files");
        std::fs::create_dir_all(&files_dir)
            .wrap_err("Failed to create database/files directory")?;
        Ok(Self {
            db,
            stats,
            files_dir,
            deletion_lock: Arc::new(Mutex::new(())),
        })
    }
}

fn day_key(prefix: &str) -> String {
    let secs = epoch_secs();
    format!("{}:{}", prefix, secs / 86400)
}

fn increment_counter(db: &Db, key: &str) {
    let _ = db.update_and_fetch(key.as_bytes(), |v| {
        let count = v.map_or(0u64, |bytes| {
            let arr: [u8; 8] = bytes.as_ref().try_into().unwrap_or([0u8; 8]);
            u64::from_be_bytes(arr)
        });
        Some((count + 1).to_be_bytes().to_vec())
    });
    let _ = db.flush();
}

fn read_counter(db: &Db, key: &str) -> u64 {
    db.get(key.as_bytes())
        .ok()
        .flatten()
        .map(|v| {
            let arr: [u8; 8] = v.as_ref().try_into().unwrap_or([0u8; 8]);
            u64::from_be_bytes(arr)
        })
        .unwrap_or(0)
}

fn content_path(files_dir: &Path, id: &str) -> PathBuf {
    files_dir.join(id)
}

fn nonce_path(files_dir: &Path, id: &str) -> PathBuf {
    files_dir.join(format!("{}.nonce", id))
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl DataStore {
    pub fn init_paste(
        &self,
        id: &str,
        header: &mitsuzo_types::CreatePasteHeader,
    ) -> eyre::Result<()> {
        // The PRNG hands out IDs that are otherwise available, which includes
        // pastes that expired but have not been cleaned up yet. Reusing such
        // an ID would otherwise leave the old chunk markers, burn row, and
        // content file behind, corrupting the new paste.
        if self.db.get(format!("meta:{}", id)).ok().flatten().is_some() {
            self.delete_paste_inner(id);
        }

        let nonce_path = nonce_path(&self.files_dir, id);
        std::fs::write(&nonce_path, header.nonce)
            .wrap_err_with(|| format!("Failed to write nonce for paste {}", id))?;

        let recipient_mode = header.recipient.is_some();
        if !recipient_mode {
            let _ = self.db.insert(
                format!("pass:{}", id),
                header.password_hash.unwrap_or_default().as_slice(),
            );
            let _ = self.db.insert(
                format!("salt:{}", id),
                header.salt.unwrap_or_default().as_slice(),
            );
            if let Some(key) = &header.key {
                let mut key_blob = Vec::with_capacity(60);
                key_blob.extend_from_slice(&key.wrap_nonce);
                key_blob.extend_from_slice(&key.wrapped_key);
                let _ = self.db.insert(format!("key:{}", id), key_blob.as_slice());
            }
        }

        if let Some(recipient) = &header.recipient {
            let _ = self
                .db
                .insert(format!("recp:{}", id), encode(recipient).as_slice());
        }

        if let Some(kid) = header.recipient.as_ref().map(|r| r.recipient_kid) {
            self.record_recipient_paste(
                &kid,
                &PasteInboxListing {
                    id: id.to_string(),
                    data_type: header.data_type.clone(),
                    filename: header.filename.clone(),
                    created_at: epoch_secs(),
                },
            );
        }

        let expiration_timestamp = match header.ttl_seconds {
            Some(ttl) if ttl > 0 => epoch_secs() + u64::from(ttl),
            _ => 0,
        };

        let meta_value = encode(&PasteMeta {
            try_count: header.try_count.unwrap_or(0),
            expiration_timestamp,
            data_type: header.data_type.clone(),
            filename: header.filename.clone(),
            content_type: header.content_type.clone(),
            total_chunks: header.total_chunks,
            allow_download: header.allow_download,
            burn_after_read: header.burn_after_read,
            recipient_pub: header.recipient_pub,
            recipient_kid: header.recipient.as_ref().map(|r| r.recipient_kid),
        });
        let _ = self.db.insert(format!("meta:{}", id), meta_value);
        let _ = self
            .db
            .insert(format!("crecv:{}", id), &0u32.to_le_bytes()[..]);
        let _ = self
            .db
            .insert(format!("burn:{}", id), header.burn_receipt_hash.as_slice());
        let _ = self.db.flush();

        increment_counter(&self.stats, "pastes_all_time");
        increment_counter(&self.stats, &day_key("pastes_day"));
        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub fn append_chunk(&self, id: &str, chunk_index: u32, data: &[u8]) -> Result<(), ()> {
        let chunk_key = format!("chunk:{}:{}", id, chunk_index);
        if self.db.get(&chunk_key).ok().flatten().is_some() {
            return Ok(());
        }

        // Use a unique temp file per append to avoid concurrent write interference
        let path = content_path(&self.files_dir, id);
        let temp_path = content_path(&self.files_dir, &format!("{}.{}", id, chunk_index));
        let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)
        else {
            return Err(());
        };
        let _ = file.write_all(data);
        let _ = file.flush();
        drop(file);

        // Atomically write to final file at correct offset
        let Ok(mut final_file) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
        else {
            return Err(());
        };
        let offset = chunk_index as u64 * mitsuzo_types::UPLOAD_CHUNK_SIZE as u64;
        let _ = final_file.seek(SeekFrom::Start(offset));
        let _ = final_file.write_all(data);
        let _ = final_file.flush();
        let _ = std::fs::remove_file(&temp_path);

        let _ = self.db.insert(chunk_key, b"1");
        let _ = self
            .db
            .update_and_fetch(format!("crecv:{}", id).as_bytes(), |v| {
                let current = v
                    .and_then(|b| b.as_ref().try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0);
                Some((current + 1).to_le_bytes().to_vec())
            });
        Ok(())
    }

    pub fn get_received_chunks(&self, id: &str) -> u32 {
        self.db
            .get(format!("crecv:{}", id))
            .ok()
            .flatten()
            .and_then(|v| v.as_ref().try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0)
    }

    fn delete_chunk_keys(&self, id: &str) {
        let prefix = format!("chunk:{}:", id);
        let keys: Vec<sled::IVec> = self
            .db
            .scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok().map(|(k, _)| k))
            .collect();
        for key in keys {
            let _ = self.db.remove(key);
        }
    }

    pub fn get_password_hash(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id) {
            return None;
        }
        self.db
            .get(format!("pass:{}", id))
            .ok()?
            .map(|v| v.to_vec())
    }

    pub fn get_salt(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id) {
            return None;
        }
        self.db
            .get(format!("salt:{}", id))
            .ok()?
            .map(|v| v.to_vec())
    }

    /// Fetch the password-wrapped content key. `None` for legacy pastes
    /// created before envelope encryption was introduced.
    pub fn get_key(&self, id: &str) -> Option<mitsuzo_types::KeyEnvelope> {
        if self.is_expired(id) {
            return None;
        }
        let blob = self
            .db
            .get(format!("key:{}", id))
            .ok()?
            .map(|v| v.to_vec())?;
        if blob.len() != 60 {
            return None;
        }
        let mut wrap_nonce = [0u8; 12];
        let mut wrapped_key = [0u8; 48];
        wrap_nonce.copy_from_slice(&blob[..12]);
        wrapped_key.copy_from_slice(&blob[12..]);
        Some(mitsuzo_types::KeyEnvelope {
            wrap_nonce,
            wrapped_key,
        })
    }

    /// Atomically replace password credentials after a password change:
    /// new salt, new password hash, and the re-wrapped content key.
    pub fn set_password(
        &self,
        id: &str,
        salt: &[u8; 16],
        password_hash: &[u8; 32],
        key: &mitsuzo_types::KeyEnvelope,
    ) {
        let mut key_blob = Vec::with_capacity(60);
        key_blob.extend_from_slice(&key.wrap_nonce);
        key_blob.extend_from_slice(&key.wrapped_key);
        let _ = self.db.insert(format!("salt:{}", id), salt.as_slice());
        let _ = self
            .db
            .insert(format!("pass:{}", id), password_hash.as_slice());
        let _ = self.db.insert(format!("key:{}", id), key_blob.as_slice());
        let _ = self.db.flush();
    }

    pub fn get_meta(&self, id: &str) -> Option<PasteMeta> {
        match self.db.get(format!("meta:{}", id)) {
            Ok(Some(value)) => decode(&value).ok(),
            Ok(None) => None,
            Err(_) => None,
        }
    }

    pub fn decrement_try_count(&self, id: &str) {
        let key = format!("meta:{}", id);
        let result = self
            .db
            .update_and_fetch(key.as_bytes(), |value| {
                let value = value.as_ref()?;
                let Ok(mut meta) = decode::<PasteMeta>(value) else {
                    return None;
                };
                if meta.try_count == 0 {
                    return None;
                }
                meta.try_count -= 1;
                Some(encode(&meta))
            })
            .ok()
            .flatten();
        if let Some(meta) = result
            && let Ok(decoded) = decode::<PasteMeta>(&meta)
            && decoded.try_count == 0
        {
            self.delete_paste(id);
        }
        let _ = self.db.flush();
    }

    pub fn delete_paste(&self, id: &str) {
        let _lock = self.deletion_lock.lock();
        self.delete_paste_inner(id);
    }

    fn delete_paste_inner(&self, id: &str) {
        if let Some(meta) = self.get_meta(id)
            && let Some(kid) = meta.recipient_kid
        {
            self.unrecord_recipient_paste(&kid, id);
        }
        let _ = self.db.remove(format!("pass:{}", id));
        let _ = self.db.remove(format!("salt:{}", id));
        let _ = self.db.remove(format!("key:{}", id));
        let _ = self.db.remove(format!("meta:{}", id));
        let _ = self.db.remove(format!("crecv:{}", id));
        let _ = self.db.remove(format!("burn:{}", id));
        let _ = self.db.remove(format!("recp:{}", id));
        self.delete_chunk_keys(id);
        let _ = std::fs::remove_file(content_path(&self.files_dir, id));
        let _ = std::fs::remove_file(nonce_path(&self.files_dir, id));
        let _ = self.db.flush();
    }

    pub fn get_burn_receipt_hash(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id) {
            return None;
        }
        self.db
            .get(format!("burn:{}", id))
            .ok()?
            .map(|v| v.to_vec())
    }

    pub fn mark_burned(&self, id: &str) -> bool {
        let burned_key = format!("burned:{}", id);
        if self.db.get(&burned_key).ok().flatten().is_some() {
            return false;
        }
        let _ = self.db.insert(&burned_key, b"1");
        let _ = self.db.flush();
        true
    }

    pub fn cleanup_expired(&self) -> usize {
        let current_time = epoch_secs();
        let mut to_delete = Vec::new();

        for item in self.db.scan_prefix(b"meta:") {
            let Ok((key, value)) = item else { continue };
            let Ok(meta) = decode::<PasteMeta>(&value) else {
                continue;
            };
            if meta.expiration_timestamp > 0
                && current_time > meta.expiration_timestamp
                && let Ok(id_str) = std::str::from_utf8(&key[5..])
            {
                to_delete.push(id_str.to_string());
            }
        }

        let _lock = self.deletion_lock.lock();
        for id in &to_delete {
            self.delete_paste_inner(id);
        }
        to_delete.len()
    }

    pub fn list_all(&self) -> Vec<PasteListing> {
        let mut results = Vec::new();
        for item in self.db.scan_prefix(b"meta:") {
            let Ok((key, value)) = item else { continue };
            let Ok(id_str) = std::str::from_utf8(&key[5..]) else {
                continue;
            };
            let Ok(meta) = decode::<PasteMeta>(&value) else {
                continue;
            };
            let size = std::fs::metadata(content_path(&self.files_dir, id_str))
                .map(|m| m.len())
                .unwrap_or(0);
            results.push(PasteListing {
                id: id_str.to_string(),
                size,
                data_type: meta.data_type,
                filename: meta.filename,
            });
        }
        results
    }

    fn is_expired(&self, id: &str) -> bool {
        if let Some(meta) = self.get_meta(id) {
            let current_time = epoch_secs();
            if meta.expiration_timestamp > 0 && current_time > meta.expiration_timestamp {
                return true;
            }
        }
        false
    }

    pub fn get_content_path(&self, id: &str) -> Option<PathBuf> {
        if self.is_expired(id) {
            return None;
        }
        let path = content_path(&self.files_dir, id);
        if path.exists() { Some(path) } else { None }
    }

    pub fn get_content_size(&self, id: &str) -> Option<u64> {
        let path = content_path(&self.files_dir, id);
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    pub fn id_available(&self, id: &str) -> bool {
        match self.db.get(format!("meta:{}", id)) {
            Ok(Some(value)) => {
                let Ok(meta) = decode::<PasteMeta>(&value) else {
                    return true;
                };
                meta.expiration_timestamp > 0 && epoch_secs() > meta.expiration_timestamp
            }
            _ => true,
        }
    }

    /// Recipient envelope for a recipient-mode paste.
    pub fn get_recipient_envelope(&self, id: &str) -> Option<RecipientEnvelope> {
        if self.is_expired(id) {
            return None;
        }
        self.db
            .get(format!("recp:{}", id))
            .ok()?
            .and_then(|v| decode(&v).ok())
    }

    /// Index a recipient-mode paste under its recipient account for the inbox.
    pub fn record_recipient_paste(&self, kid: &[u8; 32], listing: &PasteInboxListing) {
        let _ = self.db.insert(
            format!("recpix:{}:{}", hex(kid), listing.id),
            encode(listing),
        );
    }

    pub fn unrecord_recipient_paste(&self, kid: &[u8; 32], id: &str) {
        let _ = self.db.remove(format!("recpix:{}:{}", hex(kid), id));
    }

    /// Non-expired recipient-mode pastes addressed to an account.
    pub fn list_recipient_pastes(&self, kid: &[u8; 32]) -> Vec<PasteInboxListing> {
        self.db
            .scan_prefix(format!("recpix:{}:", hex(kid)).as_bytes())
            .filter_map(|item| item.ok())
            .filter_map(|(_, value)| decode::<PasteInboxListing>(&value).ok())
            .filter(|l| {
                let expired = self
                    .get_meta(&l.id)
                    .map(|m| m.expiration_timestamp != 0 && m.expiration_timestamp <= epoch_secs())
                    .unwrap_or(true);
                if expired {
                    let _ = self.db.remove(format!("recpix:{}:{}", hex(kid), l.id));
                    false
                } else {
                    true
                }
            })
            .collect()
    }

    pub fn get_nonce(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id) {
            return None;
        }
        std::fs::read(nonce_path(&self.files_dir, id)).ok()
    }

    pub fn increment_success(&self) {
        increment_counter(&self.stats, "success_all_time");
        increment_counter(&self.stats, &day_key("success_day"));
    }

    pub fn increment_fail(&self) {
        increment_counter(&self.stats, "fail_all_time");
        increment_counter(&self.stats, &day_key("fail_day"));
    }

    pub fn get_pastes_all_time(&self) -> u64 {
        read_counter(&self.stats, "pastes_all_time")
    }

    pub fn get_pastes_daily(&self) -> u64 {
        read_counter(&self.stats, &day_key("pastes_day"))
    }

    pub fn get_success_all_time(&self) -> u64 {
        read_counter(&self.stats, "success_all_time")
    }

    pub fn get_success_daily(&self) -> u64 {
        read_counter(&self.stats, &day_key("success_day"))
    }

    pub fn get_fail_all_time(&self) -> u64 {
        read_counter(&self.stats, "fail_all_time")
    }

    pub fn get_fail_daily(&self) -> u64 {
        read_counter(&self.stats, &day_key("fail_day"))
    }

    /// Insert or update an account record, keyed by full 32-byte kid.
    pub fn put_account(&self, record: &AccountRecord) {
        let _ = self.db.insert(
            format!("acct:{}", hex(&record.kid)),
            encode(record).as_slice(),
        );
        let _ = self.db.flush();
    }

    /// Delete an account record by full 32-byte kid.
    pub fn delete_account(&self, kid: &[u8; 32]) {
        let _ = self.db.remove(format!("acct:{}", hex(kid)));
        let _ = self.db.flush();
    }

    /// Look up an account by full 32-byte kid.
    pub fn get_account_by_kid(&self, kid: &[u8; 32]) -> Option<AccountRecord> {
        self.db
            .get(format!("acct:{}", hex(kid)))
            .ok()?
            .and_then(|v| decode(&v).ok())
    }

    /// Look up an account by its 20-byte display prefix (first 20 bytes of
    /// the full SHA-256). With 160 bits of prefix, collisions are negligible;
    /// a scan is fine because account counts are small.
    pub fn get_account_by_prefix(&self, prefix: &[u8; 20]) -> Option<AccountRecord> {
        let wanted = hex(prefix);
        self.db
            .scan_prefix(b"acct:")
            .filter_map(|item| item.ok())
            .find_map(|(key, value)| {
                let full = key.get(5..)?;
                if full.len() == 64 && full.get(..40)? == wanted.as_bytes() {
                    decode(&value).ok()
                } else {
                    None
                }
            })
    }

    pub fn flush(&self) -> eyre::Result<()> {
        self.db.flush().wrap_err("Failed to flush Sled db")?;
        self.stats.flush().wrap_err("Failed to flush Sled stats")?;
        Ok(())
    }
}

#[cfg(test)]
fn test_store(dir: &Path) -> eyre::Result<DataStore> {
    let db = sled::open(dir.join("db")).wrap_err("Failed to open test db")?;
    migrate_schema(&db);
    let stats = sled::open(dir.join("stats")).wrap_err("Failed to open test stats")?;
    let files_dir = dir.join("files");
    std::fs::create_dir_all(&files_dir).wrap_err("Failed to create test files dir")?;
    Ok(DataStore {
        db,
        stats,
        files_dir,
        deletion_lock: Arc::new(Mutex::new(())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mitsuzo_types::AccountRecord;

    #[test]
    fn account_lookup_by_full_kid_and_prefix() {
        let dir = std::env::temp_dir().join(format!("mitsuzo-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = test_store(&dir).expect("open store");

        for i in 0u8..3 {
            let mut kid = [0u8; 32];
            kid[0] = i;
            store.put_account(&AccountRecord {
                kid,
                pubkey: [0x42; 32],
                name: format!("user{}", i),
                created_at: 0,
            });
        }

        let mut kid = [0u8; 32];
        kid[0] = 2;
        let by_full = store.get_account_by_kid(&kid).expect("full-kid lookup");
        assert_eq!(by_full.name, "user2");

        let mut prefix = [0u8; 20];
        prefix[0] = 1;
        let by_prefix = store.get_account_by_prefix(&prefix).expect("prefix lookup");
        assert_eq!(by_prefix.kid[0], 1);
        assert_eq!(by_prefix.name, "user1");

        let mut missing = [0u8; 20];
        missing[0] = 9;
        assert!(store.get_account_by_prefix(&missing).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
