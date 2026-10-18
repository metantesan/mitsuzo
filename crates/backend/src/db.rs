use bitcode::{decode, encode};
use eyre::Context;
use mitsuzo_types::{
    AccountRecord, DataType, KeyEnvelope, LegacyPasteMeta, PasteInboxListing, PasteMeta,
    RecipientEnvelope,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    ExprTrait, QueryFilter, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use sea_orm_migration::MigratorTrait;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::info;

use crate::entities::{account, chunk, credential, paste, recipient, recipient_inbox, stat, state};

#[derive(Clone)]
pub struct DataStore {
    db: DatabaseConnection,
    files_dir: PathBuf,
    /// Serializes destructive paste deletions so a paste's row, credential,
    /// recipient, chunk, inbox, and content-file state is torn down coherently.
    deletion_lock: Arc<Mutex<()>>,
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn day_key(prefix: &str) -> String {
    format!("{}:{}", prefix, epoch_secs() / 86400)
}

fn content_path(files_dir: &Path, id: &str) -> PathBuf {
    files_dir.join(id)
}

fn nonce_path(files_dir: &Path, id: &str) -> PathBuf {
    files_dir.join(format!("{}.nonce", id))
}

/// Write one upload chunk into the paste's content file at its byte offset.
/// Writes to a unique temp file first, then copies into the final file to
/// avoid concurrent-write interference. Blocking; call via `spawn_blocking`.
fn write_chunk_file(files_dir: &Path, id: &str, chunk_index: u32, data: &[u8]) -> Result<(), ()> {
    let path = content_path(files_dir, id);
    let temp_path = content_path(files_dir, &format!("{}.{}", id, chunk_index));
    let mut temp = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp_path)
        .map_err(|_| ())?;
    temp.write_all(data).map_err(|_| ())?;
    temp.flush().map_err(|_| ())?;
    drop(temp);

    let mut final_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|_| ())?;
    let offset = chunk_index as u64 * mitsuzo_types::UPLOAD_CHUNK_SIZE as u64;
    final_file.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
    final_file.write_all(data).map_err(|_| ())?;
    final_file.flush().map_err(|_| ())?;
    let _ = std::fs::remove_file(&temp_path);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn arr32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn meta_from_model(m: &paste::Model) -> Option<PasteMeta> {
    Some(PasteMeta {
        try_count: m.try_count as u32,
        expiration_timestamp: m.expiration_timestamp as u64,
        data_type: decode::<DataType>(&m.data_type).ok()?,
        filename: m.filename.clone(),
        content_type: m.content_type.clone(),
        total_chunks: m.total_chunks as u32,
        allow_download: m.allow_download,
        burn_after_read: m.burn_after_read,
        recipient_pub: m.recipient_pub.as_deref().and_then(arr32),
        recipient_kid: m.recipient_kid.as_deref().and_then(arr32),
    })
}

fn account_from_model(m: &account::Model) -> Option<AccountRecord> {
    Some(AccountRecord {
        kid: arr32(&m.kid)?,
        pubkey: arr32(&m.pubkey)?,
        name: m.name.clone(),
        created_at: m.created_at as u64,
    })
}

/// One-time import of the legacy Sled namespaces into the SQLite schema.
///
/// Idempotent: guarded by a `legacy_sled_migrated` marker in `app_state`, and
/// transactional so a failed startup cannot leave a partially imported
/// database. Returns `Ok(())` immediately when there is no Sled data.
async fn migrate_legacy_sled(
    connection: &DatabaseConnection,
    database_dir: &Path,
) -> eyre::Result<()> {
    let sled_dir = database_dir.join("db");
    let stats_dir = database_dir.join("stats");
    if !sled_dir.exists() && !stats_dir.exists() {
        return Ok(());
    }
    if state::Entity::find_by_id("legacy_sled_migrated")
        .one(connection)
        .await?
        .is_some()
    {
        return Ok(());
    }

    let db = if sled_dir.exists() {
        Some(sled::open(&sled_dir).wrap_err("Failed to open legacy Sled database")?)
    } else {
        None
    };
    let stats = if stats_dir.exists() {
        Some(sled::open(&stats_dir).wrap_err("Failed to open legacy Sled stats")?)
    } else {
        None
    };

    let txn = connection.begin().await?;

    if let Some(db) = &db {
        for item in db.scan_prefix(b"meta:") {
            let (key, value) = item?;
            let id = std::str::from_utf8(&key[5..])?.to_owned();
            let meta = decode::<PasteMeta>(&value)
                .or_else(|_| {
                    decode::<LegacyPasteMeta>(&value).map(|legacy| PasteMeta {
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
                    })
                })
                .wrap_err_with(|| format!("Invalid legacy metadata for paste {id}"))?;

            let received_chunks = db
                .get(format!("crecv:{id}"))?
                .and_then(|v| v.as_ref().try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0);
            let burn_receipt_hash = db
                .get(format!("burn:{id}"))?
                .map(|v| v.to_vec())
                .unwrap_or_default();
            let burned = db.get(format!("burned:{id}"))?.is_some();

            paste::ActiveModel {
                id: Set(id.clone()),
                try_count: Set(meta.try_count as i32),
                expiration_timestamp: Set(meta.expiration_timestamp as i64),
                data_type: Set(encode(&meta.data_type)),
                filename: Set(meta.filename),
                content_type: Set(meta.content_type),
                total_chunks: Set(meta.total_chunks as i32),
                received_chunks: Set(received_chunks as i32),
                allow_download: Set(meta.allow_download),
                burn_after_read: Set(meta.burn_after_read),
                recipient_pub: Set(meta.recipient_pub.map(|v| v.to_vec())),
                recipient_kid: Set(meta.recipient_kid.map(|v| v.to_vec())),
                burn_receipt_hash: Set(burn_receipt_hash),
                burned: Set(burned),
                // Legacy pastes predate per-paste upload tokens.
                upload_token_hash: Set(None),
            }
            .insert(&txn)
            .await?;

            let salt = db.get(format!("salt:{id}"))?.map(|v| v.to_vec());
            let password_hash = db.get(format!("pass:{id}"))?.map(|v| v.to_vec());
            let (wrap_nonce, wrapped_key) = db
                .get(format!("key:{id}"))?
                .map(|v| {
                    let bytes = v.to_vec();
                    if bytes.len() == 60 {
                        (Some(bytes[..12].to_vec()), Some(bytes[12..].to_vec()))
                    } else {
                        (None, None)
                    }
                })
                .unwrap_or((None, None));
            if salt.is_some() || password_hash.is_some() || wrap_nonce.is_some() {
                credential::ActiveModel {
                    paste_id: Set(id.clone()),
                    salt: Set(salt),
                    password_hash: Set(password_hash),
                    wrap_nonce: Set(wrap_nonce),
                    wrapped_key: Set(wrapped_key),
                }
                .insert(&txn)
                .await?;
            }

            if let Some(value) = db.get(format!("recp:{id}"))? {
                let envelope: RecipientEnvelope = decode(&value)?;
                recipient::ActiveModel {
                    paste_id: Set(id.clone()),
                    recipient_kid: Set(envelope.recipient_kid.to_vec()),
                    ephemeral_pub: Set(envelope.ephemeral_pub.to_vec()),
                    nonce: Set(envelope.nonce.to_vec()),
                    sealed_cek: Set(envelope.sealed_cek.to_vec()),
                }
                .insert(&txn)
                .await?;
            }
        }

        for item in db.scan_prefix(b"chunk:") {
            let (key, _) = item?;
            let value = std::str::from_utf8(&key[6..])?;
            let Some((paste_id, chunk_index)) = value.rsplit_once(':') else {
                continue;
            };
            chunk::ActiveModel {
                paste_id: Set(paste_id.to_owned()),
                chunk_index: Set(chunk_index.parse::<i32>()?),
            }
            .insert(&txn)
            .await?;
        }

        for item in db.scan_prefix(b"acct:") {
            let (_, value) = item?;
            let account_record: AccountRecord = decode(&value)?;
            account::ActiveModel {
                kid: Set(account_record.kid.to_vec()),
                pubkey: Set(account_record.pubkey.to_vec()),
                name: Set(account_record.name),
                created_at: Set(account_record.created_at as i64),
            }
            .insert(&txn)
            .await?;
        }

        for item in db.scan_prefix(b"recpix:") {
            let (key, value) = item?;
            let key = std::str::from_utf8(&key[7..])?;
            let Some((kid_hex, paste_id)) = key.split_once(':') else {
                continue;
            };
            let kid = (0..kid_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&kid_hex[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()?;
            let listing: PasteInboxListing = decode(&value)?;
            recipient_inbox::ActiveModel {
                recipient_kid: Set(kid),
                paste_id: Set(paste_id.to_owned()),
                listing: Set(encode(&listing)),
            }
            .insert(&txn)
            .await?;
        }
    }

    if let Some(stats) = &stats {
        for item in stats.iter() {
            let (key, value) = item?;
            let key = std::str::from_utf8(&key)?.to_owned();
            let value = value
                .as_ref()
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0) as i64;
            stat::ActiveModel {
                key: Set(key),
                value: Set(value),
            }
            .insert(&txn)
            .await?;
        }
    }

    state::ActiveModel {
        key: Set("legacy_sled_migrated".to_owned()),
        value: Set(b"1".to_vec()),
    }
    .insert(&txn)
    .await?;

    txn.commit().await?;
    if let Some(db) = db {
        db.flush()?;
    }
    if let Some(stats) = stats {
        stats.flush()?;
    }
    info!("legacy Sled data imported into SQLite");
    Ok(())
}

/// Move the legacy Sled trees aside after a successful import so they are not
/// rescanned and it is obvious they have been migrated. Best-effort: the
/// `legacy_sled_migrated` marker already makes the import idempotent.
fn archive_legacy_sled(database_dir: &Path) {
    for name in ["db", "stats"] {
        let from = database_dir.join(name);
        let to = database_dir.join(format!("{name}.sled-migrated"));
        if from.exists() && !to.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
}

impl DataStore {
    pub async fn new() -> eyre::Result<Self> {
        Self::open(Path::new("database")).await
    }

    /// Open (or create) a store rooted at `database_dir`. Used by the server
    /// with the default `database` directory and by tests with a temp dir.
    pub async fn open(database_dir: &Path) -> eyre::Result<Self> {
        std::fs::create_dir_all(database_dir).wrap_err("Failed to create database directory")?;

        let sqlite_path = database_dir.join("mitsuzo.sqlite");
        let sqlite_url = format!("sqlite://{}?mode=rwc", sqlite_path.display());
        let mut options = ConnectOptions::new(sqlite_url);
        options.sqlx_logging(false).max_connections(5);
        options.map_sqlx_sqlite_opts(|opts| {
            opts.busy_timeout(Duration::from_secs(10))
                .journal_mode(sea_orm::sqlx::sqlite::SqliteJournalMode::Wal)
                .foreign_keys(true)
        });
        let db = Database::connect(options)
            .await
            .wrap_err("Failed to connect to SQLite")?;
        mitsuzo_migration::Migrator::up(&db, None)
            .await
            .wrap_err("Failed to apply SeaORM migrations")?;

        // One-time import of a pre-cutover Sled installation, if present.
        // Earlier releases stored paste metadata in `database/db` (and stats
        // in `database/stats`); this version stores everything in SQLite.
        // Import before serving so existing pastes keep working, then archive
        // the Sled trees so later starts skip the import.
        migrate_legacy_sled(&db, database_dir)
            .await
            .wrap_err("Failed to import legacy Sled data")?;
        archive_legacy_sled(database_dir);

        let files_dir = database_dir.join("files");
        std::fs::create_dir_all(&files_dir)
            .wrap_err("Failed to create database/files directory")?;
        Ok(Self {
            db,
            files_dir,
            deletion_lock: Arc::new(Mutex::new(())),
        })
    }

    async fn paste_model(&self, id: &str) -> Option<paste::Model> {
        paste::Entity::find_by_id(id.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()
    }

    pub async fn get_meta(&self, id: &str) -> Option<PasteMeta> {
        meta_from_model(&self.paste_model(id).await?)
    }

    async fn is_expired(&self, id: &str) -> bool {
        if let Some(meta) = self.paste_model(id).await {
            return meta.expiration_timestamp > 0
                && epoch_secs() > meta.expiration_timestamp as u64;
        }
        false
    }

    pub async fn init_paste(
        &self,
        id: &str,
        header: &mitsuzo_types::CreatePasteHeader,
        upload_token_hash: &[u8; 32],
    ) -> eyre::Result<()> {
        // The PRNG hands out IDs that are otherwise available, which includes
        // pastes that expired but have not been cleaned up yet. Reusing such an
        // ID would otherwise leave the old chunk rows and content file behind.
        if self.paste_model(id).await.is_some() {
            self.delete_paste_inner(id).await;
        }

        let nonce_path = nonce_path(&self.files_dir, id);
        std::fs::write(&nonce_path, header.nonce)
            .wrap_err_with(|| format!("Failed to write nonce for paste {}", id))?;

        let expiration_timestamp = match header.ttl_seconds {
            Some(ttl) if ttl > 0 => (epoch_secs() + u64::from(ttl)) as i64,
            _ => 0,
        };

        let txn = self
            .db
            .begin()
            .await
            .wrap_err("Failed to begin transaction")?;

        paste::ActiveModel {
            id: Set(id.to_owned()),
            try_count: Set(header.try_count.unwrap_or(0) as i32),
            expiration_timestamp: Set(expiration_timestamp),
            data_type: Set(encode(&header.data_type)),
            filename: Set(header.filename.clone()),
            content_type: Set(header.content_type.clone()),
            total_chunks: Set(header.total_chunks as i32),
            received_chunks: Set(0),
            allow_download: Set(header.allow_download),
            burn_after_read: Set(header.burn_after_read),
            recipient_pub: Set(header.recipient_pub.map(|v| v.to_vec())),
            recipient_kid: Set(header.recipient.as_ref().map(|r| r.recipient_kid.to_vec())),
            burn_receipt_hash: Set(header.burn_receipt_hash.to_vec()),
            burned: Set(false),
            upload_token_hash: Set(Some(upload_token_hash.to_vec())),
        }
        .insert(&txn)
        .await
        .wrap_err("Failed to insert paste")?;

        // Password mode: one credential row. Recipient mode: one recipient row
        // plus an inbox listing for the recipient account.
        if header.recipient.is_none() {
            credential::ActiveModel {
                paste_id: Set(id.to_owned()),
                salt: Set(header.salt.map(|v| v.to_vec())),
                password_hash: Set(header.password_hash.map(|v| v.to_vec())),
                wrap_nonce: Set(header.key.as_ref().map(|k| k.wrap_nonce.to_vec())),
                wrapped_key: Set(header.key.as_ref().map(|k| k.wrapped_key.to_vec())),
            }
            .insert(&txn)
            .await
            .wrap_err("Failed to insert paste credentials")?;
        }

        if let Some(recipient) = &header.recipient {
            recipient::ActiveModel {
                paste_id: Set(id.to_owned()),
                recipient_kid: Set(recipient.recipient_kid.to_vec()),
                ephemeral_pub: Set(recipient.ephemeral_pub.to_vec()),
                nonce: Set(recipient.nonce.to_vec()),
                sealed_cek: Set(recipient.sealed_cek.to_vec()),
            }
            .insert(&txn)
            .await
            .wrap_err("Failed to insert recipient envelope")?;

            let listing = PasteInboxListing {
                id: id.to_owned(),
                data_type: header.data_type.clone(),
                filename: header.filename.clone(),
                created_at: epoch_secs(),
            };
            recipient_inbox::ActiveModel {
                recipient_kid: Set(recipient.recipient_kid.to_vec()),
                paste_id: Set(id.to_owned()),
                listing: Set(encode(&listing)),
            }
            .insert(&txn)
            .await
            .wrap_err("Failed to insert recipient inbox listing")?;
        }

        txn.commit().await.wrap_err("Failed to commit paste")?;

        self.increment_stat("pastes_all_time").await;
        self.increment_stat(&day_key("pastes_day")).await;
        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub async fn append_chunk(&self, id: &str, chunk_index: u32, data: &[u8]) -> Result<(), ()> {
        let already = chunk::Entity::find_by_id((id.to_owned(), chunk_index as i32))
            .one(&self.db)
            .await
            .map_err(|_| ())?
            .is_some();
        if already {
            return Ok(());
        }

        // Chunk writes are blocking filesystem I/O of up to the upload chunk
        // size; run them on the blocking pool so they don't stall the runtime.
        let files_dir = self.files_dir.clone();
        let id_owned = id.to_owned();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            write_chunk_file(&files_dir, &id_owned, chunk_index, &data)
        })
        .await
        .map_err(|_| ())??;

        // Record the chunk and bump the received count atomically.
        let txn = self.db.begin().await.map_err(|_| ())?;
        chunk::ActiveModel {
            paste_id: Set(id.to_owned()),
            chunk_index: Set(chunk_index as i32),
        }
        .insert(&txn)
        .await
        .map_err(|_| ())?;
        paste::Entity::update_many()
            .col_expr(
                paste::Column::ReceivedChunks,
                Expr::col(paste::Column::ReceivedChunks).add(1),
            )
            .filter(paste::Column::Id.eq(id))
            .exec(&txn)
            .await
            .map_err(|_| ())?;
        txn.commit().await.map_err(|_| ())?;
        Ok(())
    }

    pub async fn get_received_chunks(&self, id: &str) -> u32 {
        self.paste_model(id)
            .await
            .map(|m| m.received_chunks as u32)
            .unwrap_or(0)
    }

    pub async fn get_password_hash(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id).await {
            return None;
        }
        credential::Entity::find_by_id(id.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()?
            .password_hash
    }

    pub async fn get_salt(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id).await {
            return None;
        }
        credential::Entity::find_by_id(id.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()?
            .salt
    }

    /// Fetch the password-wrapped content key. `None` for legacy pastes
    /// created before envelope encryption was introduced.
    pub async fn get_key(&self, id: &str) -> Option<KeyEnvelope> {
        if self.is_expired(id).await {
            return None;
        }
        let row = credential::Entity::find_by_id(id.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()?;
        Some(KeyEnvelope {
            wrap_nonce: row.wrap_nonce?.try_into().ok()?,
            wrapped_key: row.wrapped_key?.try_into().ok()?,
        })
    }

    /// Replace password credentials after a password change: new salt, new
    /// password hash, and the re-wrapped content key.
    pub async fn set_password(
        &self,
        id: &str,
        salt: &[u8; 16],
        password_hash: &[u8; 32],
        key: &mitsuzo_types::KeyEnvelope,
    ) {
        let am = credential::ActiveModel {
            paste_id: Set(id.to_owned()),
            salt: Set(Some(salt.to_vec())),
            password_hash: Set(Some(password_hash.to_vec())),
            wrap_nonce: Set(Some(key.wrap_nonce.to_vec())),
            wrapped_key: Set(Some(key.wrapped_key.to_vec())),
        };
        if credential::Entity::update(am).exec(&self.db).await.is_err() {
            let _ = credential::ActiveModel {
                paste_id: Set(id.to_owned()),
                salt: Set(Some(salt.to_vec())),
                password_hash: Set(Some(password_hash.to_vec())),
                wrap_nonce: Set(Some(key.wrap_nonce.to_vec())),
                wrapped_key: Set(Some(key.wrapped_key.to_vec())),
            }
            .insert(&self.db)
            .await;
        }
    }

    pub async fn decrement_try_count(&self, id: &str) {
        let Some(model) = self.paste_model(id).await else {
            return;
        };
        if model.try_count == 0 {
            return;
        }
        let new_count = model.try_count - 1;
        let mut am: paste::ActiveModel = model.into();
        am.try_count = Set(new_count);
        if am.update(&self.db).await.is_ok() && new_count == 0 {
            self.delete_paste(id).await;
        }
    }

    pub async fn delete_paste(&self, id: &str) {
        let _lock = self.deletion_lock.lock().await;
        self.delete_paste_inner(id).await;
    }

    async fn delete_paste_inner(&self, id: &str) {
        let _ = paste::Entity::delete_by_id(id.to_owned())
            .exec(&self.db)
            .await;
        let _ = credential::Entity::delete_by_id(id.to_owned())
            .exec(&self.db)
            .await;
        let _ = recipient::Entity::delete_by_id(id.to_owned())
            .exec(&self.db)
            .await;
        let _ = chunk::Entity::delete_many()
            .filter(chunk::Column::PasteId.eq(id))
            .exec(&self.db)
            .await;
        let _ = recipient_inbox::Entity::delete_many()
            .filter(recipient_inbox::Column::PasteId.eq(id))
            .exec(&self.db)
            .await;
        let _ = std::fs::remove_file(content_path(&self.files_dir, id));
        let _ = std::fs::remove_file(nonce_path(&self.files_dir, id));
    }

    pub async fn get_burn_receipt_hash(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id).await {
            return None;
        }
        self.paste_model(id).await.map(|m| m.burn_receipt_hash)
    }

    /// SHA-256 of the per-paste upload token, used to authenticate chunk
    /// uploads and completion. `None` for legacy pastes without a token.
    pub async fn get_upload_token_hash(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id).await {
            return None;
        }
        self.paste_model(id).await?.upload_token_hash
    }

    pub async fn mark_burned(&self, id: &str) -> bool {
        let Some(model) = self.paste_model(id).await else {
            return false;
        };
        if model.burned {
            return false;
        }
        let mut am: paste::ActiveModel = model.into();
        am.burned = Set(true);
        am.update(&self.db).await.is_ok()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let current = epoch_secs() as i64;
        let expired = paste::Entity::find()
            .filter(paste::Column::ExpirationTimestamp.gt(0))
            .filter(paste::Column::ExpirationTimestamp.lte(current))
            .all(&self.db)
            .await
            .unwrap_or_default();

        let _lock = self.deletion_lock.lock().await;
        for model in &expired {
            self.delete_paste_inner(&model.id).await;
        }
        expired.len()
    }

    pub async fn get_content_path(&self, id: &str) -> Option<PathBuf> {
        if self.is_expired(id).await {
            return None;
        }
        let path = content_path(&self.files_dir, id);
        path.exists().then_some(path)
    }

    pub async fn id_available(&self, id: &str) -> bool {
        match self.paste_model(id).await {
            Some(meta) => {
                meta.expiration_timestamp > 0 && epoch_secs() > meta.expiration_timestamp as u64
            }
            None => true,
        }
    }

    /// Recipient envelope for a recipient-mode paste.
    pub async fn get_recipient_envelope(&self, id: &str) -> Option<RecipientEnvelope> {
        if self.is_expired(id).await {
            return None;
        }
        let row = recipient::Entity::find_by_id(id.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()?;
        Some(RecipientEnvelope {
            recipient_kid: arr32(&row.recipient_kid)?,
            ephemeral_pub: arr32(&row.ephemeral_pub)?,
            nonce: row.nonce.try_into().ok()?,
            sealed_cek: row.sealed_cek.try_into().ok()?,
        })
    }

    /// Non-expired recipient-mode pastes addressed to an account.
    pub async fn list_recipient_pastes(&self, kid: &[u8; 32]) -> Vec<PasteInboxListing> {
        let rows = recipient_inbox::Entity::find()
            .filter(recipient_inbox::Column::RecipientKid.eq(kid.to_vec()))
            .all(&self.db)
            .await
            .unwrap_or_default();

        let mut listings = Vec::new();
        for row in rows {
            let Ok(listing) = decode::<PasteInboxListing>(&row.listing) else {
                continue;
            };
            let expired = match self.paste_model(&listing.id).await {
                Some(meta) => {
                    meta.expiration_timestamp != 0
                        && meta.expiration_timestamp <= epoch_secs() as i64
                }
                None => true,
            };
            if expired {
                let _ = recipient_inbox::Entity::delete_many()
                    .filter(recipient_inbox::Column::RecipientKid.eq(kid.to_vec()))
                    .filter(recipient_inbox::Column::PasteId.eq(&listing.id))
                    .exec(&self.db)
                    .await;
            } else {
                listings.push(listing);
            }
        }
        listings
    }

    pub async fn get_nonce(&self, id: &str) -> Option<Vec<u8>> {
        if self.is_expired(id).await {
            return None;
        }
        std::fs::read(nonce_path(&self.files_dir, id)).ok()
    }

    pub async fn increment_success(&self) {
        self.increment_stat("success_all_time").await;
        self.increment_stat(&day_key("success_day")).await;
    }

    pub async fn increment_fail(&self) {
        self.increment_stat("fail_all_time").await;
        self.increment_stat(&day_key("fail_day")).await;
    }

    async fn increment_stat(&self, key: &str) {
        if stat::Entity::find_by_id(key.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            let _ = stat::Entity::update_many()
                .col_expr(stat::Column::Value, Expr::col(stat::Column::Value).add(1))
                .filter(stat::Column::Key.eq(key))
                .exec(&self.db)
                .await;
        } else {
            let _ = stat::ActiveModel {
                key: Set(key.to_owned()),
                value: Set(1),
            }
            .insert(&self.db)
            .await;
        }
    }

    async fn read_stat(&self, key: &str) -> u64 {
        stat::Entity::find_by_id(key.to_owned())
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .map(|m| std::cmp::max(m.value, 0) as u64)
            .unwrap_or(0)
    }

    pub async fn get_pastes_all_time(&self) -> u64 {
        self.read_stat("pastes_all_time").await
    }

    pub async fn get_pastes_daily(&self) -> u64 {
        self.read_stat(&day_key("pastes_day")).await
    }

    pub async fn get_success_all_time(&self) -> u64 {
        self.read_stat("success_all_time").await
    }

    pub async fn get_success_daily(&self) -> u64 {
        self.read_stat(&day_key("success_day")).await
    }

    pub async fn get_fail_all_time(&self) -> u64 {
        self.read_stat("fail_all_time").await
    }

    pub async fn get_fail_daily(&self) -> u64 {
        self.read_stat(&day_key("fail_day")).await
    }

    /// Insert or update an account record, keyed by full 32-byte kid.
    pub async fn put_account(&self, record: &AccountRecord) {
        let _ = account::Entity::insert(account::ActiveModel {
            kid: Set(record.kid.to_vec()),
            pubkey: Set(record.pubkey.to_vec()),
            name: Set(record.name.clone()),
            created_at: Set(record.created_at as i64),
        })
        .on_conflict(
            OnConflict::column(account::Column::Kid)
                .update_columns([account::Column::Pubkey, account::Column::Name])
                .to_owned(),
        )
        .exec(&self.db)
        .await;
    }

    /// Look up an account by full 32-byte kid.
    pub async fn get_account_by_kid(&self, kid: &[u8; 32]) -> Option<AccountRecord> {
        let model = account::Entity::find_by_id(kid.to_vec())
            .one(&self.db)
            .await
            .ok()
            .flatten()?;
        account_from_model(&model)
    }

    /// Look up an account by its 20-byte display prefix (first 20 bytes of the
    /// full SHA-256). With 160 bits of prefix, collisions are negligible; a
    /// scan is fine because account counts are small.
    pub async fn get_account_by_prefix(&self, prefix: &[u8; 20]) -> Option<AccountRecord> {
        let wanted = hex(prefix);
        let accounts = account::Entity::find().all(&self.db).await.ok()?;
        accounts.into_iter().find_map(|model| {
            if hex(&model.kid).get(..40) == Some(wanted.as_str()) {
                account_from_model(&model)
            } else {
                None
            }
        })
    }

    /// SQLite commits synchronously, so there is nothing to flush explicitly.
    /// Kept for the shutdown path.
    pub fn flush(&self) -> eyre::Result<()> {
        Ok(())
    }

    /// Cheap readiness check: the database answers a query.
    pub async fn is_healthy(&self) -> bool {
        paste::Entity::find().one(&self.db).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store(dir: &Path) -> DataStore {
        std::fs::create_dir_all(dir).expect("create test dir");
        DataStore::open(dir).await.expect("open store")
    }

    #[tokio::test]
    async fn account_lookup_by_full_kid_and_prefix() {
        let dir = std::env::temp_dir().join(format!("mitsuzo-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = test_store(&dir).await;

        for i in 0u8..3 {
            let mut kid = [0u8; 32];
            kid[0] = i;
            store
                .put_account(&AccountRecord {
                    kid,
                    pubkey: [0x42; 32],
                    name: format!("user{}", i),
                    created_at: 0,
                })
                .await;
        }

        let mut kid = [0u8; 32];
        kid[0] = 2;
        let by_full = store
            .get_account_by_kid(&kid)
            .await
            .expect("full-kid lookup");
        assert_eq!(by_full.name, "user2");

        let mut prefix = [0u8; 20];
        prefix[0] = 1;
        let by_prefix = store
            .get_account_by_prefix(&prefix)
            .await
            .expect("prefix lookup");
        assert_eq!(by_prefix.kid[0], 1);
        assert_eq!(by_prefix.name, "user1");

        let mut missing = [0u8; 20];
        missing[0] = 9;
        assert!(store.get_account_by_prefix(&missing).await.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn migrates_legacy_sled_data() {
        let dir = std::env::temp_dir().join(format!("mitsuzo-db-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");

        // Build a minimal legacy Sled installation.
        let id = "123456";
        let sled_db = sled::open(dir.join("db")).expect("open legacy sled");
        let meta = PasteMeta {
            try_count: 5,
            expiration_timestamp: 0,
            data_type: DataType::Text,
            filename: None,
            content_type: None,
            total_chunks: 1,
            allow_download: true,
            burn_after_read: false,
            recipient_pub: None,
            recipient_kid: None,
        };
        sled_db
            .insert(format!("meta:{id}"), encode(&meta))
            .expect("insert meta");
        sled_db
            .insert(format!("pass:{id}"), vec![7u8; 32])
            .expect("insert pass");
        sled_db
            .insert(format!("salt:{id}"), vec![9u8; 16])
            .expect("insert salt");
        let mut key_blob = vec![0u8; 60];
        key_blob[0] = 1;
        sled_db
            .insert(format!("key:{id}"), key_blob)
            .expect("insert key");
        sled_db
            .insert(format!("crecv:{id}"), 1u32.to_le_bytes().to_vec())
            .expect("insert crecv");
        sled_db.flush().expect("flush legacy sled");
        drop(sled_db);

        // Opening the store imports the Sled data into SQLite.
        let store = DataStore::open(&dir).await.expect("open migrates");
        let migrated = store.get_meta(id).await.expect("paste migrated");
        assert_eq!(migrated.try_count, 5);
        assert_eq!(store.get_received_chunks(id).await, 1);
        assert!(store.get_password_hash(id).await.is_some());
        assert!(store.get_key(id).await.is_some());

        // The Sled tree is archived and reopening is idempotent.
        assert!(!dir.join("db").exists());
        assert!(dir.join("db.sled-migrated").exists());
        let reopened = DataStore::open(&dir).await.expect("reopen");
        assert_eq!(
            reopened
                .get_meta(id)
                .await
                .expect("still migrated")
                .try_count,
            5
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
