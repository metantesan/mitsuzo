use bitcode::{decode, encode};
use mitsuzo_types::DataType;
use sled::Db;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct DataStore {
    db: Db,
    stats: Db,
    files_dir: PathBuf,
}

impl DataStore {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let db = sled::open(Path::new("database/db")).unwrap();
        let stats = sled::open(Path::new("database/stats")).unwrap();
        let files_dir = PathBuf::from("database/files");
        std::fs::create_dir_all(&files_dir).unwrap();
        Self {
            db,
            stats,
            files_dir,
        }
    }
}

fn day_key(prefix: &str) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}:{}", prefix, secs / 86400)
}

fn increment_counter(db: &Db, key: &str) {
    let _ = db
        .update_and_fetch(key.as_bytes(), |v| {
            let count = v.map_or(0u64, |bytes| {
                let arr: [u8; 8] = bytes.as_ref().try_into().unwrap_or([0u8; 8]);
                u64::from_be_bytes(arr)
            });
            Some((count + 1).to_be_bytes().to_vec())
        })
        .unwrap();
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
        .unwrap()
        .as_secs()
}

impl DataStore {
    pub fn init_paste(
        &self,
        id: &str,
        nonce: &[u8],
        salt: &[u8],
        password_hash: &[u8],
        try_count: Option<u32>,
        ttl_seconds: Option<u32>,
        data_type: DataType,
        filename: Option<String>,
        content_type: Option<String>,
        total_chunks: u32,
        allow_download: bool,
    ) {
        std::fs::write(nonce_path(&self.files_dir, id), nonce).unwrap();

        let _ = self.db.insert(format!("pass:{}", id), password_hash);
        let _ = self.db.insert(format!("salt:{}", id), salt);

        let expiration_timestamp = match ttl_seconds {
            Some(ttl) if ttl > 0 => epoch_secs() + u64::from(ttl),
            _ => 0,
        };

        let meta_value = encode(&(
            try_count.unwrap_or(0),
            expiration_timestamp,
            data_type,
            filename,
            content_type,
            total_chunks,
            allow_download,
        ));
        let _ = self.db.insert(format!("meta:{}", id), meta_value);
        let _ = self
            .db
            .insert(format!("crecv:{}", id), &0u32.to_le_bytes()[..]);
        let _ = self.db.flush();

        increment_counter(&self.stats, "pastes_all_time");
        increment_counter(&self.stats, &day_key("pastes_day"));
    }

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

    #[allow(clippy::type_complexity)]
    pub fn get_meta(
        &self,
        id: &str,
    ) -> Option<(
        u32,
        u64,
        DataType,
        Option<String>,
        Option<String>,
        u32,
        bool,
    )> {
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
                let (
                    try_count,
                    expiration,
                    data_type,
                    filename,
                    content_type,
                    total_chunks,
                    allow_download,
                ) = decode::<(
                    u32,
                    u64,
                    DataType,
                    Option<String>,
                    Option<String>,
                    u32,
                    bool,
                )>(value)
                .ok()?;
                if try_count == 0 {
                    return None;
                }
                let new_try_count = try_count - 1;
                let encoded = encode(&(
                    new_try_count,
                    expiration,
                    data_type,
                    filename,
                    content_type,
                    total_chunks,
                    allow_download,
                ));
                Some(encoded)
            })
            .ok()
            .flatten();
        if let Some(meta) = result {
            if let Ok((0, _, _, _, _, _, _)) = decode::<(
                u32,
                u64,
                DataType,
                Option<String>,
                Option<String>,
                u32,
                bool,
            )>(&meta)
            {
                self.delete_paste(id);
            }
            let _ = self.db.flush();
        }
    }

    pub fn delete_paste(&self, id: &str) {
        let _ = self.db.remove(format!("pass:{}", id));
        let _ = self.db.remove(format!("salt:{}", id));
        let _ = self.db.remove(format!("meta:{}", id));
        let _ = self.db.remove(format!("crecv:{}", id));
        self.delete_chunk_keys(id);
        let _ = std::fs::remove_file(content_path(&self.files_dir, id));
        let _ = std::fs::remove_file(nonce_path(&self.files_dir, id));
        let _ = self.db.flush();
    }

    pub fn cleanup_expired(&self) -> usize {
        let current_time = epoch_secs();
        let mut deleted_count = 0;

        for item in self.db.scan_prefix(b"meta:") {
            let Ok((key, value)) = item else { continue };
            let Ok((_, expiration_timestamp, _, _, _, _, _)) = decode::<(
                u32,
                u64,
                DataType,
                Option<String>,
                Option<String>,
                u32,
                bool,
            )>(&value) else {
                continue;
            };
            if expiration_timestamp > 0
                && current_time > expiration_timestamp
                && let Ok(id_str) = std::str::from_utf8(&key[5..])
            {
                self.delete_paste(id_str);
                deleted_count += 1;
            }
        }

        deleted_count
    }

    pub fn list_all(&self) -> Vec<(String, u64, DataType, Option<String>)> {
        let mut results = Vec::new();
        for item in self.db.scan_prefix(b"meta:") {
            let Ok((key, value)) = item else { continue };
            let Ok(id_str) = std::str::from_utf8(&key[5..]) else {
                continue;
            };
            let Ok((_, _, data_type, filename, _, _, _)) = decode::<(
                u32,
                u64,
                DataType,
                Option<String>,
                Option<String>,
                u32,
                bool,
            )>(&value) else {
                continue;
            };
            let size = std::fs::metadata(content_path(&self.files_dir, id_str))
                .map(|m| m.len())
                .unwrap_or(0);
            results.push((id_str.to_string(), size, data_type, filename));
        }
        results
    }

    fn is_expired(&self, id: &str) -> bool {
        if let Some((_, expiration_timestamp, _, _, _, _, _)) = self.get_meta(id) {
            let current_time = epoch_secs();
            if expiration_timestamp > 0 && current_time > expiration_timestamp {
                self.delete_paste(id);
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
                let Ok((_, expiration_timestamp, _, _, _, _, _)) = decode::<(
                    u32,
                    u64,
                    DataType,
                    Option<String>,
                    Option<String>,
                    u32,
                    bool,
                )>(&value) else {
                    return true;
                };
                expiration_timestamp > 0 && epoch_secs() > expiration_timestamp
            }
            _ => true,
        }
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
}
