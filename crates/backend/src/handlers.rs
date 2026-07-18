use crate::db::DataStore;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use bitcode::{decode, encode};
use futures::stream::{self, StreamExt};
use mitsuzo_types::{
    CHUNK_SIZE, CreatePasteHeader, CreatePasteResponse, GetPasteHeader, GetSaltResponse,
    GetStatsResponse, MAX_PASTE_SIZE, read_framed,
};
use rand::RngExt;
use std::fs;
use tokio::io::AsyncReadExt;
use tracing::info;

pub async fn serve_index() -> impl IntoResponse {
    let index_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("public/index.html");
    let index_html = fs::read_to_string(index_path).unwrap();
    Html(index_html)
}

pub async fn fallback_to_index() -> impl IntoResponse {
    let index_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("public/index.html");
    let index_html = fs::read_to_string(index_path).unwrap();
    Html(index_html)
}

fn validate_id(id: &str) -> Result<(), StatusCode> {
    id.chars()
        .all(|c| c.is_ascii_digit())
        .then_some(())
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_paste(State(db): State<DataStore>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    let (header_bytes, content) = read_framed(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let header: CreatePasteHeader = decode(header_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    if content.len() > MAX_PASTE_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    if header.total_chunks == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ttl_seconds = match header.ttl_seconds {
        Some(ttl) => {
            if ttl == 0 {
                return Err(StatusCode::BAD_REQUEST);
            }
            Some(ttl.min(43200))
        }
        None => return Err(StatusCode::BAD_REQUEST),
    };

    let try_count = match header.try_count {
        Some(count) if count > 0 && count <= 100 => count,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let mut rng = rand::rng();
    let mut id_str;
    let mut attempts = 0;
    loop {
        let id: u32 = rng.random_range(100_000..1_000_000);
        id_str = id.to_string();
        if !db.id_available(&id_str) {
            attempts += 1;
            if attempts >= 100 {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            continue;
        }
        break;
    }

    db.insert(
        &id_str,
        content,
        &header.nonce,
        &header.salt,
        &header.password_hash,
        Some(try_count),
        ttl_seconds,
        header.data_type,
        header.filename,
        header.content_type,
        header.total_chunks,
    );

    info!(id = %id_str, "paste created");

    let response = CreatePasteResponse { id: id_str };
    Ok(encode(&response))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub async fn get_salt(
    State(db): State<DataStore>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if let (Some(salt), Some((try_count, expiration_timestamp, _, _, _, total_chunks))) =
        (db.get_salt(&id), db.get_meta(&id))
    {
        if try_count == 0 {
            return Err(StatusCode::NOT_FOUND);
        }
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ttl = if expiration_timestamp > 0 && expiration_timestamp > current_time {
            expiration_timestamp - current_time
        } else {
            0
        };

        let response = GetSaltResponse {
            salt,
            try_count,
            ttl,
            total_chunks,
        };
        Ok(encode(&response))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

fn compute_total_size(content_len: usize, total_chunks: u32) -> u64 {
    if total_chunks <= 1 {
        return content_len.saturating_sub(16) as u64;
    }
    let chunk_overhead: usize = 16;
    let full_chunk_cipher_len = CHUNK_SIZE + chunk_overhead;
    let full_chunks = (total_chunks - 1) as usize;
    let full_chunks_cipher_len = full_chunks * full_chunk_cipher_len;
    if content_len < full_chunks_cipher_len {
        return 0;
    }
    let last_chunk_cipher_len = content_len - full_chunks_cipher_len;
    if last_chunk_cipher_len <= chunk_overhead {
        return (full_chunks * CHUNK_SIZE) as u64;
    }
    let last_chunk_plain_len = last_chunk_cipher_len - chunk_overhead;
    (full_chunks * CHUNK_SIZE + last_chunk_plain_len) as u64
}

pub async fn get_paste(
    State(db): State<DataStore>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    validate_id(&id)?;
    if let Some(stored_hash) = db.get_password_hash(&id) {
        let Some(provided_hash_str) = headers
            .get("X-Password-Hash")
            .and_then(|value| value.to_str().ok())
        else {
            db.decrement_try_count(&id);
            db.increment_fail();
            return Err(StatusCode::UNAUTHORIZED);
        };
        let provided_hash = match general_purpose::STANDARD.decode(provided_hash_str) {
            Ok(h) => h,
            Err(_) => {
                db.decrement_try_count(&id);
                db.increment_fail();
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        if !constant_time_eq(&provided_hash, &stored_hash) {
            db.decrement_try_count(&id);
            db.increment_fail();
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let nonce = db.get_nonce(&id).ok_or(StatusCode::NOT_FOUND)?;
    let file_path = db.get_content_path(&id).ok_or(StatusCode::NOT_FOUND)?;
    let (_try_count, _expiration, data_type, filename, content_type, total_chunks) =
        db.get_meta(&id).ok_or(StatusCode::NOT_FOUND)?;

    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let content_len = file_meta.len() as usize;
    let total_size = compute_total_size(content_len, total_chunks);
    db.increment_success();

    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let header = GetPasteHeader {
        id,
        nonce: nonce_arr,
        data_type,
        filename,
        content_type,
        total_size,
        total_chunks,
    };

    let header_bytes = encode(&header);
    let mut head = Vec::with_capacity(4 + header_bytes.len());
    head.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    head.extend_from_slice(&header_bytes);

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let head_stream = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(head)) });
    let file_stream = stream::unfold(file, |mut f| async {
        let mut buf = vec![0u8; 65536];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(Bytes::from(buf)), f))
            }
            Err(e) => Some((Err(e), f)),
        }
    });

    Ok(Response::new(Body::from_stream(
        head_stream.chain(file_stream),
    )))
}

pub async fn get_stats(State(db): State<DataStore>) -> Vec<u8> {
    let stats = tokio::task::spawn_blocking(move || {
        (
            db.get_pastes_all_time(),
            db.get_pastes_daily(),
            db.get_success_all_time(),
            db.get_success_daily(),
            db.get_fail_all_time(),
            db.get_fail_daily(),
        )
    })
    .await
    .unwrap();

    encode(&GetStatsResponse {
        pastes_all_time: stats.0,
        pastes_daily: stats.1,
        requests_success_all_time: stats.2,
        requests_success_daily: stats.3,
        requests_fail_all_time: stats.4,
        requests_fail_daily: stats.5,
    })
}
