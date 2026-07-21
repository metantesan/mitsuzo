use crate::db::DataStore;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use bitcode::{decode, encode};
use futures::stream::{self, StreamExt};
use mitsuzo_types::{
    CHUNK_SIZE, ChunkInfoResponse, CreatePasteHeader, GetPasteHeader, GetSaltResponse,
    GetStatsResponse, InitPasteResponse, UPLOAD_CHUNK_SIZE,
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

fn verify_password(db: &DataStore, id: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(stored_hash) = db.get_password_hash(id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(provided_hash_str) = headers
        .get("X-Password-Hash")
        .and_then(|value| value.to_str().ok())
    else {
        db.decrement_try_count(id);
        db.increment_fail();
        return Err(StatusCode::UNAUTHORIZED);
    };
    let provided_hash = match general_purpose::STANDARD.decode(provided_hash_str) {
        Ok(h) => h,
        Err(_) => {
            db.decrement_try_count(id);
            db.increment_fail();
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if !constant_time_eq(&provided_hash, &stored_hash) {
        db.decrement_try_count(id);
        db.increment_fail();
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

pub async fn init_paste(State(db): State<DataStore>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    let header: CreatePasteHeader = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

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

    db.init_paste(
        &id_str,
        &header.nonce,
        &header.salt,
        &header.password_hash,
        Some(try_count),
        ttl_seconds,
        header.data_type,
        header.filename,
        header.content_type,
        header.total_chunks,
        header.allow_download,
    );

    info!(id = %id_str, "paste initialized");

    Ok(encode(&InitPasteResponse { id: id_str }))
}

pub async fn upload_chunk(
    State(db): State<DataStore>,
    Path((id, chunk_index)): Path<(String, u32)>,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;
    if body.len() > UPLOAD_CHUNK_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    db.append_chunk(&id, chunk_index, &body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(())
}

pub async fn get_chunk_info(
    State(db): State<DataStore>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let received = db.get_received_chunks(&id);
    Ok(encode(&ChunkInfoResponse { received }))
}

pub async fn complete_paste(
    State(db): State<DataStore>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    info!(id = %id, "paste completed");
    Ok(encode(&InitPasteResponse { id }))
}

pub async fn get_salt(
    State(db): State<DataStore>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if let (
        Some(salt),
        Some((
            try_count,
            expiration_timestamp,
            data_type,
            filename,
            content_type,
            total_chunks,
            allow_download,
        )),
    ) = (db.get_salt(&id), db.get_meta(&id))
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

        let content_len = db.get_content_size(&id).unwrap_or(0);
        let total_size = compute_total_size(content_len as usize, total_chunks);

        let nonce = db.get_nonce(&id).ok_or(StatusCode::NOT_FOUND)?;
        let nonce_arr: [u8; 12] = nonce
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let response = GetSaltResponse {
            salt,
            try_count,
            ttl,
            total_chunks,
            total_size,
            nonce: nonce_arr,
            data_type,
            filename,
            content_type,
            allow_download,
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
    verify_password(&db, &id, &headers)?;

    let nonce = db.get_nonce(&id).ok_or(StatusCode::NOT_FOUND)?;
    let file_path = db.get_content_path(&id).ok_or(StatusCode::NOT_FOUND)?;
    let (_try_count, _expiration, data_type, filename, content_type, total_chunks, allow_download) =
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
        allow_download,
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

pub async fn get_paste_data(
    State(db): State<DataStore>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    validate_id(&id)?;
    verify_password(&db, &id, &headers)?;

    let file_path = db.get_content_path(&id).ok_or(StatusCode::NOT_FOUND)?;
    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let file_len = file_meta.len();
    db.increment_success();

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);

    if let Some((start, end)) = range {
        let end = end.min(file_len - 1);
        let len = end - start + 1;

        let file = tokio::fs::File::open(&file_path)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;

        let file_stream =
            stream::unfold((file, start, false), move |(mut f, pos, done)| async move {
                if done {
                    return None;
                }
                let mut buf = vec![0u8; 65536];
                let to_read = std::cmp::min(buf.len() as u64, (end + 1) - pos) as usize;
                if to_read == 0 {
                    return None;
                }
                buf.truncate(to_read);
                use tokio::io::AsyncSeekExt;
                let _ = f.seek(std::io::SeekFrom::Start(pos)).await;
                use tokio::io::AsyncReadExt;
                match f.read(&mut buf).await {
                    Ok(0) | Err(_) => None,
                    Ok(n) => {
                        buf.truncate(n);
                        let next_pos = pos + n as u64;
                        Some((
                            Ok::<_, std::io::Error>(Bytes::from(buf)),
                            (f, next_pos, next_pos > end),
                        ))
                    }
                }
            });

        return Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_len),
            )
            .header(header::CONTENT_LENGTH, len.to_string())
            .body(Body::from_stream(file_stream))
            .unwrap());
    }

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

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

    Ok(Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, file_len.to_string())
        .body(Body::from_stream(file_stream))
        .unwrap())
}

fn parse_range(header: &str) -> Option<(u64, u64)> {
    let header = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = header.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;
    let end: u64 = if end_str.is_empty() {
        u64::MAX
    } else {
        end_str.parse().ok()?
    };
    Some((start, end))
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
