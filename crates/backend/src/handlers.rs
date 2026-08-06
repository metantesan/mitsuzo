use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose};
use bitcode::{decode, encode};
use futures::stream::{self, StreamExt};
use mitsuzo_types::{
    ChunkInfoResponse, CreatePasteHeader, GetPasteHeader, GetSaltResponse, GetStatsResponse,
    InitPasteResponse, UPLOAD_CHUNK_SIZE,
};
use mitsuzo_utils::get_plaintext_size;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::fs;
use tokio::io::AsyncReadExt;
use tracing::info;

fn index_html() -> Result<String, StatusCode> {
    public_file("index.html")
}

fn etag(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    format!(
        "\"{}\"",
        digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    )
}

fn static_response(headers: &HeaderMap, content: String, content_type: &str) -> Response {
    let tag = etag(&content);
    let etag_value =
        HeaderValue::from_str(&tag).unwrap_or_else(|_| HeaderValue::from_static("\"\""));
    if headers.get(header::IF_NONE_MATCH).map(|v| v.as_bytes()) == Some(tag.as_bytes()) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, etag_value)
            .body(Body::empty())
            .expect("empty body");
    }
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::ETAG, etag_value)
        .body(Body::from(content))
        .expect("valid response")
}

pub async fn serve_index(headers: HeaderMap) -> Result<Response, StatusCode> {
    Ok(static_response(&headers, index_html()?, "text/html"))
}

pub async fn fallback_to_index(headers: HeaderMap) -> Result<Response, StatusCode> {
    Ok(static_response(&headers, index_html()?, "text/html"))
}

const DEFAULT_ROBOTS_TXT: &str = "User-agent: *\nDisallow: /api\nDisallow: /paste\nDisallow: /p\n";

fn public_file(name: &str) -> Result<String, StatusCode> {
    let exe = std::env::current_exe().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let parent = exe.parent().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let path = parent.join("public").join(name);
    fs::read_to_string(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn robots_txt(headers: HeaderMap) -> Result<Response, StatusCode> {
    let content = public_file("robots.txt").unwrap_or_else(|_| DEFAULT_ROBOTS_TXT.to_string());
    Ok(static_response(&headers, content, "text/plain"))
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

fn verify_password(
    db: &crate::db::DataStore,
    id: &str,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
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

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub async fn init_paste(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip(&headers);
    if !state.limiter.check(&format!("init:{}", ip), 10, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let header: CreatePasteHeader = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if header.total_chunks == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let _ttl_seconds = match header.ttl_seconds {
        Some(ttl) => {
            if ttl == 0 {
                return Err(StatusCode::BAD_REQUEST);
            }
            Some(ttl.min(43200))
        }
        None => return Err(StatusCode::BAD_REQUEST),
    };

    let _try_count = match header.try_count {
        Some(count) if count > 0 && count <= 100 => count,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let mut rng = rand::rng();
    let mut id_str;
    let mut attempts = 0;
    loop {
        let id: u32 = rng.random_range(100_000..1_000_000);
        id_str = id.to_string();
        if !state.db.id_available(&id_str) {
            attempts += 1;
            if attempts >= 100 {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            continue;
        }
        break;
    }

    state
        .db
        .init_paste(&id_str, &header)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(id = %id_str, "paste initialized");

    Ok(encode(&InitPasteResponse { id: id_str }))
}

pub async fn upload_chunk(
    State(state): State<AppState>,
    Path((id, chunk_index)): Path<(String, u32)>,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;
    if body.len() > UPLOAD_CHUNK_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if state.db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    state
        .db
        .append_chunk(&id, chunk_index, &body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(())
}

pub async fn get_chunk_info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if state.db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let received = state.db.get_received_chunks(&id);
    Ok(encode(&ChunkInfoResponse { received }))
}

pub async fn complete_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if state.db.get_salt(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    info!(id = %id, "paste completed");
    Ok(encode(&InitPasteResponse { id }))
}

pub async fn get_salt(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    if let (Some(salt), Some(meta)) = (state.db.get_salt(&id), state.db.get_meta(&id)) {
        if meta.try_count == 0 {
            return Err(StatusCode::NOT_FOUND);
        }
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = if meta.expiration_timestamp > 0 && meta.expiration_timestamp > current_time {
            meta.expiration_timestamp - current_time
        } else {
            0
        };

        let content_len = state.db.get_content_size(&id).unwrap_or(0);
        let total_size =
            get_plaintext_size(meta.total_chunks, content_len as usize).unwrap_or(0) as u64;

        let nonce = state.db.get_nonce(&id).ok_or(StatusCode::NOT_FOUND)?;
        let nonce_arr: [u8; 12] = nonce
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let response = GetSaltResponse {
            salt,
            try_count: meta.try_count,
            ttl,
            total_chunks: meta.total_chunks,
            total_size,
            nonce: nonce_arr,
            data_type: meta.data_type,
            filename: meta.filename,
            content_type: meta.content_type,
            allow_download: meta.allow_download,
            burn_after_read: meta.burn_after_read,
        };
        Ok(encode(&response))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    validate_id(&id)?;
    verify_password(&state.db, &id, &headers)?;

    let nonce = state.db.get_nonce(&id).ok_or(StatusCode::NOT_FOUND)?;
    let file_path = state
        .db
        .get_content_path(&id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let meta = state.db.get_meta(&id).ok_or(StatusCode::NOT_FOUND)?;

    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let content_len = file_meta.len() as usize;
    let total_size = get_plaintext_size(meta.total_chunks, content_len).unwrap_or(0) as u64;
    state.db.increment_success();

    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let header = GetPasteHeader {
        id,
        nonce: nonce_arr,
        data_type: meta.data_type,
        filename: meta.filename,
        content_type: meta.content_type,
        total_size,
        total_chunks: meta.total_chunks,
        allow_download: meta.allow_download,
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
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    validate_id(&id)?;
    verify_password(&state.db, &id, &headers)?;

    let file_path = state
        .db
        .get_content_path(&id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let file_len = file_meta.len();
    state.db.increment_success();

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

        return Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_len),
            )
            .header(header::CONTENT_LENGTH, len.to_string())
            .body(Body::from_stream(file_stream))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
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

    Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, file_len.to_string())
        .body(Body::from_stream(file_stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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

pub async fn burn_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;

    let ip = client_ip(&headers);
    if !state.limiter.check(&format!("burn:{}", ip), 5, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(stored_hash) = state.db.get_burn_receipt_hash(&id) else {
        return Err(StatusCode::NOT_FOUND);
    };

    if !constant_time_eq(&body, &stored_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !state.db.mark_burned(&id) {
        return Err(StatusCode::GONE);
    }

    state.db.delete_paste(&id);
    info!(id = %id, "paste burned after read");
    Ok(())
}

pub async fn get_stats(State(state): State<AppState>) -> Result<Vec<u8>, StatusCode> {
    let stats = tokio::task::spawn_blocking(move || {
        (
            state.db.get_pastes_all_time(),
            state.db.get_pastes_daily(),
            state.db.get_success_all_time(),
            state.db.get_success_daily(),
            state.db.get_fail_all_time(),
            state.db.get_fail_daily(),
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(encode(&GetStatsResponse {
        pastes_all_time: stats.0,
        pastes_daily: stats.1,
        requests_success_all_time: stats.2,
        requests_success_daily: stats.3,
        requests_fail_all_time: stats.4,
        requests_fail_daily: stats.5,
    }))
}
