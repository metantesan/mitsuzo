use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose};
use bitcode::{decode, encode};
use futures::stream::{self, StreamExt};
use mitsuzo_types::{
    AccountProfileResponse, AccountRecord, CHUNK_SIZE, ChallengeResponse, ChangeNameRequest,
    ChangePasswordRequest, ChunkInfoResponse, CreatePasteHeader, FailedAttempt, GetPasteHeader,
    GetSaltResponse, GetStatsResponse, InboxResponse, InitPasteResponse, PasteAuthMode,
    PasteRecipientInfo, RecipientAuthChallenge, RecipientEnvelope, RegisterAccountRequest,
    UPLOAD_CHUNK_SIZE,
};
use mitsuzo_utils::{
    generate_x25519_keypair, get_ciphertext_size, get_plaintext_size, kid_from_pubkey,
    seal_challenge,
};
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

pub async fn install_script(headers: HeaderMap) -> Result<Response, StatusCode> {
    Ok(static_response(
        &headers,
        public_file("install.sh")?,
        "text/plain; charset=utf-8",
    ))
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

/// Remaining try count and TTL in seconds, read after a failed attempt so the
/// 401 response body can reflect the server's authoritative state.
fn remaining_attempts(db: &crate::db::DataStore, id: &str) -> (u32, u64) {
    let Some(meta) = db.get_meta(id) else {
        return (0, 0);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = if meta.expiration_timestamp > 0 && meta.expiration_timestamp > now {
        meta.expiration_timestamp - now
    } else {
        0
    };
    (meta.try_count, ttl)
}

#[derive(Debug)]
pub(crate) enum ApiError {
    Status(StatusCode),
    Unauthorized { try_count: u32, ttl: u64 },
}

impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        ApiError::Status(status)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Status(status) => status.into_response(),
            ApiError::Unauthorized { try_count, ttl } => (
                StatusCode::UNAUTHORIZED,
                Bytes::from(encode(&FailedAttempt { try_count, ttl })),
            )
                .into_response(),
        }
    }
}

fn verify_password(
    db: &crate::db::DataStore,
    id: &str,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let Some(stored_hash) = db.get_password_hash(id) else {
        return Err(ApiError::Status(StatusCode::NOT_FOUND));
    };
    let Some(provided_hash_str) = headers
        .get("X-Password-Hash")
        .and_then(|value| value.to_str().ok())
    else {
        db.decrement_try_count(id);
        db.increment_fail();
        let (try_count, ttl) = remaining_attempts(db, id);
        return Err(ApiError::Unauthorized { try_count, ttl });
    };
    let provided_hash = match general_purpose::STANDARD.decode(provided_hash_str) {
        Ok(h) => h,
        Err(_) => {
            db.decrement_try_count(id);
            db.increment_fail();
            let (try_count, ttl) = remaining_attempts(db, id);
            return Err(ApiError::Unauthorized { try_count, ttl });
        }
    };

    if !constant_time_eq(&provided_hash, &stored_hash) {
        db.decrement_try_count(id);
        db.increment_fail();
        let (try_count, ttl) = remaining_attempts(db, id);
        return Err(ApiError::Unauthorized { try_count, ttl });
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

    let mut header: CreatePasteHeader = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if header.total_chunks == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Auth mode is inferred: recipient mode (recipient set, password fields
    // all None) xor password mode (all three password fields Some). Reject
    // mixed or empty credential sets.
    let recipient_mode = header.recipient.is_some();
    let password_mode = match (&header.salt, &header.password_hash, &header.key) {
        (Some(_), Some(_), Some(_)) => true,
        (None, None, None) => false,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    if recipient_mode == password_mode {
        return Err(StatusCode::BAD_REQUEST);
    }
    if recipient_mode {
        let Some(recipient_pub) = header.recipient_pub else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let Some(recipient) = &header.recipient else {
            return Err(StatusCode::BAD_REQUEST);
        };
        // If the recipient account exists, its public key must match the one
        // the client sealed to — otherwise the envelope cannot be opened.
        if let Some(account) = state.db.get_account_by_kid(&recipient.recipient_kid)
            && account.pubkey != recipient_pub
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    header.ttl_seconds = match header.ttl_seconds {
        Some(ttl) if ttl > 0 => Some(ttl.min(state.config.max_ttl_seconds.max(1))),
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Reject pastes whose estimated size exceeds the configured maximum before writing anything.
    let estimated_size = u64::from(header.total_chunks) * CHUNK_SIZE as u64;
    if estimated_size > state.config.max_file_size {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    if password_mode {
        let _try_count = match header.try_count {
            Some(count) if count > 0 && count <= 100 => count,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
    }

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
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;
    // Uploads are separately rate-limited because a client can otherwise
    // initialize a small number of pastes and use unlimited chunk requests
    // to consume bandwidth/storage on a public demo.
    let ip = client_ip(&headers);
    if !state
        .limiter
        .check(&format!("upload:{}", ip), 180, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if body.len() > UPLOAD_CHUNK_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    // Enforce the configured maximum paste size across the whole upload.
    let max_cipher_len = get_ciphertext_size(state.config.max_file_size as usize) as u64;
    let write_end = u64::from(chunk_index) * UPLOAD_CHUNK_SIZE as u64 + body.len() as u64;
    if write_end > max_cipher_len {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if let Some(meta) = state.db.get_meta(&id) {
        // Reject uploads to pastes that have already expired; cleanup may
        // not have deleted the row yet.
        if meta.expiration_timestamp > 0 && meta.expiration_timestamp <= epoch_secs() {
            return Err(StatusCode::NOT_FOUND);
        }
    } else {
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
    if state.db.get_meta(&id).is_none() {
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
    if state.db.get_meta(&id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    info!(id = %id, "paste completed");
    Ok(encode(&InitPasteResponse { id }))
}

pub async fn get_salt(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    // Tells the client which authentication the paste uses: `salt: Some`
    // → password mode; `salt: None` → recipient/audience mode. Only the
    // salt field ever needs to be served without authentication — all other
    // metadata arrives in the authenticated /data metadata frame.
    let has_meta = state
        .db
        .get_meta(&id)
        .is_some_and(|m| m.expiration_timestamp == 0 || m.expiration_timestamp > epoch_secs());
    if !has_meta {
        return Err(StatusCode::NOT_FOUND);
    }
    let meta = state.db.get_meta(&id).ok_or(StatusCode::NOT_FOUND)?;
    let raw_salt = state.db.get_salt(&id).unwrap_or_default();
    let recipient = if raw_salt.is_empty() {
        // Recipient/audience mode: say who can open it, pre-auth, so a client
        // can show "encrypted to <name> (0x…)" on page load.
        let recipient_kid = meta.recipient_kid.unwrap_or_default();
        let mut kid_prefix = [0u8; 20];
        kid_prefix.copy_from_slice(&recipient_kid[..20]);
        let name = meta
            .recipient_kid
            .and_then(|kid| state.db.get_account_by_kid(&kid))
            .map(|account| account.name);
        Some(PasteRecipientInfo {
            kid: recipient_kid,
            kid_prefix,
            name,
        })
    } else {
        None
    };
    Ok(encode(&GetSaltResponse {
        mode: if raw_salt.is_empty() {
            PasteAuthMode::Recipient
        } else {
            PasteAuthMode::Password
        },
        salt: if raw_salt.is_empty() {
            None
        } else {
            Some(raw_salt)
        },
        recipient,
    }))
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) async fn get_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
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
    let key = state.db.get_key(&id);
    let (try_count, ttl) = remaining_attempts(&state.db, &id);

    let header = GetPasteHeader {
        id,
        nonce: nonce_arr,
        data_type: meta.data_type,
        filename: meta.filename,
        content_type: meta.content_type,
        total_size,
        total_chunks: meta.total_chunks,
        allow_download: meta.allow_download,
        key,
        try_count,
        ttl,
        burn_after_read: meta.burn_after_read,
        recipient: None,
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode a hex account id, accepting an optional `0x` prefix and either the
/// full 32-byte hash or the 20-byte display prefix.
fn parse_kid_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || !s.len().is_multiple_of(2) || (s.len() != 40 && s.len() != 64) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| ())
}

/// Resolve an account record from a URL kid (full hash or display prefix).
fn resolve_account(
    db: &crate::db::DataStore,
    kid_str: &str,
) -> Result<Option<AccountRecord>, StatusCode> {
    let kid = parse_kid_hex(kid_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    match kid.len() {
        32 => {
            let mut full = [0u8; 32];
            full.copy_from_slice(&kid);
            Ok(db.get_account_by_kid(&full))
        }
        20 => {
            let mut prefix = [0u8; 20];
            prefix.copy_from_slice(&kid);
            Ok(db.get_account_by_prefix(&prefix))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

fn account_profile(record: &AccountRecord) -> AccountProfileResponse {
    let mut kid_prefix = [0u8; 20];
    kid_prefix.copy_from_slice(&record.kid[..20]);
    AccountProfileResponse {
        kid: record.kid,
        kid_prefix,
        pubkey: record.pubkey,
        name: record.name.clone(),
    }
}

/// Generate and store a single-use challenge sealed to a recipient public
/// key, returning the encoded `RecipientAuthChallenge`. The ephemeral
/// keypair + expected response are held in memory keyed by `key`.
async fn make_recipient_challenge(
    state: &AppState,
    key: String,
    recipient_pub: &[u8; 32],
) -> Result<Vec<u8>, StatusCode> {
    let (eph_priv, eph_pub) =
        generate_x25519_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (nonce, sealed) = seal_challenge(&eph_priv, recipient_pub, &secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state.challenges.insert(key, eph_priv, secret).await;
    Ok(encode(&RecipientAuthChallenge {
        challenge: ChallengeResponse {
            ephemeral_pub: eph_pub,
            nonce,
            sealed,
        },
    }))
}

/// Issue a fresh 401 challenge sealed to a recipient public key and return it
/// as the response body. Single-use: `verify_and_consume` removes it.
async fn issue_recipient_challenge(
    state: &AppState,
    key: String,
    recipient_pub: &[u8; 32],
) -> Result<Response<Body>, ApiError> {
    let body = make_recipient_challenge(state, key, recipient_pub)
        .await
        .map_err(ApiError::Status)?;
    Ok((StatusCode::UNAUTHORIZED, Bytes::from(body)).into_response())
}

/// Issue a single-use challenge for a recipient-mode paste so the client can
/// solve it and present `X-Account-Proof` directly on the next `/data`
/// request — no unauthenticated probe round needed.
pub async fn get_paste_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    let meta = state
        .db
        .get_meta(&id)
        .filter(|m| m.expiration_timestamp == 0 || m.expiration_timestamp > epoch_secs())
        .ok_or(StatusCode::NOT_FOUND)?;
    let Some(recipient_pub) = meta.recipient_pub else {
        // Password-mode paste: there is no account challenge to issue.
        return Err(StatusCode::NOT_FOUND);
    };
    make_recipient_challenge(&state, format!("paste:{}", id), &recipient_pub).await
}

/// Verify the `X-Account-Proof: <kid>:<b64-response>` header against the
/// paste's stored recipient. Single-use challenge is consumed on success.
async fn verify_recipient_proof(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    meta: &mitsuzo_types::PasteMeta,
) -> Result<bool, ApiError> {
    let Some(recipient_kid) = meta.recipient_kid else {
        return Ok(false);
    };
    let Some(proof) = headers.get("X-Account-Proof").and_then(|v| v.to_str().ok()) else {
        return Ok(false);
    };
    let (kid_str, resp_b64) = proof
        .split_once(':')
        .ok_or(ApiError::Status(StatusCode::BAD_REQUEST))?;
    let kid_bytes =
        parse_kid_hex(kid_str).map_err(|_| ApiError::Status(StatusCode::BAD_REQUEST))?;
    let response = general_purpose::STANDARD
        .decode(resp_b64)
        .map_err(|_| ApiError::Status(StatusCode::BAD_REQUEST))?;

    let audience_ok = match kid_bytes.len() {
        20 => &recipient_kid[..20] == kid_bytes.as_slice(),
        32 => recipient_kid.as_slice() == kid_bytes.as_slice(),
        _ => false,
    };
    if !audience_ok {
        return Ok(false);
    }
    Ok(state
        .challenges
        .verify_and_consume(&format!("paste:{}", id), &response)
        .await)
}

pub(crate) async fn get_paste_data(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    validate_id(&id)?;
    let meta = state
        .db
        .get_meta(&id)
        .ok_or(ApiError::Status(StatusCode::NOT_FOUND))?;
    // Enforce expiration for both auth modes. Password mode also gets this
    // via `get_password_hash`, but recipient mode would otherwise keep
    // serving an expired paste until the periodic cleanup removes it.
    if meta.expiration_timestamp > 0 && meta.expiration_timestamp <= epoch_secs() {
        return Err(ApiError::Status(StatusCode::NOT_FOUND));
    }

    // Recipient-mode pastes authenticate via the X-Account-Proof challenge
    // instead of X-Password-Hash. The proof is single-use and short-TTL.
    let mut recipient_envelope: Option<RecipientEnvelope> = None;
    if meta.recipient_pub.is_some() {
        let challenge_key = format!("paste:{}", id);
        if !verify_recipient_proof(&state, &id, &headers, &meta).await? {
            let recipient_pub = meta
                .recipient_pub
                .ok_or(ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
            return issue_recipient_challenge(&state, challenge_key, &recipient_pub).await;
        }
        recipient_envelope = Some(
            state
                .db
                .get_recipient_envelope(&id)
                .ok_or(ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?,
        );
    } else {
        verify_password(&state.db, &id, &headers)?;
    }

    let nonce = state
        .db
        .get_nonce(&id)
        .ok_or(ApiError::Status(StatusCode::NOT_FOUND))?;
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?;

    let file_path = state
        .db
        .get_content_path(&id)
        .ok_or(ApiError::Status(StatusCode::NOT_FOUND))?;
    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| ApiError::Status(StatusCode::NOT_FOUND))?;
    let file_len = file_meta.len();
    state.db.increment_success();

    let (try_count, ttl) = remaining_attempts(&state.db, &id);
    let frame = GetPasteHeader {
        id: id.clone(),
        nonce: nonce_arr,
        data_type: meta.data_type.clone(),
        filename: meta.filename.clone(),
        content_type: meta.content_type.clone(),
        total_size: get_plaintext_size(meta.total_chunks, file_len as usize).unwrap_or(0) as u64,
        total_chunks: meta.total_chunks,
        allow_download: meta.allow_download,
        key: state.db.get_key(&id),
        try_count,
        ttl,
        burn_after_read: meta.burn_after_read,
        recipient: recipient_envelope,
    }
    .encode_frame();
    let frame_len = frame.len() as u64;

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);

    if let Some((start, end)) = range {
        // Reject unsatisfiable ranges instead of letting `end - start + 1`
        // underflow into a bogus Content-Length.
        if file_len == 0 || start >= file_len {
            return Err(ApiError::Status(StatusCode::RANGE_NOT_SATISFIABLE));
        }
        let end = end.min(file_len - 1);
        if start > end {
            return Err(ApiError::Status(StatusCode::RANGE_NOT_SATISFIABLE));
        }
        let len = end - start + 1;

        let file = tokio::fs::File::open(&file_path)
            .await
            .map_err(|_| ApiError::Status(StatusCode::NOT_FOUND))?;

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

        let frame_stream = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(frame)) });
        // Content-Length includes the metadata frame prefix; Content-Range
        // stays in ciphertext coordinates so range math is unchanged.
        return Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_len),
            )
            .header(header::CONTENT_LENGTH, (frame_len + len).to_string())
            .body(Body::from_stream(frame_stream.chain(file_stream)))
            .map_err(|_| ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| ApiError::Status(StatusCode::NOT_FOUND))?;

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

    let frame_stream = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(frame)) });
    Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, (frame_len + file_len).to_string())
        .body(Body::from_stream(frame_stream.chain(file_stream)))
        .map_err(|_| ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))
}

pub(crate) async fn change_password(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    validate_id(&id)?;

    let ip = client_ip(&headers);
    if !state.limiter.check(&format!("passwd:{}", ip), 5, 60).await {
        return Err(ApiError::Status(StatusCode::TOO_MANY_REQUESTS));
    }

    // Reject like get_salt once the try-count is exhausted.
    if let Some(meta) = state.db.get_meta(&id)
        && meta.try_count == 0
    {
        return Err(ApiError::Status(StatusCode::NOT_FOUND));
    }

    // Verifies the OLD password hash; on failure decrements try_count and
    // counts a failed request, same as the data endpoint.
    verify_password(&state.db, &id, &headers)?;

    let request: ChangePasswordRequest = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .db
        .set_password(&id, &request.salt, &request.password_hash, &request.key);
    info!(id = %id, "paste password changed");
    Ok(())
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
        demo_mode: state.config.demo_mode,
        max_ttl_seconds: state.config.max_ttl_seconds,
        max_file_size: state.config.max_file_size,
    }))
}

/// Register a new account. The server recomputes `kid = SHA-256(pubkey)` and
/// rejects it if it does not match the submitted value (prevents squatting a
/// different account's namespace); 409 if the kid is already registered.
pub async fn register_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip(&headers);
    if !state.limiter.check(&format!("acct:{}", ip), 10, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let request: RegisterAccountRequest = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.name.is_empty()
        || request.name.len() > 64
        || request.name.chars().any(|c| c.is_control())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let computed_kid = kid_from_pubkey(&request.pubkey);
    if !constant_time_eq(&computed_kid, &request.kid) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(existing) = state.db.get_account_by_kid(&request.kid) {
        // Same key re-registered (e.g. restoring from a seed on another
        // machine): idempotent, return the existing profile unchanged.
        if constant_time_eq(&existing.pubkey, &request.pubkey) {
            return Ok(encode(&account_profile(&existing)));
        }
        return Err(StatusCode::CONFLICT);
    }

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let record = AccountRecord {
        kid: request.kid,
        pubkey: request.pubkey,
        name: request.name,
        created_at,
    };
    state.db.put_account(&record);
    info!(kid = %to_hex(&record.kid), "account registered");
    Ok(encode(&account_profile(&record)))
}

/// Public account profile. Accepts the full 32-byte kid or the 20-byte prefix.
pub async fn get_account(
    State(state): State<AppState>,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let Some(record) = resolve_account(&state.db, &kid_str)? else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(encode(&account_profile(&record)))
}

/// Issue a single-use login challenge sealed to the account's public key.
pub async fn get_account_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip(&headers);
    if !state
        .limiter
        .check(&format!("challenge:{}", ip), 30, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(record) = resolve_account(&state.db, &kid_str)? else {
        return Err(StatusCode::NOT_FOUND);
    };
    let (eph_priv, eph_pub) =
        generate_x25519_keypair().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (nonce, sealed) = seal_challenge(&eph_priv, &record.pubkey, &secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .challenges
        .insert(format!("acct:{}", to_hex(&record.kid)), eph_priv, secret)
        .await;
    Ok(encode(&ChallengeResponse {
        ephemeral_pub: eph_pub,
        nonce,
        sealed,
    }))
}

/// Change the account display name. Proves ownership by solving the
/// challenge issued by `GET /api/account/{kid}/challenge`.
pub async fn change_account_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(kid_str): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip(&headers);
    if !state.limiter.check(&format!("name:{}", ip), 20, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(record) = resolve_account(&state.db, &kid_str)? else {
        return Err(StatusCode::NOT_FOUND);
    };
    let request: ChangeNameRequest = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.name.is_empty()
        || request.name.len() > 64
        || request.name.chars().any(|c| c.is_control())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let challenge_key = format!("acct:{}", to_hex(&record.kid));
    if !state
        .challenges
        .verify_and_consume(&challenge_key, &request.challenge_response)
        .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut updated = record;
    updated.name = request.name;
    state.db.put_account(&updated);
    info!(kid = %to_hex(&updated.kid), "account name changed");
    Ok(encode(&account_profile(&updated)))
}

/// List recipient-mode pastes addressed to this account. Proves ownership by
/// solving the challenge issued by `GET /api/account/{kid}/challenge` and
/// sending the recovered nonce in an `X-Account-Proof: <kid>:<b64>` header.
pub async fn get_account_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let Some(record) = resolve_account(&state.db, &kid_str)? else {
        return Err(StatusCode::NOT_FOUND);
    };

    let Some(proof) = headers.get("X-Account-Proof").and_then(|v| v.to_str().ok()) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let (kid_str, resp_b64) = proof.split_once(':').ok_or(StatusCode::BAD_REQUEST)?;
    let kid_bytes = parse_kid_hex(kid_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    let audience_ok = match kid_bytes.len() {
        20 => &record.kid[..20] == kid_bytes.as_slice(),
        32 => record.kid.as_slice() == kid_bytes.as_slice(),
        _ => false,
    };
    if !audience_ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let response = general_purpose::STANDARD
        .decode(resp_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let challenge_key = format!("acct:{}", to_hex(&record.kid));
    if !state
        .challenges
        .verify_and_consume(&challenge_key, &response)
        .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(encode(&InboxResponse {
        pastes: state.db.list_recipient_pastes(&record.kid),
    }))
}
