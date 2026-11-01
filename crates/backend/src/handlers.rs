use crate::AppState;
use crate::client::ClientIp;
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
    AccountProfileResponse, AccountRecord, AccountXWingKeyRequest, AccountXWingKeyResponse,
    CHUNK_SIZE, ChallengeResponse, ChangeNameRequest, ChangePasswordRequest, ChunkInfoResponse,
    CreatePasteHeader, FailedAttempt, GetPasteHeader, GetSaltResponse, GetStatsResponse,
    InboxResponse, InitPasteResponse, PasteAuthMode, PasteRecipientInfo, RecipientAuthChallenge,
    RecipientEnvelope, RegisterAccountRequest, UPLOAD_CHUNK_SIZE,
};
use mitsuzo_utils::{
    KeyEncapsulation, XWING_PUBLIC_KEY_SIZE, XWingKeyEncapsulation, generate_x25519_keypair,
    get_ciphertext_size, get_plaintext_size, kid_from_xwing_pubkey, seal_challenge,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::{Mutex, OnceLock};
use tokio::io::AsyncReadExt;
use tracing::info;

/// A static file plus its precomputed strong ETag.
struct StaticAsset {
    content: String,
    etag: String,
}

fn static_cache() -> &'static Mutex<HashMap<String, StaticAsset>> {
    static CACHE: OnceLock<Mutex<HashMap<String, StaticAsset>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
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

/// Read a file from the executable's `public/` directory, caching its content
/// and ETag. Assets are immutable for the process lifetime, so this avoids
/// re-reading and re-hashing them on every request.
fn load_static(name: &str) -> Result<StaticAsset, StatusCode> {
    if let Some(asset) = static_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(name)
    {
        return Ok(StaticAsset {
            content: asset.content.clone(),
            etag: asset.etag.clone(),
        });
    }

    let exe = std::env::current_exe().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let parent = exe.parent().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let content = fs::read_to_string(parent.join("public").join(name))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let asset = StaticAsset {
        etag: etag(&content),
        content,
    };
    static_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            name.to_string(),
            StaticAsset {
                content: asset.content.clone(),
                etag: asset.etag.clone(),
            },
        );
    Ok(asset)
}

fn index_html() -> Result<StaticAsset, StatusCode> {
    load_static("index.html")
}

fn static_response(headers: &HeaderMap, content: &str, tag: &str, content_type: &str) -> Response {
    let etag_value =
        HeaderValue::from_str(tag).unwrap_or_else(|_| HeaderValue::from_static("\"\""));
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
        .body(Body::from(content.to_owned()))
        .expect("valid response")
}

pub async fn serve_index(headers: HeaderMap) -> Result<Response, StatusCode> {
    let asset = index_html()?;
    Ok(static_response(
        &headers,
        &asset.content,
        &asset.etag,
        "text/html",
    ))
}

pub async fn fallback_to_index(headers: HeaderMap) -> Result<Response, StatusCode> {
    let asset = index_html()?;
    Ok(static_response(
        &headers,
        &asset.content,
        &asset.etag,
        "text/html",
    ))
}

const DEFAULT_ROBOTS_TXT: &str = "User-agent: *\nDisallow: /api\nDisallow: /paste\nDisallow: /p\n";

pub async fn robots_txt(headers: HeaderMap) -> Result<Response, StatusCode> {
    match load_static("robots.txt") {
        Ok(asset) => Ok(static_response(
            &headers,
            &asset.content,
            &asset.etag,
            "text/plain",
        )),
        Err(_) => {
            let tag = etag(DEFAULT_ROBOTS_TXT);
            Ok(static_response(
                &headers,
                DEFAULT_ROBOTS_TXT,
                &tag,
                "text/plain",
            ))
        }
    }
}

pub async fn install_script(headers: HeaderMap) -> Result<Response, StatusCode> {
    let asset = load_static("install.sh")?;
    Ok(static_response(
        &headers,
        &asset.content,
        &asset.etag,
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

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Authenticate an in-progress upload: the caller must present the per-paste
/// token issued by `POST /paste` in the `X-Upload-Token` header. Verified
/// against the stored `SHA-256(token)` in constant time.
async fn verify_upload_token(
    db: &crate::db::DataStore,
    id: &str,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    let Some(stored) = db.get_upload_token_hash(id).await else {
        // Legacy paste with no token on record, or unknown/expired id.
        return Err(StatusCode::FORBIDDEN);
    };
    let Some(provided) = headers
        .get("X-Upload-Token")
        .and_then(|value| value.to_str().ok())
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let token = general_purpose::STANDARD
        .decode(provided)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if constant_time_eq(&sha256(&token), &stored) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Remaining try count and TTL in seconds, read after a failed attempt so the
/// 401 response body can reflect the server's authoritative state.
async fn remaining_attempts(db: &crate::db::DataStore, id: &str) -> (u32, u64) {
    let Some(meta) = db.get_meta(id).await else {
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

async fn verify_password(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    client_ip: &str,
) -> Result<(), ApiError> {
    let Some(stored_hash) = state.db.get_password_hash(id).await else {
        return Err(ApiError::Status(StatusCode::NOT_FOUND));
    };
    let Some(provided_hash_str) = headers
        .get("X-Password-Hash")
        .and_then(|value| value.to_str().ok())
    else {
        record_password_failure(state, id, client_ip).await?;
        let (try_count, ttl) = remaining_attempts(&state.db, id).await;
        return Err(ApiError::Unauthorized { try_count, ttl });
    };
    let provided_hash = match general_purpose::STANDARD.decode(provided_hash_str) {
        Ok(h) => h,
        Err(_) => {
            record_password_failure(state, id, client_ip).await?;
            let (try_count, ttl) = remaining_attempts(&state.db, id).await;
            return Err(ApiError::Unauthorized { try_count, ttl });
        }
    };

    if !constant_time_eq(&provided_hash, &stored_hash) {
        record_password_failure(state, id, client_ip).await?;
        let (try_count, ttl) = remaining_attempts(&state.db, id).await;
        return Err(ApiError::Unauthorized { try_count, ttl });
    }
    Ok(())
}

async fn record_password_failure(
    state: &AppState,
    id: &str,
    client_ip: &str,
) -> Result<(), ApiError> {
    let ip_allowed = state
        .limiter
        .check(&format!("password-fail:ip:{client_ip}"), 30, 60)
        .await;
    let paste_allowed = state
        .limiter
        .check(&format!("password-fail:paste:{client_ip}:{id}"), 10, 60)
        .await;
    if !ip_allowed || !paste_allowed {
        return Err(ApiError::Status(StatusCode::TOO_MANY_REQUESTS));
    }
    state
        .db
        .decrement_try_count(id)
        .await
        .map_err(|_| ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?;
    state.db.increment_fail().await;
    Ok(())
}

// Client identity is resolved by the `ClientIp` extractor (see `crate::client`),
// which honors forwarded headers only when `MITSUZO_TRUST_PROXY` is enabled.

pub async fn init_paste(
    State(state): State<AppState>,
    client_ip: ClientIp,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip.0;
    if !state.limiter.check(&format!("init:{}", ip), 10, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let (mut header, xchacha_nonce, xwing_ciphertext) = if body
        .starts_with(mitsuzo_types::XWING_FORMAT_MARKER)
    {
        let request: mitsuzo_types::XWingCreatePasteRequest =
            decode(&body[8..]).map_err(|_| StatusCode::BAD_REQUEST)?;
        (
            request.header,
            request.xchacha_nonce,
            Some(request.xwing_ciphertext),
        )
    } else if body.starts_with(mitsuzo_types::XCHACHA_FORMAT_MARKER) {
        if body.len() < 32 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let header: CreatePasteHeader = decode(&body[32..]).map_err(|_| StatusCode::BAD_REQUEST)?;
        (
            header,
            Some(
                body[8..32]
                    .try_into()
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
            ),
            None,
        )
    } else {
        (
            decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?,
            None,
            None,
        )
    };

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
        if let Some(ciphertext) = xwing_ciphertext.as_ref() {
            if ciphertext.len() != mitsuzo_utils::XWING_CIPHERTEXT_SIZE {
                return Err(StatusCode::BAD_REQUEST);
            }
            let account = state
                .db
                .get_account_by_kid(&recipient.recipient_kid)
                .await
                .ok_or(StatusCode::BAD_REQUEST)?;
            if account.pubkey != recipient_pub
                || account
                    .xwing_pubkey
                    .as_deref()
                    .is_none_or(|key| kid_from_xwing_pubkey(key) != account.kid)
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            // Accept only X-Wing-marked recipient envelopes for new pastes.
            // Legacy X25519 envelopes remain readable, but cannot be created.
            return Err(StatusCode::BAD_REQUEST);
        }
    } else if xwing_ciphertext.is_some() {
        return Err(StatusCode::BAD_REQUEST);
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

    let mut upload_token = [0u8; 32];
    getrandom::fill(&mut upload_token).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let upload_token_hash = sha256(&upload_token);

    let id_str = state
        .db
        .create_paste(
            &header,
            xchacha_nonce,
            xwing_ciphertext.as_deref(),
            &upload_token_hash,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    info!(id = %id_str, "paste initialized");

    Ok(encode(&InitPasteResponse {
        id: id_str,
        upload_token,
    }))
}

pub async fn upload_chunk(
    State(state): State<AppState>,
    Path((id, chunk_index)): Path<(String, u32)>,
    client_ip: ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;
    // Uploads are separately rate-limited because a client can otherwise
    // initialize a small number of pastes and use unlimited chunk requests
    // to consume bandwidth/storage on a public demo.
    let ip = client_ip.0;
    if !state
        .limiter
        .check(&format!("upload:{}", ip), 180, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Only the sender that initialized the paste may write its chunks.
    verify_upload_token(&state.db, &id, &headers).await?;
    if body.len() > UPLOAD_CHUNK_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    // Enforce the configured maximum paste size across the whole upload.
    let max_cipher_len = get_ciphertext_size(state.config.max_file_size as usize) as u64;
    let write_end = u64::from(chunk_index) * UPLOAD_CHUNK_SIZE as u64 + body.len() as u64;
    if write_end > max_cipher_len {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if let Some(meta) = state.db.get_meta(&id).await {
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
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(())
}

pub async fn get_chunk_info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    validate_id(&id)?;
    if state.db.get_meta(&id).await.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let received = state.db.get_received_chunks(&id).await;
    Ok(encode(&ChunkInfoResponse { received }))
}

pub async fn complete_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    validate_id(&id)?;
    let Some(meta) = state.db.get_meta(&id).await else {
        return Err(StatusCode::NOT_FOUND);
    };
    verify_upload_token(&state.db, &id, &headers).await?;
    // Every chunk must have arrived before the paste is considered complete;
    // otherwise a partial upload would be served as if it were whole.
    if !state.db.upload_is_complete(&id, meta.total_chunks).await {
        return Err(StatusCode::CONFLICT);
    }
    info!(id = %id, "paste completed");
    Ok(StatusCode::OK)
}

/// Delete an in-progress paste when its creator cancels the upload. The
/// creator must present the per-paste upload token.
pub async fn cancel_paste(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    validate_id(&id)?;
    verify_upload_token(&state.db, &id, &headers).await?;
    state.db.delete_paste(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_salt(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    if !state
        .limiter
        .check(&format!("salt:{}", client_ip.0), 30, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    validate_id(&id)?;
    // Tells the client which authentication the paste uses: `salt: Some`
    // → password mode; `salt: None` → recipient/audience mode. Only the
    // salt field ever needs to be served without authentication — all other
    // metadata arrives in the authenticated /data metadata frame.
    let has_meta = state
        .db
        .get_meta(&id)
        .await
        .is_some_and(|m| m.expiration_timestamp == 0 || m.expiration_timestamp > epoch_secs());
    if !has_meta {
        return Err(StatusCode::NOT_FOUND);
    }
    let meta = state.db.get_meta(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    let raw_salt = state.db.get_salt(&id).await.unwrap_or_default();
    let recipient = if raw_salt.is_empty() {
        // Recipient/audience mode: say who can open it, pre-auth, so a client
        // can show "encrypted to <name> (0x…)" on page load.
        let recipient_kid = meta.recipient_kid.unwrap_or_default();
        let mut kid_prefix = [0u8; 20];
        kid_prefix.copy_from_slice(&recipient_kid[..20]);
        Some(PasteRecipientInfo {
            kid: recipient_kid,
            kid_prefix,
            name: None,
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
    client_ip: ClientIp,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    validate_id(&id)?;
    verify_password(&state, &id, &headers, &client_ip.0).await?;

    let nonce = state.db.get_nonce(&id).await.ok_or(StatusCode::NOT_FOUND)?;
    let file_path = state
        .db
        .get_content_path(&id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    let meta = state.db.get_meta(&id).await.ok_or(StatusCode::NOT_FOUND)?;

    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let content_len = file_meta.len() as usize;
    let total_size = get_plaintext_size(meta.total_chunks, content_len).unwrap_or(0) as u64;
    state.db.increment_success().await;

    let xchacha_nonce: Option<[u8; 24]> = if nonce.len() == 24 {
        Some(nonce.as_slice().try_into().unwrap())
    } else {
        None
    };
    let nonce_arr: [u8; 12] = nonce
        .get(..12)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .try_into()
        .unwrap();
    if nonce.len() != 12 && xchacha_nonce.is_none() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
    }
    let key = state.db.get_key(&id).await;
    let (try_count, ttl) = remaining_attempts(&state.db, &id).await;

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

    let head = match xchacha_nonce {
        Some(nonce) => header.encode_xchacha_frame(&nonce),
        None => header.encode_frame(),
    };

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
async fn resolve_account(
    db: &crate::db::DataStore,
    kid_str: &str,
) -> Result<Option<AccountRecord>, StatusCode> {
    let kid = parse_kid_hex(kid_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    match kid.len() {
        32 => {
            let mut full = [0u8; 32];
            full.copy_from_slice(&kid);
            Ok(db.get_account_by_kid(&full).await)
        }
        20 => {
            let mut prefix = [0u8; 20];
            prefix.copy_from_slice(&kid);
            Ok(db.get_account_by_prefix(&prefix).await)
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
    client_ip: ClientIp,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    if !state
        .limiter
        .check(&format!("challenge:{}", client_ip.0), 20, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    validate_id(&id)?;
    let meta = state
        .db
        .get_meta(&id)
        .await
        .filter(|m| m.expiration_timestamp == 0 || m.expiration_timestamp > epoch_secs())
        .ok_or(StatusCode::NOT_FOUND)?;
    let Some(recipient_pub) = meta.recipient_pub else {
        // Password-mode paste: there is no account challenge to issue.
        return Err(StatusCode::NOT_FOUND);
    };
    make_recipient_challenge(&state, format!("paste:{}", id), &recipient_pub).await
}

/// Parse an `X-Account-Proof: <kid>:<b64-response>` header into `(kid,
/// response)`. A missing header is `UNAUTHORIZED`; a malformed value is
/// `BAD_REQUEST`.
fn parse_account_proof(headers: &HeaderMap) -> Result<(Vec<u8>, Vec<u8>), StatusCode> {
    let proof = headers
        .get("X-Account-Proof")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (kid_str, resp_b64) = proof.split_once(':').ok_or(StatusCode::BAD_REQUEST)?;
    let kid = parse_kid_hex(kid_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    let response = general_purpose::STANDARD
        .decode(resp_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((kid, response))
}

/// Whether a presented proof kid (full 32-byte hash or 20-byte display prefix)
/// matches the expected account kid.
fn kid_matches(expected: &[u8], provided: &[u8]) -> bool {
    match provided.len() {
        20 => expected.len() >= 20 && &expected[..20] == provided,
        32 => expected.len() == 32 && expected == provided,
        _ => false,
    }
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
    let (kid_bytes, response) = match parse_account_proof(headers) {
        Ok(parsed) => parsed,
        // No proof presented: fall through to issuing a challenge.
        Err(StatusCode::UNAUTHORIZED) => return Ok(false),
        Err(status) => return Err(ApiError::Status(status)),
    };
    if !kid_matches(&recipient_kid, &kid_bytes) {
        return Ok(false);
    }
    Ok(state
        .challenges
        .verify_and_consume(&format!("paste:{}", id), &response)
        .await)
}

pub(crate) async fn get_paste_data(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    validate_id(&id)?;
    let meta = state
        .db
        .get_meta(&id)
        .await
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
                .await
                .ok_or(ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?,
        );
    } else {
        verify_password(&state, &id, &headers, &client_ip.0).await?;
    }

    let nonce = state
        .db
        .get_nonce(&id)
        .await
        .ok_or(ApiError::Status(StatusCode::NOT_FOUND))?;
    let xchacha_nonce: Option<[u8; 24]> = if nonce.len() == 24 {
        Some(nonce.as_slice().try_into().unwrap())
    } else {
        None
    };
    let nonce_arr: [u8; 12] = nonce
        .get(..12)
        .ok_or(ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR))?
        .try_into()
        .unwrap();
    if nonce.len() != 12 && xchacha_nonce.is_none() {
        return Err(ApiError::Status(StatusCode::INTERNAL_SERVER_ERROR));
    }

    let file_path = state
        .db
        .get_content_path(&id)
        .await
        .ok_or(ApiError::Status(StatusCode::NOT_FOUND))?;
    let file_meta = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| ApiError::Status(StatusCode::NOT_FOUND))?;
    let file_len = file_meta.len();
    state.db.increment_success().await;

    let (try_count, ttl) = remaining_attempts(&state.db, &id).await;
    let frame_header = GetPasteHeader {
        id: id.clone(),
        nonce: nonce_arr,
        data_type: meta.data_type.clone(),
        filename: meta.filename.clone(),
        content_type: meta.content_type.clone(),
        total_size: get_plaintext_size(meta.total_chunks, file_len as usize).unwrap_or(0) as u64,
        total_chunks: meta.total_chunks,
        allow_download: meta.allow_download,
        key: state.db.get_key(&id).await,
        try_count,
        ttl,
        burn_after_read: meta.burn_after_read,
        recipient: recipient_envelope,
    };
    let frame = if let Some(kem_ciphertext) = state.db.get_xwing_ciphertext(&id).await {
        frame_header.encode_xwing_frame(kem_ciphertext, xchacha_nonce)
    } else {
        match xchacha_nonce {
            Some(nonce) => frame_header.encode_xchacha_frame(&nonce),
            None => frame_header.encode_frame(),
        }
    };
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
    client_ip: ClientIp,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(), ApiError> {
    validate_id(&id)?;

    let ip = client_ip.0;
    if !state.limiter.check(&format!("passwd:{}", ip), 5, 60).await {
        return Err(ApiError::Status(StatusCode::TOO_MANY_REQUESTS));
    }

    // Reject like get_salt once the try-count is exhausted.
    if let Some(meta) = state.db.get_meta(&id).await
        && meta.try_count == 0
    {
        return Err(ApiError::Status(StatusCode::NOT_FOUND));
    }

    // Verifies the OLD password hash; on failure decrements try_count and
    // counts a failed request, same as the data endpoint.
    verify_password(&state, &id, &headers, &ip).await?;

    let request: ChangePasswordRequest = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .db
        .set_password(&id, &request.salt, &request.password_hash, &request.key)
        .await;
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
    client_ip: ClientIp,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<(), StatusCode> {
    validate_id(&id)?;

    let ip = client_ip.0;
    if !state.limiter.check(&format!("burn:{}", ip), 5, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(stored_hash) = state.db.get_burn_receipt_hash(&id).await else {
        return Err(StatusCode::NOT_FOUND);
    };

    if !constant_time_eq(&body, &stored_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !state.db.mark_burned(&id).await {
        return Err(StatusCode::GONE);
    }

    state.db.delete_paste(&id).await;
    info!(id = %id, "paste burned after read");
    Ok(())
}

/// Liveness probe: the process is up and serving.
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe: the process can reach its storage.
pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.db.is_healthy().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub async fn get_stats(State(state): State<AppState>) -> Result<Vec<u8>, StatusCode> {
    Ok(encode(&GetStatsResponse {
        pastes_all_time: state.db.get_pastes_all_time().await,
        pastes_daily: state.db.get_pastes_daily().await,
        requests_success_all_time: state.db.get_success_all_time().await,
        requests_success_daily: state.db.get_success_daily().await,
        requests_fail_all_time: state.db.get_fail_all_time().await,
        requests_fail_daily: state.db.get_fail_daily().await,
        demo_mode: state.config.demo_mode,
        max_ttl_seconds: state.config.max_ttl_seconds,
        max_file_size: state.config.max_file_size,
    }))
}

/// Register an X-Wing account. Its id is SHA-256 of its X-Wing public key; the
/// X25519 key remains the account-authentication key during this transition.
pub async fn register_account(
    State(state): State<AppState>,
    client_ip: ClientIp,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip.0;
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

    if request.xwing_pubkey.len() != XWING_PUBLIC_KEY_SIZE
        || XWingKeyEncapsulation::validate_public_key(&request.xwing_pubkey).is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let computed_kid = kid_from_xwing_pubkey(&request.xwing_pubkey);
    if !constant_time_eq(&computed_kid, &request.kid) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(existing) = state.db.get_account_by_kid(&request.kid).await {
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
        xwing_pubkey: Some(request.xwing_pubkey),
    };
    state.db.put_account(&record).await;
    info!(kid = %to_hex(&record.kid), "account registered");
    Ok(encode(&account_profile(&record)))
}

/// Public account profile. Accepts the full 32-byte kid or the 20-byte prefix.
pub async fn get_account(
    State(state): State<AppState>,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(encode(&account_profile(&record)))
}

/// Public X-Wing key used by senders to encapsulate a shared secret for this account.
pub async fn get_account_xwing_key(
    State(state): State<AppState>,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
        return Err(StatusCode::NOT_FOUND);
    };
    let public_key = record.xwing_pubkey.ok_or(StatusCode::NOT_FOUND)?;
    if kid_from_xwing_pubkey(&public_key) != record.kid {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(encode(&AccountXWingKeyResponse { public_key }))
}

/// Confirm the registered X-Wing key after proving control of the account's X25519 key.
/// The key cannot be rotated in place because it defines the account id.
pub async fn set_account_xwing_key(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Path(kid_str): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip.0;
    if !state.limiter.check(&format!("xwing:{}", ip), 20, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
        return Err(StatusCode::NOT_FOUND);
    };
    let request: AccountXWingKeyRequest = decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.public_key.len() != XWING_PUBLIC_KEY_SIZE {
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
    XWingKeyEncapsulation::validate_public_key(&request.public_key)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if kid_from_xwing_pubkey(&request.public_key) != record.kid {
        return Err(StatusCode::BAD_REQUEST);
    }
    if record.xwing_pubkey.as_deref() != Some(request.public_key.as_slice()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(encode(&AccountXWingKeyResponse {
        public_key: record.xwing_pubkey.unwrap_or_default(),
    }))
}

/// Issue a single-use login challenge sealed to the account's public key.
pub async fn get_account_challenge(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Path(kid_str): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip.0;
    if !state
        .limiter
        .check(&format!("challenge:{}", ip), 30, 60)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
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
    client_ip: ClientIp,
    Path(kid_str): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let ip = client_ip.0;
    if !state.limiter.check(&format!("name:{}", ip), 20, 60).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
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
    state.db.put_account(&updated).await;
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
    let Some(record) = resolve_account(&state.db, &kid_str).await? else {
        return Err(StatusCode::NOT_FOUND);
    };

    let (kid_bytes, response) = parse_account_proof(&headers)?;
    if !kid_matches(&record.kid, &kid_bytes) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let challenge_key = format!("acct:{}", to_hex(&record.kid));
    if !state
        .challenges
        .verify_and_consume(&challenge_key, &response)
        .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(encode(&InboxResponse {
        pastes: state.db.list_recipient_pastes(&record.kid).await,
    }))
}
