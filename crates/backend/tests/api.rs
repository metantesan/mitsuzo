//! HTTP-level integration tests for the API router.
//!
//! These drive the real Axum router with `tower::ServiceExt::oneshot`, so they
//! cover routing, extractors, auth, and the persistence layer together.
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use backend::db::DataStore;
use backend::rate_limit::RateLimiter;
use backend::routes::api_router;
use backend::{AppState, RuntimeConfig};
use base64::Engine as _;
use bitcode::encode;
use mitsuzo_types::{CreatePasteHeader, DataType, InitPasteResponse, KeyEnvelope};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn test_state(trust_proxy: bool) -> (AppState, PathBuf) {
    let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mitsuzo-api-test-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let db = DataStore::open(&dir).await.expect("open store");
    let config = RuntimeConfig {
        demo_mode: false,
        max_ttl_seconds: 43200,
        max_file_size: 64 * 1024 * 1024,
        trust_proxy,
        allowed_origins: vec![],
    };
    (AppState::new(db, RateLimiter::new(), config), dir)
}

fn password_header() -> CreatePasteHeader {
    CreatePasteHeader {
        nonce: [1u8; 12],
        salt: Some([9u8; 16]),
        password_hash: Some([7u8; 32]),
        key: Some(KeyEnvelope {
            wrap_nonce: [2u8; 12],
            wrapped_key: [3u8; 48],
        }),
        try_count: Some(5),
        ttl_seconds: Some(3600),
        data_type: DataType::Text,
        filename: None,
        content_type: None,
        total_chunks: 1,
        allow_download: true,
        burn_after_read: false,
        burn_receipt_hash: [4u8; 32],
        recipient: None,
        recipient_pub: None,
    }
}

/// Build a request with a socket peer (`ConnectInfo`) and optional headers.
fn request(
    method: Method,
    uri: &str,
    peer: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut req = builder.body(Body::from(body)).expect("build request");
    req.extensions_mut().insert(ConnectInfo(
        format!("{peer}:12345")
            .parse::<SocketAddr>()
            .expect("peer addr"),
    ));
    req
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body")
        .to_vec()
}

async fn init_paste(
    router: &axum::Router,
    peer: &str,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, Option<InitPasteResponse>) {
    let body = encode(&password_header());
    let response = router
        .clone()
        .oneshot(request(Method::POST, "/paste", peer, extra_headers, body))
        .await
        .expect("init request");
    let status = response.status();
    let decoded = if status.is_success() {
        bitcode::decode::<InitPasteResponse>(&body_bytes(response).await).ok()
    } else {
        None
    };
    (status, decoded)
}

#[tokio::test]
async fn upload_requires_token_and_completion_requires_all_chunks() {
    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.1";

    let (status, init) = init_paste(&router, peer, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let init = init.expect("init response");
    let id = init.id;
    let token = b64(&init.upload_token);

    // Completion of a paste with missing chunks is rejected.
    let complete_early = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/paste/{id}/complete"),
            peer,
            &[("x-upload-token", token.as_str())],
            vec![],
        ))
        .await
        .expect("complete request");
    assert_eq!(complete_early.status(), StatusCode::CONFLICT);

    // Chunk upload without the token is rejected.
    let no_token = router
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/paste/{id}/chunk/0"),
            peer,
            &[],
            vec![0u8; 32],
        ))
        .await
        .expect("upload request");
    assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);

    // Wrong token is rejected.
    let wrong_token = router
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/paste/{id}/chunk/0"),
            peer,
            &[("x-upload-token", b64(&[0u8; 32]).as_str())],
            vec![0u8; 32],
        ))
        .await
        .expect("upload request");
    assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

    // Correct token is accepted.
    let ok_upload = router
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/paste/{id}/chunk/0"),
            peer,
            &[("x-upload-token", token.as_str())],
            vec![0u8; 32],
        ))
        .await
        .expect("upload request");
    assert_eq!(ok_upload.status(), StatusCode::OK);

    // Now completion succeeds.
    let complete = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/paste/{id}/complete"),
            peer,
            &[("x-upload-token", token.as_str())],
            vec![],
        ))
        .await
        .expect("complete request");
    assert_eq!(complete.status(), StatusCode::OK);

    // The authenticated content fetch returns the metadata frame + ciphertext.
    let fetch = router
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/paste/{id}/data"),
            peer,
            &[("X-Password-Hash", b64(&[7u8; 32]).as_str())],
            vec![],
        ))
        .await
        .expect("data request");
    assert_eq!(fetch.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn cancelled_upload_requires_token_and_deletes_partial_paste() {
    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.45";
    let (status, paste) = init_paste(&router, peer, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let paste = paste.expect("init response");
    let paste_url = format!("/paste/{}/cancel", paste.id);

    let unauthorized = router
        .clone()
        .oneshot(request(Method::POST, &paste_url, peer, &[], vec![]))
        .await
        .expect("cancel without token");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let token = b64(&paste.upload_token);
    let cancelled = router
        .clone()
        .oneshot(request(
            Method::POST,
            &paste_url,
            peer,
            &[("x-upload-token", token.as_str())],
            vec![],
        ))
        .await
        .expect("cancel with token");
    assert_eq!(cancelled.status(), StatusCode::NO_CONTENT);

    let chunks = router
        .oneshot(request(
            Method::GET,
            &format!("/paste/{}/chunks", paste.id),
            peer,
            &[],
            vec![],
        ))
        .await
        .expect("query cancelled paste");
    assert_eq!(chunks.status(), StatusCode::NOT_FOUND);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn xchacha_password_paste_round_trip() {
    use mitsuzo_types::{encode_xchacha_create, split_paste_frame_with_nonce};
    use mitsuzo_utils::{decrypt_xchacha_chunk_into, encrypt_setup, encrypt_xchacha_chunk_into};
    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.42";
    let key = [42; 32];
    let nonce = [23; 24];
    let setup = encrypt_setup("a strong password", &key).unwrap();
    let mut header = password_header();
    header.salt = Some(setup.salt);
    header.password_hash = Some(setup.password_hash);
    header.key = Some(KeyEnvelope {
        wrap_nonce: setup.wrap_nonce,
        wrapped_key: setup.wrapped_key,
    });
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            "/paste/xchacha",
            peer,
            &[],
            encode_xchacha_create(&header, &nonce),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let init: InitPasteResponse = bitcode::decode(&body_bytes(response).await).unwrap();
    let token = b64(&init.upload_token);
    let mut ciphertext = Vec::new();
    encrypt_xchacha_chunk_into(b"xchacha test", &key, &nonce, 0, &mut ciphertext).unwrap();
    let response = router
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/paste/{}/chunk/0", init.id),
            peer,
            &[("x-upload-token", &token)],
            ciphertext,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/paste/{}/complete", init.id),
            peer,
            &[("x-upload-token", &token)],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth = b64(&setup.password_hash);
    let response = router
        .oneshot(request(
            Method::GET,
            &format!("/paste/{}/data", init.id),
            peer,
            &[("x-password-hash", &auth)],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let (meta, returned_nonce, _, encrypted, _) = split_paste_frame_with_nonce(&body).unwrap();
    assert_eq!(returned_nonce, Some(nonce));
    assert_eq!(meta.key.unwrap().wrapped_key, setup.wrapped_key);
    let mut plaintext = Vec::new();
    decrypt_xchacha_chunk_into(encrypted, &key, &nonce, 0, &mut plaintext).unwrap();
    assert_eq!(plaintext, b"xchacha test");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn blake3_integrity_requires_and_validates_eof_commitment() {
    use mitsuzo_types::{
        Blake3CreatePasteRequest, blake3_metadata_binding, encode_blake3_create,
        split_paste_frame_with_nonce,
    };
    use mitsuzo_utils::{
        Blake3CommitmentContext, ContentCipherKind, encrypt_blake3_commitment,
        encrypt_xchacha_chunk_into, verify_blake3_commitment,
    };

    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.45";
    let key = [52; 32];
    let nonce = [53; 24];
    let plaintext = b"integrity-v2 payload";
    let setup = mitsuzo_utils::encrypt_setup("integrity password", &key).unwrap();
    let mut header = password_header();
    header.salt = Some(setup.salt);
    header.password_hash = Some(setup.password_hash);
    header.key = Some(KeyEnvelope {
        wrap_nonce: setup.wrap_nonce,
        wrapped_key: setup.wrapped_key,
    });
    header.filename = Some("proof.txt".into());
    header.content_type = Some("text/plain".into());
    let body = encode_blake3_create(&Blake3CreatePasteRequest {
        header: header.clone(),
        xwing_ciphertext: None,
        xchacha_nonce: Some(nonce),
    });
    let response = router
        .clone()
        .oneshot(request(Method::POST, "/paste", peer, &[], body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let init: InitPasteResponse = bitcode::decode(&body_bytes(response).await).unwrap();
    let token = b64(&init.upload_token);

    let mut ciphertext = Vec::new();
    encrypt_xchacha_chunk_into(plaintext, &key, &nonce, 0, &mut ciphertext).unwrap();
    let metadata = blake3_metadata_binding(
        &init.id,
        &header.data_type,
        &header.filename,
        &header.content_type,
        header.total_chunks,
        plaintext.len() as u64,
        header.allow_download,
        header.burn_after_read,
    );
    encrypt_blake3_commitment(
        ContentCipherKind::XChaCha20Poly1305,
        &key,
        &nonce,
        Blake3CommitmentContext {
            paste_id: &init.id,
            total_chunks: header.total_chunks,
            plaintext_len: plaintext.len() as u64,
            metadata: &metadata,
        },
        &mitsuzo_utils::blake3_digest(plaintext).unwrap(),
        &mut ciphertext,
    )
    .unwrap();
    let response = router
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/paste/{}/chunk/0", init.id),
            peer,
            &[("x-upload-token", &token)],
            ciphertext,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/paste/{}/complete", init.id),
            peer,
            &[("x-upload-token", &token)],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let auth = b64(&setup.password_hash);
    let response = router
        .oneshot(request(
            Method::GET,
            &format!("/paste/{}/data", init.id),
            peer,
            &[("x-password-hash", &auth)],
            vec![],
        ))
        .await
        .unwrap();
    let body = body_bytes(response).await;
    let (meta, returned_nonce, _, encrypted, blake3_integrity) =
        split_paste_frame_with_nonce(&body).unwrap();
    assert!(blake3_integrity);
    assert_eq!(returned_nonce, Some(nonce));
    let commitment_offset = encrypted.len() - mitsuzo_types::BLAKE3_COMMITMENT_CIPHERTEXT_LEN;
    let metadata = blake3_metadata_binding(
        &meta.id,
        &meta.data_type,
        &meta.filename,
        &meta.content_type,
        meta.total_chunks,
        meta.total_size,
        meta.allow_download,
        meta.burn_after_read,
    );
    verify_blake3_commitment(
        ContentCipherKind::XChaCha20Poly1305,
        &key,
        &nonce,
        &encrypted[commitment_offset..],
        Blake3CommitmentContext {
            paste_id: &init.id,
            total_chunks: 1,
            plaintext_len: plaintext.len() as u64,
            metadata: &metadata,
        },
    )
    .unwrap();
    let mut recovered = Vec::new();
    mitsuzo_utils::decrypt_xchacha_chunk_into(
        &encrypted[..commitment_offset],
        &key,
        &nonce,
        0,
        &mut recovered,
    )
    .unwrap();
    assert_eq!(recovered, plaintext);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn failed_password_checks_are_rate_limited_per_ip_and_paste() {
    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.44";
    let mut header = password_header();
    header.try_count = Some(100);
    let response = router
        .clone()
        .oneshot(request(Method::POST, "/paste", peer, &[], encode(&header)))
        .await
        .expect("init request");
    assert_eq!(response.status(), StatusCode::OK);
    let paste: InitPasteResponse = bitcode::decode(&body_bytes(response).await).unwrap();

    for attempt in 0..10 {
        let response = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/paste/{}", paste.id),
                peer,
                &[("x-password-hash", &b64(&[0; 32]))],
                vec![],
            ))
            .await
            .expect("password check");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}"
        );
    }
    let blocked = router
        .oneshot(request(
            Method::GET,
            &format!("/paste/{}", paste.id),
            peer,
            &[("x-password-hash", &b64(&[0; 32]))],
            vec![],
        ))
        .await
        .expect("rate-limited password check");
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn rejects_new_x25519_only_recipient_pastes() {
    use mitsuzo_types::{RecipientEnvelope, encode_xchacha_create};

    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let mut header = password_header();
    header.salt = None;
    header.password_hash = None;
    header.key = None;
    header.try_count = None;
    header.recipient_pub = Some([42; 32]);
    header.recipient = Some(RecipientEnvelope {
        recipient_kid: [7; 32],
        ephemeral_pub: [8; 32],
        nonce: [9; 12],
        sealed_cek: [10; 48],
    });

    let response = router
        .oneshot(request(
            Method::POST,
            "/paste/xchacha",
            "203.0.113.43",
            &[],
            encode_xchacha_create(&header, &[11; 24]),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn xwing_recipient_paste_end_to_end_for_both_content_ciphers() {
    use mitsuzo_types::{
        AccountProfileResponse, AccountXWingKeyRequest, AccountXWingKeyResponse, ChallengeResponse,
        RecipientAuthChallenge, RecipientEnvelope, RegisterAccountRequest, XWingCreatePasteRequest,
        encode_xwing_create, split_paste_frame_with_nonce,
    };
    use mitsuzo_utils::{
        XWING_CIPHERTEXT_SIZE, decrypt_chunk_into, decrypt_xchacha_chunk_into,
        derive_xwing_account_public_key, encrypt_chunk_into, encrypt_xchacha_chunk_into,
        generate_x25519_keypair, open_challenge, open_content_key_for_xwing_account,
        open_content_key_for_xwing_shared, seal_content_key_for_xwing,
    };

    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.44";
    let (recipient_secret, recipient_pub) = generate_x25519_keypair().unwrap();
    let xwing_public_key = derive_xwing_account_public_key(&recipient_secret).unwrap();
    let kid = mitsuzo_utils::kid_from_xwing_pubkey(&xwing_public_key);
    let kid_hex: String = kid.iter().map(|b| format!("{b:02x}")).collect();

    let registration = RegisterAccountRequest {
        kid,
        pubkey: recipient_pub,
        xwing_pubkey: xwing_public_key.clone(),
        name: "X-Wing recipient".to_string(),
    };
    let mut x25519_only_registration = registration.clone();
    x25519_only_registration.xwing_pubkey.clear();
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            "/account",
            peer,
            &[],
            encode(&x25519_only_registration),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            "/account",
            peer,
            &[],
            encode(&registration),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _: AccountProfileResponse = bitcode::decode(&body_bytes(response).await).unwrap();

    let response = router
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/account/{kid_hex}/xwing"),
            peer,
            &[],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let registered_key: AccountXWingKeyResponse =
        bitcode::decode(&body_bytes(response).await).unwrap();
    assert_eq!(registered_key.public_key, xwing_public_key);
    let unauthenticated_update = AccountXWingKeyRequest {
        public_key: derive_xwing_account_public_key(&recipient_secret).unwrap(),
        challenge_response: [0; 32],
    };
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/account/{kid_hex}/xwing"),
            peer,
            &[],
            encode(&unauthenticated_update),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/account/{kid_hex}/challenge"),
            peer,
            &[],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: ChallengeResponse = bitcode::decode(&body_bytes(response).await).unwrap();
    let challenge_response = open_challenge(
        &recipient_secret,
        &challenge.ephemeral_pub,
        &challenge.nonce,
        &challenge.sealed,
    )
    .unwrap();
    let set_key = AccountXWingKeyRequest {
        public_key: xwing_public_key.clone(),
        challenge_response,
    };
    let response = router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/account/{kid_hex}/xwing"),
            peer,
            &[],
            encode(&set_key),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let saved: AccountXWingKeyResponse = bitcode::decode(&body_bytes(response).await).unwrap();
    assert_eq!(saved.public_key, xwing_public_key);

    let response = router
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/account/{kid_hex}/xwing"),
            peer,
            &[],
            vec![],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: AccountXWingKeyResponse = bitcode::decode(&body_bytes(response).await).unwrap();
    assert_eq!(fetched.public_key, xwing_public_key);

    for xchacha in [false, true] {
        let key = [if xchacha { 65 } else { 64 }; 32];
        let text = if xchacha {
            b"X-Wing XChaCha".as_slice()
        } else {
            b"X-Wing ChaCha".as_slice()
        };
        let mut base_nonce = [11u8; 12];
        base_nonce[0] = if xchacha { 2 } else { 1 };
        let xchacha_nonce = xchacha.then_some([21u8; 24]);
        let (shared_secret, kem_ciphertext, wrap_nonce, sealed_cek) =
            seal_content_key_for_xwing(&xwing_public_key, &key).unwrap();
        assert_eq!(kem_ciphertext.len(), XWING_CIPHERTEXT_SIZE);
        let mut header = password_header();
        header.nonce = base_nonce;
        header.salt = None;
        header.password_hash = None;
        header.key = None;
        header.try_count = None;
        header.recipient_pub = Some(recipient_pub);
        header.recipient = Some(RecipientEnvelope {
            recipient_kid: kid,
            ephemeral_pub: [0; 32],
            nonce: wrap_nonce,
            sealed_cek,
        });
        let request_body = encode_xwing_create(&XWingCreatePasteRequest {
            header,
            xwing_ciphertext: kem_ciphertext.clone(),
            xchacha_nonce,
        });
        let response = router
            .clone()
            .oneshot(request(Method::POST, "/paste", peer, &[], request_body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let init: InitPasteResponse = bitcode::decode(&body_bytes(response).await).unwrap();
        let token = b64(&init.upload_token);
        let mut ciphertext = Vec::new();
        if let Some(nonce) = xchacha_nonce {
            encrypt_xchacha_chunk_into(text, &key, &nonce, 0, &mut ciphertext).unwrap();
        } else {
            encrypt_chunk_into(text, &key, &base_nonce, 0, &mut ciphertext).unwrap();
        }
        let response = router
            .clone()
            .oneshot(request(
                Method::PUT,
                &format!("/paste/{}/chunk/0", init.id),
                peer,
                &[("x-upload-token", &token)],
                ciphertext,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/paste/{}/complete", init.id),
                peer,
                &[("x-upload-token", &token)],
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/paste/{}/challenge", init.id),
                peer,
                &[],
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: RecipientAuthChallenge =
            bitcode::decode(&body_bytes(response).await).unwrap();
        let answer = open_challenge(
            &recipient_secret,
            &challenge.challenge.ephemeral_pub,
            &challenge.challenge.nonce,
            &challenge.challenge.sealed,
        )
        .unwrap();
        let proof = format!("{}:{}", kid_hex, b64(&answer));
        let response = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/paste/{}/data", init.id),
                peer,
                &[("x-account-proof", &proof)],
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let (meta, returned_xnonce, returned_kem, encrypted, blake3_integrity) =
            split_paste_frame_with_nonce(&body).unwrap();
        assert!(!blake3_integrity);
        assert_eq!(returned_xnonce, xchacha_nonce);
        let returned_kem = returned_kem.expect("X-Wing frame marker and KEM ciphertext");
        assert_eq!(returned_kem, kem_ciphertext);
        let envelope = meta.recipient.unwrap();
        let recipient_key = open_content_key_for_xwing_account(
            &recipient_secret,
            &returned_kem,
            &envelope.nonce,
            &envelope.sealed_cek,
        )
        .unwrap();
        assert_eq!(recipient_key, key);
        let sender_key = open_content_key_for_xwing_shared(
            &shared_secret,
            &envelope.nonce,
            &envelope.sealed_cek,
        )
        .unwrap();
        assert_eq!(sender_key, key);
        let mut plaintext = Vec::new();
        if let Some(nonce) = returned_xnonce {
            decrypt_xchacha_chunk_into(encrypted, &recipient_key, &nonce, 0, &mut plaintext)
                .unwrap();
        } else {
            decrypt_chunk_into(encrypted, &recipient_key, &base_nonce, 0, &mut plaintext).unwrap();
        }
        assert_eq!(plaintext, text);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn untrusted_forwarded_for_does_not_bypass_rate_limit() {
    let (state, dir) = test_state(false).await;
    let router = api_router(state);
    let peer = "203.0.113.5";

    // Distinct spoofed X-Forwarded-For values on the same socket peer must not
    // grant fresh buckets: the 11th init (limit 10/60s) is rejected.
    let mut statuses = Vec::new();
    for i in 0..11 {
        let xff = format!("10.0.0.{i}");
        let (status, _) = init_paste(&router, peer, &[("X-Forwarded-For", xff.as_str())]).await;
        statuses.push(status);
    }
    assert!(
        statuses.iter().take(10).all(|s| s.is_success()),
        "first ten should succeed: {statuses:?}"
    );
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn trusted_forwarded_for_scopes_rate_limit_per_client() {
    let (state, dir) = test_state(true).await;
    let router = api_router(state);
    let peer = "203.0.113.5";

    // Distinct forwarded addresses are independent clients.
    for i in 0..11 {
        let xff = format!("10.0.0.{i}");
        let (status, _) = init_paste(&router, peer, &[("X-Forwarded-For", xff.as_str())]).await;
        assert!(status.is_success(), "request {i} failed with {status}");
    }

    // Reusing one forwarded address still hits its own limit.
    let mut same = Vec::new();
    for _ in 0..11 {
        let (status, _) = init_paste(&router, peer, &[("X-Forwarded-For", "10.0.0.99")]).await;
        same.push(status);
    }
    assert_eq!(same[10], StatusCode::TOO_MANY_REQUESTS);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn health_and_readiness_endpoints_report_ok() {
    let (state, dir) = test_state(false).await;
    let router = backend::routes::app_router(state);
    let peer = "127.0.0.1";

    let health = router
        .clone()
        .oneshot(request(Method::GET, "/healthz", peer, &[], vec![]))
        .await
        .expect("health request");
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(
        health.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        health.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(health.headers().get("x-frame-options").unwrap(), "DENY");
    let csp = health
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    assert!(csp.contains("style-src-attr 'unsafe-inline'"));
    assert!(csp.contains("connect-src 'self'"));

    let ready = router
        .clone()
        .oneshot(request(Method::GET, "/readyz", peer, &[], vec![]))
        .await
        .expect("ready request");
    assert_eq!(ready.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}
