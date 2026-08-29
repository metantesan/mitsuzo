use crate::BASE_URL;
use crate::Route;
use crate::account::{
    RecipientEphemeral, RecipientTarget, use_recipient_ephemerals, use_recipient_target,
};
use crate::components::PopupContext;
use crate::sanitize_id;
use crate::utils::{copy_to_clipboard, do_xhr_get, do_xhr_post, do_xhr_put};
use base64::Engine as _;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_i18n::t;
use gloo_timers::future::TimeoutFuture;
use mitsuzo_types::{
    AccountProfileResponse, CHUNK_SIZE, ChunkInfoResponse, CreatePasteHeader, DataType,
    GetStatsResponse, InitPasteResponse, KeyEnvelope, MAX_PASTE_SIZE, RecipientEnvelope,
    UPLOAD_CHUNK_SIZE,
};
use mitsuzo_utils::{
    compute_burn_receipt, encrypt_chunk_into, encrypt_setup, generate_content_key,
    generate_x25519_keypair, get_ciphertext_size, seal_content_key_for_recipient,
};
use wasm_bindgen::JsCast;
use web_sys;

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_size(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

fn format_duration(seconds: u32) -> String {
    if seconds >= 60 && seconds.is_multiple_of(60) {
        let mins = seconds / 60;
        if mins == 1 {
            "1 minute".to_string()
        } else {
            format!("{} minutes", mins)
        }
    } else {
        format!("{} seconds", seconds)
    }
}

#[derive(Clone, Debug)]
pub struct ProgressState {
    pub status: String,
    pub progress: f32,
}

#[derive(Clone, Copy, PartialEq)]
enum EncryptMode {
    Password,
    Account,
}

#[component]
pub fn home_view() -> Element {
    let mut content = use_signal(String::new);
    let mut password_input = use_signal(String::new);
    let mut try_count_preset = use_signal(|| "5".to_string());
    let mut try_count_custom = use_signal(|| "5".to_string());
    let mut generated_id: Signal<Option<String>> = use_signal(|| None);
    let mut bin_id_input = use_signal(String::new);
    let navigator = use_navigator();
    let mut file_data: Signal<Option<web_sys::File>> = use_signal(|| None);
    let mut file_name: Signal<Option<String>> = use_signal(|| None);
    let mut file_content_type: Signal<Option<String>> = use_signal(|| None);
    let mut progress: Signal<Option<ProgressState>> = use_signal(|| None);
    let mut popup_ctx = use_context::<Signal<PopupContext>>();
    let stats = use_context::<Signal<Option<GetStatsResponse>>>();
    let auto_generated = use_signal(|| false);
    let mut disable_download = use_signal(|| false);
    let mut burn_after_read = use_signal(|| false);
    let mut drag_over = use_signal(|| false);
    let mut ttl_preset = use_signal(|| "43200".to_string());
    let mut ttl_custom = use_signal(|| "43200".to_string());
    let recipient = use_recipient_target();
    let recipient_ephemerals = use_recipient_ephemerals();
    let mut recipient_search = use_signal(String::new);
    let mut encrypt_mode = use_signal(move || {
        if recipient.read().is_some() {
            EncryptMode::Account
        } else {
            EncryptMode::Password
        }
    });

    let cancel_recipient = {
        let mut recipient = recipient;
        move |_| {
            recipient.set(None);
        }
    };

    let search_recipient = {
        let mut recipient_search = recipient_search;
        let mut recipient = recipient;
        let mut popup_ctx = popup_ctx;
        move |_| {
            let query = recipient_search.read().trim().to_string();
            if query.is_empty() {
                popup_ctx.write().show_error(t!("user-not-found"));
                return;
            }
            spawn(async move {
                let url = format!("{}/api/account/{}", BASE_URL, query);
                match do_xhr_get(&url, vec![], |_, _| {}).await {
                    Ok(r) if r.status >= 200 && r.status < 300 => {
                        if let Some(body) = r.body
                            && let Ok(p) = bitcode::decode::<AccountProfileResponse>(&body)
                        {
                            recipient.set(Some(RecipientTarget {
                                kid: p.kid,
                                kid_prefix: p.kid_prefix,
                                pubkey: p.pubkey,
                                name: p.name.clone(),
                            }));
                            recipient_search.set(String::new());
                            popup_ctx
                                .write()
                                .show_success(t!("recipient-found", name: p.name));
                        } else {
                            popup_ctx.write().show_error(t!("user-not-found"));
                        }
                    }
                    _ => popup_ctx.write().show_error(t!("user-not-found")),
                }
            });
        }
    };

    let mut ttl_initialized = use_signal(|| false);
    use_effect({
        let mut ttl_preset = ttl_preset;
        let mut ttl_custom = ttl_custom;
        move || {
            if *ttl_initialized.read() {
                return;
            }
            let stats_guard = stats.read();
            let Some(s) = stats_guard.as_ref() else {
                return;
            };
            ttl_initialized.set(true);
            if s.max_ttl_seconds >= 43200 {
                return;
            }
            let default = s.max_ttl_seconds.min(43200).to_string();
            if ttl_preset.read().as_str() == "43200" {
                ttl_preset.set(default.clone());
            }
            if ttl_custom.read().as_str() == "43200" {
                ttl_custom.set(default);
            }
        }
    });

    let ttl_presets: Vec<(u32, String)> = {
        let max_ttl = stats
            .read()
            .as_ref()
            .map(|s| s.max_ttl_seconds)
            .unwrap_or(43200);
        let mut presets: Vec<(u32, String)> = Vec::new();
        if max_ttl >= 60 {
            presets.push((60, t!("ttl-1min")));
        }
        if max_ttl >= 300 {
            presets.push((300, t!("ttl-5min")));
        }
        if max_ttl >= 1800 {
            presets.push((1800, t!("ttl-30min")));
        }
        if max_ttl >= 3600 {
            presets.push((3600, t!("ttl-1hour")));
        }
        if max_ttl >= 21600 {
            presets.push((21600, t!("ttl-6hour")));
        }
        if max_ttl >= 43200 {
            presets.push((43200, t!("ttl-12hour")));
        }
        if presets.is_empty() {
            presets.push((max_ttl.max(1), t!("ttl-1min")));
        }
        presets
    };

    let demo_mode = stats.read().as_ref().map(|s| s.demo_mode).unwrap_or(false);
    let demo_ttl_text = format_duration(
        stats
            .read()
            .as_ref()
            .map(|s| s.max_ttl_seconds)
            .unwrap_or(43200),
    );
    let demo_size_text = format_size(
        stats
            .read()
            .as_ref()
            .map(|s| s.max_file_size)
            .unwrap_or(MAX_PASTE_SIZE as u64),
    );

    let create_paste = {
        let mut auto_generated = auto_generated;
        let disable_download = disable_download;
        let mut recipient_ephemerals = recipient_ephemerals;
        move |_| {
            spawn(async move {
                let mode = *encrypt_mode.read();
                let recipient_info = recipient.read().clone();
                let password = password_input.read().clone();
                let password_mode = mode == EncryptMode::Password;
                // Account mode has no password at all; password mode
                // auto-generates one when the field is left empty.
                auto_generated.set(password_mode && password.is_empty());
                let password = if password_mode && password.is_empty() {
                    let mut buf = [0u8; 16];
                    let _ = getrandom::fill(&mut buf);
                    let auto_pw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
                    password_input.set(auto_pw.clone());
                    auto_pw
                } else {
                    password
                };

                if !password_mode && recipient_info.is_none() {
                    popup_ctx.write().show_error(t!("recipient-required"));
                    return;
                }

                progress.set(Some(ProgressState {
                    status: t!("progress-validating"),
                    progress: 10.0,
                }));

                let try_count_value = if try_count_preset.read().as_str() == "custom" {
                    try_count_custom.read().clone()
                } else {
                    try_count_preset.read().clone()
                };
                let try_count = try_count_value.parse::<u32>().ok();
                let ttl_value = if ttl_preset.read().as_str() == "custom" {
                    ttl_custom.read().clone()
                } else {
                    ttl_preset.read().clone()
                };
                let max_ttl = stats
                    .read()
                    .as_ref()
                    .map(|s| s.max_ttl_seconds)
                    .unwrap_or(43200);
                let mut ttl_seconds_option = ttl_value.parse::<u32>().ok();
                if let Some(ref mut ts) = ttl_seconds_option {
                    if *ts > max_ttl {
                        *ts = max_ttl;
                    }
                } else {
                    popup_ctx.write().show_error(t!("error-ttl-invalid"));
                    progress.set(None);
                    return;
                }

                let max_size = stats
                    .read()
                    .as_ref()
                    .map(|s| s.max_file_size)
                    .unwrap_or(MAX_PASTE_SIZE as u64);
                let file_size_for_chunks: u64;
                let data_type: DataType;
                let mut text_fallback: Option<Vec<u8>> = None;
                if let Some(f) = file_data.read().as_ref() {
                    if f.size() as u64 > max_size {
                        popup_ctx.write().show_error(t!(
                            "error-file-too-large",
                            size: format_size(max_size)
                        ));
                        progress.set(None);
                        return;
                    }
                    progress.set(Some(ProgressState {
                        status: t!("progress-processing-file"),
                        progress: 20.0,
                    }));
                    file_size_for_chunks = f.size() as u64;
                    data_type = DataType::File;
                } else {
                    let text_content = content.read().clone();
                    if text_content.is_empty() {
                        popup_ctx.write().show_error(t!("error-content-empty"));
                        progress.set(None);
                        return;
                    }
                    if text_content.len() as u64 > max_size {
                        popup_ctx.write().show_error(t!(
                            "error-file-too-large",
                            size: format_size(max_size)
                        ));
                        progress.set(None);
                        return;
                    }
                    progress.set(Some(ProgressState {
                        status: t!("progress-processing-text"),
                        progress: 20.0,
                    }));
                    file_size_for_chunks = text_content.len() as u64;
                    data_type = DataType::Text;
                    text_fallback = Some(text_content.into_bytes());
                }

                let content_key = match generate_content_key() {
                    Ok(k) => k,
                    Err(e) => {
                        popup_ctx
                            .write()
                            .show_error(t!("error-encryption-failed", error: e.to_string()));
                        progress.set(None);
                        return;
                    }
                };

                let total_chunks = if file_size_for_chunks == 0 {
                    1
                } else {
                    (file_size_for_chunks as usize).div_ceil(CHUNK_SIZE) as u32
                };

                let (header, session_ephemeral): (CreatePasteHeader, Option<([u8; 32], [u8; 32])>) =
                    if !password_mode {
                        // Recipient mode: seal the CEK to the recipient's
                        // public key. Both the recipient (via account scalar)
                        // and the sender (via the ephemeral key held in memory)
                        // can reopen this envelope.
                        let Some(target) = recipient_info.as_ref() else {
                            return;
                        };
                        let mut base_nonce = [0u8; 12];
                        let _ = getrandom::fill(&mut base_nonce);
                        let (eph_priv, eph_pub) = match generate_x25519_keypair() {
                            Ok(pair) => pair,
                            Err(e) => {
                                popup_ctx.write().show_error(t!(
                                    "error-encryption-failed",
                                    error: e.to_string()
                                ));
                                progress.set(None);
                                return;
                            }
                        };
                        let (env_nonce, sealed_cek) = match seal_content_key_for_recipient(
                            &eph_priv,
                            &target.pubkey,
                            &content_key,
                        ) {
                            Ok(pair) => pair,
                            Err(e) => {
                                popup_ctx.write().show_error(t!(
                                    "error-encryption-failed",
                                    error: e.to_string()
                                ));
                                progress.set(None);
                                return;
                            }
                        };
                        let header = CreatePasteHeader {
                            nonce: base_nonce,
                            salt: None,
                            password_hash: None,
                            key: None,
                            try_count: None,
                            ttl_seconds: ttl_seconds_option,
                            data_type,
                            filename: file_name.read().clone(),
                            content_type: file_content_type.read().clone(),
                            total_chunks,
                            allow_download: !*disable_download.read(),
                            burn_after_read: *burn_after_read.read(),
                            burn_receipt_hash: if *burn_after_read.read() {
                                compute_burn_receipt(&content_key)
                            } else {
                                [0u8; 32]
                            },
                            recipient: Some(RecipientEnvelope {
                                recipient_kid: target.kid,
                                ephemeral_pub: eph_pub,
                                nonce: env_nonce,
                                sealed_cek,
                            }),
                            recipient_pub: Some(target.pubkey),
                        };
                        (header, Some((target.kid, eph_priv)))
                    } else {
                        let setup = match encrypt_setup(&password, &content_key) {
                            Ok(data) => data,
                            Err(e) => {
                                popup_ctx.write().show_error(t!(
                                    "error-encryption-failed",
                                    error: e.to_string()
                                ));
                                progress.set(None);
                                return;
                            }
                        };
                        let salt_bytes = setup.salt;
                        let nonce_bytes = setup.base_nonce;
                        let password_hash = setup.password_hash;
                        let header = CreatePasteHeader {
                            nonce: nonce_bytes,
                            salt: Some(salt_bytes),
                            password_hash: Some(password_hash),
                            key: Some(KeyEnvelope {
                                wrap_nonce: setup.wrap_nonce,
                                wrapped_key: setup.wrapped_key,
                            }),
                            try_count,
                            ttl_seconds: ttl_seconds_option,
                            data_type,
                            filename: file_name.read().clone(),
                            content_type: file_content_type.read().clone(),
                            total_chunks,
                            allow_download: !*disable_download.read(),
                            burn_after_read: *burn_after_read.read(),
                            burn_receipt_hash: if *burn_after_read.read() {
                                compute_burn_receipt(&content_key)
                            } else {
                                [0u8; 32]
                            },
                            recipient: None,
                            recipient_pub: None,
                        };
                        (header, None)
                    };
                let encryption_key = content_key;
                let nonce_bytes = header.nonce;

                let header_bytes = bitcode::encode(&header);

                progress.set(Some(ProgressState {
                    status: t!("progress-encrypting"),
                    progress: 30.0,
                }));

                let mut enc_body = Vec::new();
                let js_file = file_data.read().as_ref().cloned();

                match (text_fallback, js_file) {
                    (Some(text_bytes), _) => {
                        let chunk_size = get_ciphertext_size(text_bytes.len());
                        enc_body.reserve(chunk_size);
                        if let Err(e) = encrypt_chunk_into(
                            &text_bytes,
                            &encryption_key,
                            &nonce_bytes,
                            0,
                            &mut enc_body,
                        ) {
                            popup_ctx
                                .write()
                                .show_error(t!("error-encryption-failed", error: e.to_string()));
                            progress.set(None);
                            return;
                        }
                    }
                    (_, Some(file)) => {
                        let total_cipher_size = get_ciphertext_size(file_size_for_chunks as usize);
                        enc_body.reserve(total_cipher_size);
                        for i in 0..total_chunks {
                            if i % 8 == 0 {
                                TimeoutFuture::new(0).await;
                                let pct = 30.0 + (i as f32 / total_chunks as f32) * 20.0;
                                progress.set(Some(ProgressState {
                                    status: t!("progress-encrypting-percent", percent: format!("{:.0}", pct)),
                                    progress: pct,
                                }));
                            }

                            let start = i as u64 * CHUNK_SIZE as u64;
                            let end =
                                std::cmp::min(start + CHUNK_SIZE as u64, file_size_for_chunks);
                            let blob = file
                                .slice_with_f64_and_f64(start as f64, end as f64)
                                .map_err(|_| "slice failed".to_string())
                                .unwrap();
                            let g_blob: gloo_file::Blob = blob.into();
                            let chunk_bytes = gloo_file::futures::read_as_bytes(&g_blob)
                                .await
                                .map_err(|_| "read failed".to_string())
                                .unwrap();
                            if let Err(e) = encrypt_chunk_into(
                                &chunk_bytes,
                                &encryption_key,
                                &nonce_bytes,
                                i,
                                &mut enc_body,
                            ) {
                                popup_ctx.write().show_error(
                                    t!("error-encryption-failed", error: e.to_string()),
                                );
                                progress.set(None);
                                return;
                            }
                        }
                    }
                    _ => {}
                }

                progress.set(Some(ProgressState {
                    status: t!("progress-initiating-upload"),
                    progress: 50.0,
                }));

                let init_result =
                    do_xhr_post(&format!("{}/api/paste", BASE_URL), header_bytes, |_, _| {}).await;

                let paste_id = match init_result {
                    Ok(response) if response.status >= 200 && response.status < 300 => {
                        match response
                            .body
                            .and_then(|b| bitcode::decode::<InitPasteResponse>(&b).ok())
                        {
                            Some(r) => r.id,
                            None => {
                                popup_ctx.write().show_error(
                                    t!("error-parse-response-failed", error: "init response"),
                                );
                                progress.set(None);
                                return;
                            }
                        }
                    }
                    _ => {
                        popup_ctx
                            .write()
                            .show_error(t!("error-create-paste-failed", status: "init"));
                        progress.set(None);
                        return;
                    }
                };

                let total_upload_chunks = enc_body.len().div_ceil(UPLOAD_CHUNK_SIZE);

                // Remember the sender's ephemeral key so this session can
                // reopen the paste (ECDH symmetry with the recipient).
                if let Some((kid, eph_priv)) = session_ephemeral {
                    recipient_ephemerals.write().push(RecipientEphemeral {
                        paste_id: paste_id.clone(),
                        recipient_kid: kid,
                        ephemeral_priv: eph_priv,
                    });
                }

                let chunk_info = do_xhr_get(
                    &format!("{}/api/paste/{}/chunks", BASE_URL, paste_id),
                    vec![],
                    |_, _| {},
                )
                .await;
                let start_chunk = match chunk_info {
                    Ok(r) if r.status >= 200 && r.status < 300 => r
                        .body
                        .as_ref()
                        .and_then(|b| bitcode::decode::<ChunkInfoResponse>(b).ok())
                        .map(|c| c.received)
                        .unwrap_or(0),
                    _ => 0,
                };

                let mut last_update = 0.0;
                for i in start_chunk..total_upload_chunks as u32 {
                    let chunk_start = i as usize * UPLOAD_CHUNK_SIZE;
                    let chunk_end = std::cmp::min(chunk_start + UPLOAD_CHUNK_SIZE, enc_body.len());
                    let chunk_data = enc_body[chunk_start..chunk_end].to_vec();

                    let upload_result = do_xhr_put(
                        &format!("{}/api/paste/{}/chunk/{}", BASE_URL, paste_id, i),
                        chunk_data,
                        |loaded, total| {
                            if total > 0 {
                                let chunk_pct = loaded as f32 / total as f32;
                                let overall = 50.0 + ((i as f32 + chunk_pct) / total_upload_chunks as f32) * 40.0;
                                if overall - last_update > 1.0 {
                                    last_update = overall;
                                    progress.set(Some(ProgressState {
                                        status: t!("progress-upload-percent", percent: format!("{:.0}", (overall - 50.0) / 40.0 * 100.0)),
                                        progress: overall,
                                    }));
                                }
                            }
                        },
                    ).await;

                    match upload_result {
                        Ok(r) if r.status >= 200 && r.status < 300 => {}
                        _ => {
                            popup_ctx.write().show_error(
                                t!("error-create-paste-failed", status: format!("chunk {}", i)),
                            );
                            progress.set(None);
                            return;
                        }
                    }
                }

                progress.set(Some(ProgressState {
                    status: t!("progress-finalizing"),
                    progress: 95.0,
                }));

                let complete_result = do_xhr_post(
                    &format!("{}/api/paste/{}/complete", BASE_URL, paste_id),
                    Vec::new(),
                    |_, _| {},
                )
                .await;

                match complete_result {
                    Ok(response) if response.status >= 200 && response.status < 300 => {
                        generated_id.set(Some(paste_id));
                        progress.set(Some(ProgressState {
                            status: t!("progress-upload-complete"),
                            progress: 100.0,
                        }));
                    }
                    _ => {
                        popup_ctx
                            .write()
                            .show_error(t!("error-create-paste-failed", status: "complete"));
                        progress.set(None);
                    }
                }
            });
        }
    };

    let go_to_paste = move |_| {
        let id = sanitize_id(&bin_id_input.read().clone());
        if !id.is_empty() {
            navigator.push(Route::Paste { id });
        }
    };

    let file_size_text = move || {
        file_data
            .read()
            .as_ref()
            .map(|f| format!("({:.1} KB)", f.size() as f32 / 1024.0))
            .unwrap_or_default()
    };

    let account_mode = *encrypt_mode.read() == EncryptMode::Account;

    rsx! {
        div {
            class: if *drag_over.read() { "max-w-2xl mx-auto px-4 py-8 flex flex-col items-center justify-center min-h-[calc(100vh-3.5rem)] rounded-2xl border-2 border-dashed border-accent/50 transition-all duration-200" } else { "max-w-2xl mx-auto px-4 py-8 flex flex-col items-center justify-center min-h-[calc(100vh-3.5rem)] transition-all duration-200" },
            ondragover: move |evt| {
                evt.prevent_default();
                drag_over.set(true);
            },
            ondragleave: move |_| {
                drag_over.set(false);
            },
            ondrop: move |evt| {
                evt.prevent_default();
                drag_over.set(false);
                let files = evt.files();
                if let Some(file) = files.into_iter().next()
                    && let Some(web_file) = file.inner().downcast_ref::<web_sys::File>().cloned()
                {
                    progress.set(Some(ProgressState { status: t!("progress-file-loaded"), progress: 100.0 }));
                    file_data.set(Some(web_file));
                    file_name.set(Some(file.name()));
                    file_content_type.set(file.content_type());
                }
            },
            h1 {
                class: "text-4xl font-bold text-text mb-10 tracking-tight animate-glow-pulse",
                {t!("app-title")}
            }

            if demo_mode {
                div {
                    class: "w-full max-w-xl mb-6 p-4 bg-surface border border-accent rounded-lg text-center",
                    p {
                        class: "text-sm font-semibold text-accent",
                        {t!("demo-banner-text", ttl: demo_ttl_text, size: demo_size_text)}
                    }
                }
            }

            if let Some(prog) = progress.read().as_ref() {
                div {
                    class: "w-full max-w-xl mb-4 p-4 bg-surface rounded-lg",
                    div {
                        class: "text-sm font-semibold mb-2 text-text text-center",
                        "{prog.status}"
                    }
                    div {
                        class: "w-full bg-surface rounded-full h-3",
                        div {
                            class: "bg-accent h-3 rounded-full transition-all duration-150",
                            style: "width: {prog.progress}%"
                        }
                    }
                }
            }

            if account_mode
                && let Some(target) = recipient.read().as_ref()
            {
                div {
                    class: "w-full max-w-xl mb-4 p-4 bg-accent/15 border border-accent rounded-lg flex justify-between items-center",
                    span {
                        class: "text-sm font-semibold text-accent",
                        {t!("recipient-banner", name: target.name.clone(), kid: target.kid_prefix_hex())}
                    }
                    button {
                        class: "text-sm text-muted hover:text-danger transition-colors",
                        onclick: cancel_recipient,
                        {t!("recipient-cancel")}
                    }
                }
            }

            if let Some(name) = file_name.read().as_ref() {
                div {
                    class: "w-full max-w-xl p-4 mb-4 bg-surface text-text rounded-lg flex justify-between items-center",
                    span { "{name}" }
                    span {
                        class: "text-muted text-sm ml-2",
                        "{file_size_text()}"
                    }
                    button {
                        class: "text-danger hover:text-danger-hover",
                        onclick: move |_| {
                            file_name.set(None);
                            file_data.set(None);
                            file_content_type.set(None);
                            progress.set(None);
                        },
                        {t!("clear")}
                    }
                }
            } else {
                textarea {
                    class: "w-full max-w-xl p-4 mb-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                    rows: "10",
                    oninput: move |evt| content.set(evt.value()),
                    placeholder: "{t!(\"home-placeholder\")}",
                    value: "{content}"
                }
            }

            div {
                class: "w-full max-w-xl mb-4",
                label {
                    class: "block text-muted text-sm font-bold mb-2",
                    "for": "file-upload",
                    {t!("or-upload-file")}
                }
                div {
                    class: "relative",
                    input {
                        class: "hidden",
                        id: "file-upload",
                        r#type: "file",
                        onchange: move |_| {
                            async move {
                                let input = web_sys::window()
                                    .and_then(|w| w.document())
                                    .and_then(|d| d.get_element_by_id("file-upload"))
                                    .and_then(|el| el.dyn_into::<web_sys::HtmlInputElement>().ok());
                                if let Some(input) = input
                                    && let Some(files) = input.files()
                                        && let Some(file) = files.get(0) {
                                            progress.set(Some(ProgressState { status: "File loaded".to_string(), progress: 100.0 }));
                                            file_data.set(Some(file));
                                            file_name.set(Some(files.get(0).unwrap().name()));
                                            file_content_type.set(Some(files.get(0).unwrap().type_()));
                                        }
                            }
                        }
                    }
                    label {
                        class: "w-full p-4 bg-surface text-muted rounded-lg border border-border border-dashed cursor-pointer block text-center transition-all duration-200",
                        "for": "file-upload",
                        {t!("choose-file")}
                    }
                }
            }

            div {
                class: "w-full max-w-xl mb-4",
                div {
                    class: "grid grid-cols-2 gap-1.5 bg-surface p-1.5 rounded-lg border border-border",
                    button {
                        class: if *encrypt_mode.read() == EncryptMode::Password {
                            "px-4 py-2 rounded-md bg-accent text-bg font-semibold text-sm transition-all duration-200"
                        } else {
                            "px-4 py-2 rounded-md text-muted font-semibold text-sm hover:text-text transition-all duration-200"
                        },
                        onclick: move |_| encrypt_mode.set(EncryptMode::Password),
                        {t!("encrypt-mode-password")}
                    }
                    button {
                        class: if *encrypt_mode.read() == EncryptMode::Account {
                            "px-4 py-2 rounded-md bg-accent text-bg font-semibold text-sm transition-all duration-200"
                        } else {
                            "px-4 py-2 rounded-md text-muted font-semibold text-sm hover:text-text transition-all duration-200"
                        },
                        onclick: move |_| encrypt_mode.set(EncryptMode::Account),
                        {t!("encrypt-mode-account")}
                    }
                }
            }

            if account_mode
                && recipient.read().is_none()
            {
                div {
                    class: "w-full max-w-xl mb-4",
                    label {
                        class: "block text-muted text-sm font-bold mb-2",
                        {t!("recipient-search-label")}
                    }
                    div {
                        class: "flex gap-2",
                        input {
                            class: "flex-1 p-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                            placeholder: "{t!(\"recipient-search-placeholder\")}",
                            oninput: move |evt| recipient_search.set(evt.value()),
                            value: "{recipient_search}",
                        }
                        button {
                            class: "px-4 py-2 bg-elevated text-text font-semibold rounded-lg hover:bg-accent hover:text-bg transition-all duration-200",
                            onclick: search_recipient,
                            {t!("recipient-search-button")}
                        }
                    }
                }
            }

            if !account_mode {
                input {
                    class: "w-full max-w-xl p-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                    r#type: "password",
                    placeholder: "{t!(\"password-placeholder\")}",
                    autocomplete: "new-password",
                    oninput: move |evt| password_input.set(evt.value()),
                    value: "{password_input}",
                }
                p {
                    class: "w-full max-w-xl text-xs text-muted mb-4 text-right",
                    {t!("password-auto-gen-hint")}
                }
            }
            div {
                class: "w-full max-w-xl flex flex-col sm:flex-row gap-4 mb-4",
                if !account_mode {
                    div {
                        class: "flex-1",
                    label {
                        class: "block text-muted text-sm font-bold mb-2",
                        {t!("try-count-label")}
                    }
                    div {
                        class: "grid grid-cols-3 gap-1.5 mb-2",
                        button {
                            class: if try_count_preset.read().as_str() == "1" { "px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center" } else { "px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center" },
                            onclick: move |_| try_count_preset.set("1".to_string()),
                            "1"
                        }
                        button {
                            class: if try_count_preset.read().as_str() == "5" { "px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center" } else { "px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center" },
                            onclick: move |_| try_count_preset.set("5".to_string()),
                            "5"
                        }
                        button {
                            class: if try_count_preset.read().as_str() == "25" { "px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center" } else { "px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center" },
                            onclick: move |_| try_count_preset.set("25".to_string()),
                            "25"
                        }
                        button {
                            class: if try_count_preset.read().as_str() == "custom" { "col-span-3 px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center mt-1" } else { "col-span-3 px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center mt-1" },
                            onclick: move |_| try_count_preset.set("custom".to_string()),
                            {t!("ttl-custom")}
                        }
                    }
                    if try_count_preset.read().as_str() == "custom" {
                        input {
                            class: "w-full p-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                            r#type: "number",
                            oninput: move |evt| try_count_custom.set(evt.value()),
                            value: "{try_count_custom}",
                        }
                    }
                }
                }
                div {
                    class: "flex-1",
                    label {
                        class: "block text-muted text-sm font-bold mb-2",
                        {t!("ttl-label")}
                    }
                    div {
                        class: "grid grid-cols-3 gap-1.5 mb-2",
                        {ttl_presets.iter().map(|(value, label)| {
                            let value_str = value.to_string();
                            let base_cls = if ttl_preset.read().as_str() == value_str {
                                "px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center"
                            } else {
                                "px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center"
                            };
                            let cls = if ttl_presets.len() == 1 {
                                format!("{} col-span-3", base_cls)
                            } else {
                                base_cls.to_string()
                            };
                            rsx! {
                                button {
                                    class: "{cls}",
                                    onclick: move |_| ttl_preset.set(value_str.clone()),
                                    "{label}"
                                }
                            }
                        })}
                        button {
                            class: if ttl_preset.read().as_str() == "custom" { "col-span-3 px-3 py-1.5 bg-accent text-bg text-sm font-semibold rounded text-center mt-1" } else { "col-span-3 px-3 py-1.5 bg-surface text-muted text-sm font-semibold rounded border border-border text-center mt-1" },
                            onclick: move |_| ttl_preset.set("custom".to_string()),
                            {t!("ttl-custom")}
                        }
                    }
                    if ttl_preset.read().as_str() == "custom" {
                        input {
                            class: "w-full p-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                            r#type: "number",
                            oninput: move |evt| ttl_custom.set(evt.value()),
                            value: "{ttl_custom}",
                            max: stats.read().as_ref().map(|s| s.max_ttl_seconds).unwrap_or(43200)
                        }
                    }
                }
            }
            div {
                class: "w-full max-w-xl flex items-center gap-6 mb-4",
                div {
                    class: "flex items-center gap-2",
                    input {
                        r#type: "checkbox",
                        id: "no-download",
                        oninput: move |evt| disable_download.set(evt.checked()),
                    }
                    label {
                        "for": "no-download",
                        class: "text-sm text-muted select-none",
                        {t!("disable-download")}
                    }
                }
                div {
                    class: "flex items-center gap-2",
                    input {
                        r#type: "checkbox",
                        id: "burn-after",
                        oninput: move |evt| burn_after_read.set(evt.checked()),
                    }
                    label {
                        "for": "burn-after",
                        class: "text-sm text-muted select-none",
                        {t!("burn-after-read")}
                    }
                }
            }
            button {
                class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg shadow-md hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2",
                onclick: create_paste,
                {t!("create-paste")}
            }

            {generated_id.read().as_ref().map(|id| {
                let password = password_input.read().clone();
                let is_auto = *auto_generated.read();
                let origin = web_sys::window()
                    .and_then(|w| w.location().origin().ok())
                    .unwrap_or_else(|| BASE_URL.to_string());
                let paste_url = format!("{}/paste/{}{}", origin, id, if is_auto {
                    format!("#{}", password)
                } else {
                    String::new()
                });
                rsx!{
                    div {
                        class: "mt-4 p-4 bg-success text-text rounded-lg shadow-md",
                        p { class: "font-bold text-lg", {{t!("paste-created")}} }
                        div {
                            class: "mt-2",
                            div {
                                class: "flex justify-between items-center",
                                p { class: "text-sm text-text-secondary", "Full Link:" }
                                button {
                                    class: "px-3 py-1 bg-accent text-bg text-xs font-semibold rounded hover:bg-accent-hover transition-all duration-200",
                                    onclick: {
                                        let url = paste_url.clone();
                                        move |_| {
                                            if let Err(e) = copy_to_clipboard(&url) {
                                                popup_ctx.write().show_error(&e);
                                            } else {
                                                popup_ctx.write().show_success(t!("copy-success"));
                                            }
                                        }
                                    },
                                    {t!("copy-clipboard")}
                                }
                            }
                            input {
                                class: "w-full p-2 mt-1 bg-success text-text rounded text-sm font-mono",
                                value: "{paste_url}",
                                readonly: "true",
                                onclick: move |_| {},
                            }
                        }
                        div {
                            class: "mt-3 grid grid-cols-2 gap-2",
                            div {
                                p { class: "text-sm text-text-secondary", "Paste ID:" }
                                input {
                                    class: "w-full p-2 mt-1 bg-success text-text rounded text-sm font-mono",
                                    value: "{id}",
                                    readonly: "true",
                                }
                            }
                            if is_auto {
                                div {
                                    p { class: "text-sm text-text-secondary", "Passcode:" }
                                    input {
                                        class: "w-full p-2 mt-1 bg-success text-text rounded text-sm font-mono",
                                        value: "{password}",
                                        readonly: "true",
                                    }
                                }
                            }
                        }
                        p { class: "mt-2 text-xs text-text-secondary", {{t!("remember-password")}} }
                    }
                }
            })}

            div {
                class: "mt-8 w-full max-w-xl",
                h2 {
                    class: "text-2xl font-bold text-text mb-4",
                    {t!("view-existing-paste")}
                }
                input {
                    class: "w-full p-4 mb-4 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                    r#type: "text",
                    placeholder: "{t!(\"enter-paste-id\")}",
                    oninput: move |evt| bin_id_input.set(sanitize_id(&evt.value())),
                    value: "{bin_id_input}",
                }
                button {
                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
                    onclick: go_to_paste,
                    {t!("view-paste")}
                }
            }

            div {
                class: "mt-8 w-full max-w-xl p-6 bg-surface rounded-lg",
                h2 {
                    class: "text-xl font-bold text-text mb-4 text-center",
                    {t!("stats-title")}
                }
                p {
                    class: "text-xs text-muted text-center mb-4",
                    {t!("stats-description")}
                }
                h3 {
                    class: "text-sm font-semibold text-text text-center",
                    {t!("all-time")}
                }
                div {
                    class: "grid grid-cols-3 gap-4 text-center",
                    div {
                        p { class: "text-2xl font-bold text-text", "{format_count(stats.read().as_ref().map(|s| s.pastes_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("created")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-success", "{format_count(stats.read().as_ref().map(|s| s.requests_success_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("decrypted")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-danger", "{format_count(stats.read().as_ref().map(|s| s.requests_fail_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("wrong-password")} }
                    }
                }
                div {
                    class: "border-t border-border my-4"
                }
                h3 {
                    class: "text-sm font-semibold text-muted text-center mb-2",
                    {t!("today")}
                }
                div {
                    class: "grid grid-cols-3 gap-4 text-center",
                    div {
                        p { class: "text-2xl font-bold text-text", "{format_count(stats.read().as_ref().map(|s| s.pastes_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("created")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-success", "{format_count(stats.read().as_ref().map(|s| s.requests_success_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("decrypted")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-danger", "{format_count(stats.read().as_ref().map(|s| s.requests_fail_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-muted", {t!("wrong-password")} }
                    }
                }
            }
        }
    }
}
