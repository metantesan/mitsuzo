use crate::BASE_URL;
use crate::components::PopupContext;
use crate::sanitize_id;
use crate::utils::do_xhr_get;
use base64::{Engine as _, engine::general_purpose};
use dioxus::prelude::*;
use dioxus_i18n::t;
use gloo_timers::future::TimeoutFuture;
use mitsuzo_types::{DataType, GetSaltResponse};
use mitsuzo_utils::{
    compute_password_hash, decrypt_chunk_into, derive_keys, get_chunk_bounds, get_plaintext_size,
};
use wasm_bindgen::JsCast;
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url, js_sys};

#[derive(Clone, Debug)]
pub struct ProgressState {
    pub status: String,
    pub progress: f32,
}

#[component]
pub fn paste_view(id: String) -> Element {
    let id = sanitize_id(&id);
    let mut password_input = use_signal(String::new);
    let paste_content =
        use_signal(|| Option::<(Vec<u8>, DataType, Option<String>, Option<String>, bool)>::None);
    let paste_id_state = use_signal(|| id.clone());
    let try_count: Signal<Option<u32>> = use_signal(|| None);
    let ttl: Signal<Option<u64>> = use_signal(|| None);
    let progress: Signal<Option<ProgressState>> = use_signal(|| None);
    let mut popup_ctx = use_context::<Signal<PopupContext>>();

    let hash_from_url = (|| {
        let storage = web_sys::window().and_then(|w| w.session_storage().ok().flatten())?;
        let hash = storage.get_item("paste_hash").ok().flatten()?;
        let _ = storage.remove_item("paste_hash");
        let pwd = hash.strip_prefix('#').unwrap_or("").to_string();
        if pwd.is_empty() { None } else { Some(pwd) }
    })();
    if let Some(ref pwd) = hash_from_url
        && password_input.read().is_empty()
    {
        password_input.set(pwd.clone());
    }

    let fetch_and_decrypt = {
        let mut popup_ctx = popup_ctx;
        move |_| {
            let current_id = paste_id_state.read().clone();
            let current_password = password_input.read().clone();
            if current_password.is_empty() {
                popup_ctx.write().show_error(t!("error-password-empty"));
                return;
            }
            spawn(do_decrypt(
                current_id,
                current_password,
                popup_ctx,
                try_count,
                ttl,
                progress,
                paste_content,
            ));
        }
    };

    let hash_processed = use_signal(|| false);

    use_effect({
        let mut hash_processed = hash_processed;
        move || {
            if *hash_processed.read() {
                return;
            }
            let current_password = password_input.read().clone();
            if !current_password.is_empty() && hash_from_url.is_some() {
                hash_processed.set(true);
                let current_id = paste_id_state.read().clone();
                spawn(do_decrypt(
                    current_id,
                    current_password,
                    popup_ctx,
                    try_count,
                    ttl,
                    progress,
                    paste_content,
                ));
            }
        }
    });

    rsx! {
        div {
            class: "max-w-2xl mx-auto px-4 py-8",
            h1 {
                class: "text-3xl font-bold text-center mb-8 tracking-tight",
                {t!("paste-view-title")}
            }

            div {
                class: "mb-4",
                input {
                    class: "w-full p-4 mb-2 bg-surface text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                    r#type: "password",
                    placeholder: "{t!(\"decrypt-password-placeholder\")}",
                    autocomplete: "new-password",
                    oninput: move |evt| password_input.set(evt.value()),
                    value: "{password_input}",
                }
                button {
                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
                    onclick: fetch_and_decrypt,
                    {t!("decrypt-paste")}
                }
            }

            if let Some(prog) = progress.read().as_ref() {
                div {
                    class: "w-full max-w-md mx-auto mb-4 p-4 bg-surface rounded-lg",
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

            div {
                class: "text-center text-muted my-4",
                match *try_count.read() {
                    Some(count) if count > 0 => rsx! { p { {t!("tries-left", count: count)} } },
                    _ => rsx! { Fragment {} },
                },
                match *ttl.read() {
                    Some(time) if time < u64::MAX => rsx! { p { {t!("time-left", time: time)} } },
                    _ => rsx! { Fragment {} },
                },
            }

            {
                match &*paste_content.read() {
                    Some((bytes, data_type, filename, content_type, allow_download)) => {
                        let id = paste_id_state.read().clone();
                        match data_type {
                            DataType::Text => rsx! {
                                div {
                                    class: "bg-surface p-6 rounded-lg shadow-lg",
                                    h2 {
                                        class: "text-xl font-semibold mb-4",
                                        {t!("paste-id", id: id)}
                                    }
                                    pre {
                                        class: "bg-bg p-4 rounded-md text-left whitespace-pre-wrap break-words overflow-auto text-text-secondary",
                                        {String::from_utf8_lossy(bytes).to_string()}
                                    }
                                }
                            },
                            DataType::File => {
                                let owned_id = id.clone();
                                let owned_filename = filename.clone();
                                let owned_content_type = content_type.clone();
                                if is_previewable(content_type.as_deref()) {
                                    let preview_bytes = bytes.to_vec();
                                    rsx! {
                                        div {
                                            class: "bg-surface p-6 rounded-lg shadow-lg text-center",
                                            h2 {
                                                class: "text-xl font-semibold mb-4",
                                                {t!("file-preview")}
                                            }
                                            div {
                                                class: "mb-4 flex justify-center",
                                                {
                                                    let ct = content_type.clone().unwrap_or_default();
                                                    if ct.starts_with("image/") {
                                                        let b64_content = general_purpose::STANDARD.encode(&preview_bytes);
                                                        let data_url = format!("data:{};base64,{}", ct, b64_content);
                                                        rsx!{
                                                            img {
                                                                class: "max-w-full h-auto rounded-lg mx-auto",
                                                                src: "{data_url}"
                                                            }
                                                        }
                                                    } else if ct.starts_with("video/") {
                                                        let b64_content = general_purpose::STANDARD.encode(&preview_bytes);
                                                        let data_url = format!("data:{};base64,{}", ct, b64_content);
                                                        rsx!{
                                                            video {
                                                                class: "max-w-full h-auto rounded-lg mx-auto",
                                                                src: "{data_url}",
                                                                controls: true,
                                                            }
                                                        }
                                                    } else if ct.starts_with("audio/") {
                                                        let b64_content = general_purpose::STANDARD.encode(&preview_bytes);
                                                        let data_url = format!("data:{};base64,{}", ct, b64_content);
                                                        rsx!{
                                                            audio {
                                                                class: "w-full",
                                                                src: "{data_url}",
                                                                controls: true,
                                                            }
                                                        }
                                                    } else if ct == "application/pdf" {
                                                        let b64_content = general_purpose::STANDARD.encode(&preview_bytes);
                                                        let data_url = format!("data:{};base64,{}", ct, b64_content);
                                                        rsx!{
                                                            iframe {
                                                                class: "w-full h-96 rounded-lg",
                                                                src: "{data_url}",
                                                            }
                                                        }
                                                    } else {
                                                        rsx!{
                                                            pre {
                                                                class: "bg-bg p-4 rounded-md text-left whitespace-pre-wrap break-words overflow-auto text-text-secondary",
                                                                {String::from_utf8_lossy(bytes).to_string()}
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            if *allow_download {
                                                button {
                                                    class: "px-6 py-3 bg-success text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
                                                    onclick: move |_| {
                                                        match download_file(preview_bytes.clone(), owned_filename.clone().unwrap_or(owned_id.clone()), owned_content_type.clone()) {
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                popup_ctx.write().show_error(&e);
                                                            }
                                                        }
                                                    },
                                                    {t!("download-file")}
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    let dl_bytes = bytes.to_vec();
                                    rsx! {
                                        div {
                                            class: "bg-surface p-6 rounded-lg shadow-lg text-center",
                                            h2 {
                                                class: "text-xl font-semibold mb-4",
                                                {t!("file-ready-download")}
                                            }
                                            p {
                                                class: "mb-4 text-muted",
                                                {t!("paste-id", id: id)}
                                            }
                                            if *allow_download {
                                                button {
                                                    class: "px-6 py-3 bg-success text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
                                                    onclick: move |_| {
                                                        match download_file(dl_bytes.clone(), owned_filename.clone().unwrap_or(owned_id.clone()), owned_content_type.clone()) {
                                                            Ok(_) => {}
                                                            Err(e) => {
                                                                popup_ctx.write().show_error(&e);
                                                            }
                                                        }
                                                    },
                                                    {t!("download-file")}
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                        }
                    },
                    None => rsx! {
                        div {
                            class: "text-center text-muted",
                            {t!("enter-password-desc")}
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::type_complexity)]
async fn do_decrypt(
    current_id: String,
    current_password: String,
    mut popup_ctx: Signal<PopupContext>,
    mut try_count: Signal<Option<u32>>,
    mut ttl: Signal<Option<u64>>,
    mut progress: Signal<Option<ProgressState>>,
    mut paste_content: Signal<Option<(Vec<u8>, DataType, Option<String>, Option<String>, bool)>>,
) {
    progress.set(Some(ProgressState {
        status: t!("progress-downloading-metadata"),
        progress: 10.0,
    }));

    let salt_result = do_xhr_get(
        &format!("{}/api/paste/{}/salt", BASE_URL, current_id),
        vec![],
        |loaded, total| {
            if total > 0 {
                let percent = (loaded as f32 / total as f32) * 20.0;
                let status_text = t!("progress-downloading-percent", percent: format!("{:.0}", (percent / 20.0) * 100.0));
                progress.set(Some(ProgressState {
                    status: status_text,
                    progress: 10.0 + percent,
                }));
            }
        },
    )
    .await;

    let (
        salt,
        total_chunks,
        header_nonce,
        header_data_type,
        header_filename,
        header_content_type,
        header_allow_download,
    ) = match salt_result {
        Ok(response) => {
            if response.status >= 200 && response.status < 300 {
                if let Some(body) = response.body {
                    match bitcode::decode::<GetSaltResponse>(&body) {
                        Ok(decoded) => {
                            try_count.set(Some(decoded.try_count));
                            ttl.set(Some(decoded.ttl));
                            (
                                decoded.salt,
                                decoded.total_chunks,
                                decoded.nonce,
                                decoded.data_type,
                                decoded.filename,
                                decoded.content_type,
                                decoded.allow_download,
                            )
                        }
                        Err(e) => {
                            popup_ctx
                                .write()
                                .show_error(t!("error-decode-salt-failed", error: e.to_string()));
                            progress.set(None);
                            return;
                        }
                    }
                } else {
                    popup_ctx
                        .write()
                        .show_error(t!("error-empty-salt-response"));
                    progress.set(None);
                    return;
                }
            } else {
                popup_ctx
                    .write()
                    .show_error(t!("error-get-salt-failed", status: response.status.to_string()));
                progress.set(None);
                return;
            }
        }
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-salt-request-failed", error: e));
            progress.set(None);
            return;
        }
    };

    progress.set(Some(ProgressState {
        status: t!("progress-deriving-key"),
        progress: 40.0,
    }));

    let (_encryption_key, validation_key) = match derive_keys(&current_password, &salt) {
        Ok(keys) => keys,
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-key-derivation-failed", error: e));
            progress.set(None);
            return;
        }
    };

    let password_hash = compute_password_hash(&validation_key, &salt);
    let encoded_hash = general_purpose::STANDARD.encode(password_hash);

    progress.set(Some(ProgressState {
        status: t!("progress-downloading-content"),
        progress: 50.0,
    }));

    let content_result = do_xhr_get(
        &format!("{}/api/paste/{}/data", BASE_URL, current_id),
        vec![("X-Password-Hash".to_string(), encoded_hash)],
        |loaded, total| {
            if total > 0 {
                let percent = (loaded as f32 / total as f32) * 40.0;
                let status_text = t!("progress-downloading-percent", percent: format!("{:.0}", (percent / 40.0) * 100.0));
                progress.set(Some(ProgressState {
                    status: status_text,
                    progress: 50.0 + percent,
                }));
            } else if loaded > 0 {
                let status_text = t!("progress-downloading-kb", kb: format!("{:.1}", loaded as f32 / 1024.0));
                progress.set(Some(ProgressState {
                    status: status_text,
                    progress: 90.0,
                }));
            }
        },
    )
    .await;

    match content_result {
        Ok(response) => {
            if response.status >= 200 && response.status < 300 {
                if let Some(content) = response.body {
                    let paste_total_chunks = total_chunks;

                    let (encryption_key, _) = match derive_keys(&current_password, &salt) {
                        Ok(k) => k,
                        Err(e) => {
                            popup_ctx
                                .write()
                                .show_error(t!("error-decryption-failed", error: e));
                            progress.set(None);
                            return;
                        }
                    };

                    let plaintext_size = match get_plaintext_size(paste_total_chunks, content.len())
                    {
                        Ok(s) => s,
                        Err(e) => {
                            popup_ctx
                                .write()
                                .show_error(t!("error-decryption-failed", error: e.to_string()));
                            progress.set(None);
                            return;
                        }
                    };

                    let mut plaintext = Vec::with_capacity(plaintext_size);
                    let result: Result<(), String> = async {
                        for i in 0..paste_total_chunks {
                            if i % 8 == 0 {
                                let pct = 90.0 + (i as f32 / paste_total_chunks as f32) * 10.0;
                                progress.set(Some(ProgressState {
                                    status: t!("progress-decrypting-percent", percent: format!("{:.0}", (i as f32 / paste_total_chunks as f32) * 100.0)),
                                    progress: pct,
                                }));
                                TimeoutFuture::new(0).await;
                            }
                            let (start, end) = get_chunk_bounds(paste_total_chunks, i, content.len());
                            decrypt_chunk_into(&content[start..end], &encryption_key, &header_nonce, i, &mut plaintext)?;
                        }
                        Ok(())
                    }.await;

                    match result {
                        Ok(()) => {
                            paste_content.set(Some((
                                plaintext,
                                header_data_type,
                                header_filename,
                                header_content_type,
                                header_allow_download,
                            )));
                            progress.set(None);
                        }
                        Err(e) => {
                            popup_ctx
                                .write()
                                .show_error(t!("error-decryption-failed", error: e.to_string()));
                            progress.set(None);
                        }
                    }
                } else {
                    popup_ctx.write().show_error(t!("error-empty-response"));
                    progress.set(None);
                }
            } else {
                popup_ctx
                    .write()
                    .show_error(t!("error-get-paste-failed", status: response.status.to_string()));
                progress.set(None);
                let current = *try_count.read();
                if let Some(count) = current {
                    if count > 0 {
                        try_count.set(Some(count - 1));
                    }
                }
            }
        }
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-send-request-failed", error: e));
            progress.set(None);
        }
    }
}

fn is_previewable(content_type: Option<&str>) -> bool {
    match content_type {
        Some(ct) => {
            ct.starts_with("image/")
                || ct.starts_with("text/")
                || ct == "application/json"
                || ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct == "application/pdf"
        }
        None => false,
    }
}

fn download_file(
    content: Vec<u8>,
    default_name: String,
    content_type: Option<String>,
) -> Result<(), String> {
    let uint8_array = js_sys::Uint8Array::from(content.as_slice());
    let props = BlobPropertyBag::new();
    if let Some(ct) = content_type {
        props.set_type(&ct);
    } else {
        props.set_type("application/octet-stream");
    }
    let blob = Blob::new_with_u8_array_sequence_and_options(
        &js_sys::Array::of1(&uint8_array.into()),
        &props,
    )
    .map_err(|e| format!("Failed to create blob: {:?}", e))?;

    let url = Url::create_object_url_with_blob(&blob)
        .map_err(|e| format!("Failed to create object URL: {:?}", e))?;

    let window = web_sys::window().ok_or("Failed to get browser window")?;
    let document = window.document().ok_or("Failed to get document")?;
    let a = document
        .create_element("a")
        .map_err(|e| format!("Failed to create anchor element: {:?}", e))?
        .dyn_into::<HtmlAnchorElement>()
        .map_err(|_| "Failed to convert to anchor element")?;

    a.set_href(&url);
    a.set_download(&default_name);
    a.click();

    Url::revoke_object_url(&url).map_err(|e| format!("Failed to revoke object URL: {:?}", e))?;

    Ok(())
}
