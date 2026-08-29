use crate::BASE_URL;
use crate::account::{
    AccountSession, RecipientEphemeral, solve_account_challenge, unlock_local_account, use_account,
    use_recipient_ephemerals,
};
use crate::components::PopupContext;
use crate::sanitize_id;
use crate::utils::{copy_to_clipboard, do_xhr_get, do_xhr_post, do_xhr_post_headers};
use base64::{Engine as _, engine::general_purpose};
use dioxus::prelude::*;
use dioxus_i18n::t;
use gloo_timers::future::TimeoutFuture;
use mitsuzo_types::{
    ChangePasswordRequest, DataType, FailedAttempt, GetSaltResponse, KeyEnvelope, PasteAuthMode,
    RecipientAuthChallenge, split_paste_frame,
};
use mitsuzo_utils::{
    compute_burn_receipt, compute_password_hash, decrypt_chunk_into, derive_keys, encrypt_setup,
    get_chunk_bounds, get_plaintext_size, open_content_key_for_recipient, unwrap_content_key,
};
use wasm_bindgen::JsCast;
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url, js_sys};

pub struct PasteContent {
    pub bytes: Vec<u8>,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub allow_download: bool,
}

#[derive(Clone, Debug)]
pub struct ProgressState {
    pub status: String,
    pub progress: f32,
}

/// Key material for recipient-mode decryption: either a logged-in account
/// scalar or the sender's ephemeral key for this paste.
#[derive(Clone, Copy)]
struct RecipientKey {
    kid: [u8; 32],
    scalar: [u8; 32],
}

#[component]
pub fn paste_view(id: String) -> Element {
    let id = sanitize_id(&id);
    let mut password_input = use_signal(String::new);
    let paste_content: Signal<Option<PasteContent>> = use_signal(|| None);
    let paste_id_state = use_signal(|| id.clone());
    let try_count: Signal<Option<u32>> = use_signal(|| None);
    let ttl: Signal<Option<u64>> = use_signal(|| None);
    let burn_after_read = use_signal(|| false);
    let salt: Signal<Option<Vec<u8>>> = use_signal(|| None);
    let progress: Signal<Option<ProgressState>> = use_signal(|| None);
    let mut popup_ctx = use_context::<Signal<PopupContext>>();
    let content_key: Signal<Option<[u8; 32]>> = use_signal(|| None);
    let old_password_hash: Signal<Option<[u8; 32]>> = use_signal(|| None);
    let can_change_password = use_signal(|| false);
    let mut new_password_input = use_signal(String::new);
    let mut confirm_password_input = use_signal(String::new);
    let changing_password = use_signal(|| false);

    let is_recipient_mode = use_signal(|| false);
    let needs_account_password = use_signal(|| false);
    let not_found = use_signal(|| false);
    let mut account_password_input = use_signal(String::new);
    let recipient_session: Signal<Option<RecipientKey>> = use_signal(|| None);
    let ephemerals = use_recipient_ephemerals();
    let account = use_account();
    let mode_probed = use_signal(|| false);

    // Probe the paste's auth mode on page load so the UI shows the right box
    // at once: a password prompt for password-mode pastes, or the account
    // unlock/decrypt flow for recipient-mode pastes — never both.
    use_effect({
        let mut is_recipient_mode = is_recipient_mode;
        let mut needs_account_password = needs_account_password;
        let mut not_found = not_found;
        let mut mode_probed = mode_probed;
        move || {
            if *mode_probed.read() {
                return;
            }
            let current_id = paste_id_state.read().clone();
            spawn(async move {
                let probe = do_xhr_get(
                    &format!("{}/api/paste/{}/salt", BASE_URL, current_id),
                    vec![],
                    |_, _| {},
                )
                .await;
                // The response carries the auth mode explicitly. A 404 (or an
                // undecodable body) means the paste does not exist rather than
                // "recipient mode" — never misdirect the user to the account
                // unlock flow for a missing paste.
                let recipient_mode = match &probe {
                    Ok(r) if r.status >= 200 && r.status < 300 => r
                        .body
                        .as_ref()
                        .and_then(|b| bitcode::decode::<GetSaltResponse>(b).ok())
                        .is_some_and(|decoded| decoded.mode == PasteAuthMode::Recipient),
                    Ok(r) if r.status == 404 => {
                        not_found.set(true);
                        false
                    }
                    _ => false,
                };
                is_recipient_mode.set(recipient_mode);
                if recipient_mode {
                    // A key is already available (sender ephemeral in session,
                    // or account unlocked): offer decrypt directly. Otherwise
                    // surface the account-password unlock form.
                    let has_key = ephemerals.read().iter().any(|e| e.paste_id == current_id)
                        || account.read().is_some();
                    needs_account_password.set(!has_key);
                }
                mode_probed.set(true);
            });
        }
    });

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
        let popup_ctx = popup_ctx;
        let is_recipient_mode2 = is_recipient_mode;
        move |_| {
            let current_id = paste_id_state.read().clone();
            let current_password = password_input.read().clone();
            // An empty password is allowed here: for recipient-mode pastes the
            // /salt probe answers 404 and we switch into the account flow.
            spawn(do_decrypt(
                current_id,
                current_password,
                popup_ctx,
                try_count,
                ttl,
                progress,
                paste_content,
                burn_after_read,
                salt,
                content_key,
                old_password_hash,
                can_change_password,
                is_recipient_mode2,
                needs_account_password,
                recipient_session,
                ephemerals,
                account,
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
                    burn_after_read,
                    salt,
                    content_key,
                    old_password_hash,
                    can_change_password,
                    is_recipient_mode,
                    needs_account_password,
                    recipient_session,
                    ephemerals,
                    account,
                ));
            }
        }
    });

    let unlock_for_recipient = {
        let mut popup_ctx = popup_ctx;
        let mut recipient_session = recipient_session;
        let mut needs_account_password2 = needs_account_password;
        move |_| {
            let pw = account_password_input.read().clone();
            if pw.is_empty() {
                popup_ctx.write().show_error(t!("account-password-empty"));
                return;
            }
            match unlock_local_account(&pw) {
                Ok(session) => {
                    recipient_session.set(Some(RecipientKey {
                        kid: session.kid,
                        scalar: session.scalar,
                    }));
                    needs_account_password2.set(false);
                    account_password_input.set(String::new());
                    let current_id = paste_id_state.read().clone();
                    spawn(do_decrypt(
                        current_id,
                        String::new(),
                        popup_ctx,
                        try_count,
                        ttl,
                        progress,
                        paste_content,
                        burn_after_read,
                        salt,
                        content_key,
                        old_password_hash,
                        can_change_password,
                        is_recipient_mode,
                        needs_account_password,
                        recipient_session,
                        ephemerals,
                        account,
                    ));
                }
                Err(e) => popup_ctx.write().show_error(e),
            }
        }
    };

    let change_password_action = move |_| {
        let current_id = paste_id_state.read().clone();
        let new_password = new_password_input.read().clone();
        let confirm = confirm_password_input.read().clone();
        let key = *content_key.read();
        let old_hash = *old_password_hash.read();
        if new_password.is_empty() {
            popup_ctx.write().show_error(t!("error-password-empty"));
            return;
        }
        if new_password != confirm {
            popup_ctx
                .write()
                .show_error(t!("error-change-password-mismatch"));
            return;
        }
        let (Some(key), Some(old_hash)) = (key, old_hash) else {
            return;
        };
        spawn(do_change_password(ChangePasswordParams {
            current_id,
            new_password,
            content_key: key,
            old_hash,
            popup_ctx,
            busy: changing_password,
            new_password_input,
            confirm_password_input,
        }));
    };

    rsx! {
        div {
            class: "max-w-2xl mx-auto px-4 py-8",
            h1 {
                class: "text-3xl font-bold text-center mb-8 tracking-tight",
                {t!("paste-view-title")}
            }

            if paste_content.read().is_none() && !*mode_probed.read() {
                div {
                    class: "mb-4 p-4 bg-surface rounded-lg text-center text-muted",
                    {t!("paste-loading")}
                }
            }

            if *not_found.read() {
                div {
                    class: "mb-4 p-4 bg-surface rounded-lg text-center text-muted",
                    {t!("paste-not-found")}
                }
            } else if *mode_probed.read() && !*is_recipient_mode.read() {
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
            }

            if *is_recipient_mode.read() {
                div {
                    class: "mb-4 p-4 bg-accent/15 border border-accent rounded-lg text-sm text-accent",
                    {t!("recipient-mode-notice")}
                }
            }

            if *is_recipient_mode.read() && *needs_account_password.read() {
                div {
                    class: "mb-4 p-4 bg-surface rounded-lg",
                    p {
                        class: "text-sm font-semibold mb-2",
                        {t!("recipient-unlock-title")}
                    }
                    div {
                        class: "flex flex-col sm:flex-row gap-3",
                        input {
                            class: "flex-1 p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                            r#type: "password",
                            placeholder: "{t!(\"account-password-placeholder\")}",
                            oninput: move |evt| account_password_input.set(evt.value()),
                            value: "{account_password_input}",
                        }
                        button {
                            class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200",
                            onclick: unlock_for_recipient,
                            {t!("recipient-unlock-button")}
                        }
                    }
                }
            } else if *is_recipient_mode.read() && *mode_probed.read() {
                div {
                    class: "mb-4",
                    button {
                        class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
                        onclick: fetch_and_decrypt,
                        {t!("recipient-decrypt-button")}
                    }
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
                {if *burn_after_read.read() {
                    rsx! { p { class: "text-accent font-semibold", {t!("burn-notice")} } }
                } else {
                    rsx! { Fragment {} }
                }}
            }

            {
                match &*paste_content.read() {
                    Some(PasteContent { bytes, data_type, filename, content_type, allow_download }) => {
                        let id = paste_id_state.read().clone();
                        let origin = web_sys::window()
                            .and_then(|w| w.location().origin().ok())
                            .unwrap_or_else(|| BASE_URL.to_string());
                        let paste_url = format!("{}/paste/{}", origin, id);
                        match data_type {
                            DataType::Text => {
                                let text_content = String::from_utf8_lossy(bytes).to_string();
                                let text_for_copy = text_content.clone();
                                rsx! {
                                    div {
                                        class: "bg-surface p-6 rounded-lg shadow-lg",
                                        div {
                                            class: "flex justify-between items-center mb-4",
                                            h2 {
                                                class: "text-xl font-semibold",
                                                {t!("paste-id", id: id)}
                                            }
                                            button {
                                                class: "px-4 py-2 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200 text-sm",
                                                onclick: move |_| {
                                                    if let Err(e) = copy_to_clipboard(&text_for_copy) {
                                                        popup_ctx.write().show_error(&e);
                                                    } else {
                                                        popup_ctx.write().show_success(t!("copy-success"));
                                                    }
                                                },
                                                {t!("copy-clipboard")}
                                            }
                                        }
                                        pre {
                                            class: "bg-bg p-4 rounded-md text-left whitespace-pre-wrap break-words overflow-auto text-text-secondary",
                                            {text_content}
                                        }
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
                                            div {
                                                class: "flex justify-center gap-3",
                                                button {
                                                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
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
                                            div {
                                                class: "flex justify-center gap-3",
                                                button {
                                                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200",
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
                                }
                            },
                        }
                    },
                    None => rsx! {
                        div {
                            class: "text-center text-muted",
                            {if *is_recipient_mode.read() {
                                t!("recipient-mode-notice")
                            } else {
                                t!("enter-password-desc")
                            }}
                        }
                    }
                }
            }

            {if *can_change_password.read() {
                rsx! {
                    div {
                        class: "bg-surface p-6 rounded-lg shadow-lg mt-6",
                        h2 {
                            class: "text-xl font-semibold mb-2",
                            {t!("change-password-title")}
                        }
                        p {
                            class: "text-muted text-sm mb-4",
                            {t!("change-password-desc")}
                        }
                        div {
                            class: "space-y-3",
                            input {
                                class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                r#type: "password",
                                placeholder: "{t!(\"change-password-new-placeholder\")}",
                                autocomplete: "new-password",
                                oninput: move |evt| new_password_input.set(evt.value()),
                                value: "{new_password_input}",
                            }
                            input {
                                class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                r#type: "password",
                                placeholder: "{t!(\"change-password-confirm-placeholder\")}",
                                autocomplete: "new-password",
                                oninput: move |evt| confirm_password_input.set(evt.value()),
                                value: "{confirm_password_input}",
                            }
                            button {
                                class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 transition-all duration-200 disabled:opacity-50",
                                disabled: *changing_password.read(),
                                onclick: change_password_action,
                                {t!("change-password-button")}
                            }
                        }
                    }
                }
            } else {
                rsx! { Fragment {} }
            }}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn do_decrypt(
    current_id: String,
    current_password: String,
    mut popup_ctx: Signal<PopupContext>,
    mut try_count: Signal<Option<u32>>,
    mut ttl: Signal<Option<u64>>,
    mut progress: Signal<Option<ProgressState>>,
    mut paste_content: Signal<Option<PasteContent>>,
    mut burn_after_read: Signal<bool>,
    mut salt: Signal<Option<Vec<u8>>>,
    mut content_key: Signal<Option<[u8; 32]>>,
    mut old_password_hash: Signal<Option<[u8; 32]>>,
    mut can_change_password: Signal<bool>,
    mut is_recipient_mode: Signal<bool>,
    mut needs_account_password: Signal<bool>,
    recipient_session: Signal<Option<RecipientKey>>,
    ephemerals: Signal<Vec<RecipientEphemeral>>,
    account: Signal<Option<AccountSession>>,
) {
    progress.set(Some(ProgressState {
        status: t!("progress-downloading-metadata"),
        progress: 10.0,
    }));
    can_change_password.set(false);
    needs_account_password.set(false);

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

    // The salt probe answers 200 with an explicit auth mode: `Recipient`
    // pastes route through the account/challenge flow, `Password` pastes
    // continue below. Any other status (404 etc.) falls through to the
    // generic error handling.
    let is_recipient_mode_salt = match &salt_result {
        Ok(response) if response.status >= 200 && response.status < 300 => response
            .body
            .as_ref()
            .and_then(|b| bitcode::decode::<GetSaltResponse>(b).ok())
            .is_some_and(|decoded| decoded.mode == PasteAuthMode::Recipient),
        _ => false,
    };
    if is_recipient_mode_salt {
        is_recipient_mode.set(true);
        let recipient_key = {
            // 1. Sender reopening: ephemeral key held for this session.
            let from_ephemeral = ephemerals
                .read()
                .iter()
                .find(|e| e.paste_id == current_id)
                .map(|e| RecipientKey {
                    kid: e.recipient_kid,
                    scalar: e.ephemeral_priv,
                });
            from_ephemeral
                // 2. Account already unlocked.
                .or_else(|| {
                    account.read().clone().map(|a| RecipientKey {
                        kid: a.kid,
                        scalar: a.scalar,
                    })
                })
                // 3. Unlocked explicitly for this paste view.
                .or_else(|| *recipient_session.read())
        };
        let Some(key) = recipient_key else {
            needs_account_password.set(true);
            progress.set(None);
            return;
        };
        return do_recipient_decrypt(
            &current_id,
            key,
            popup_ctx,
            try_count,
            ttl,
            progress,
            paste_content,
            burn_after_read,
            content_key,
            can_change_password,
            recipient_session,
        )
        .await;
    }

    let salt_bytes = match salt_result {
        Ok(response) => {
            if response.status >= 200 && response.status < 300 {
                if let Some(body) = response.body {
                    match bitcode::decode::<GetSaltResponse>(&body) {
                        Ok(decoded) => match decoded.salt {
                            Some(raw_salt) => {
                                salt.set(Some(raw_salt.clone()));
                                raw_salt
                            }
                            None => {
                                popup_ctx
                                    .write()
                                    .show_error(t!("error-decode-salt-failed", error: t!("recipient-mode-notice")));
                                progress.set(None);
                                return;
                            }
                        },
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

    // We only reach here for password-mode pastes (recipient pastes answer
    // the salt probe above), so a password is required now.
    if current_password.is_empty() {
        popup_ctx.write().show_error(t!("error-password-empty"));
        progress.set(None);
        return;
    }

    progress.set(Some(ProgressState {
        status: t!("progress-deriving-key"),
        progress: 40.0,
    }));

    // Derive the KEK and validation key from the password. The KEK later
    // unwraps the content key that arrives with the ciphertext; the
    // validation key produces the hash the server checks before streaming.
    let (kek, validation_key) = match derive_keys(&current_password, &salt_bytes) {
        Ok(kv) => kv,
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-key-derivation-failed", error: e));
            progress.set(None);
            return;
        }
    };

    let password_hash = compute_password_hash(&validation_key, &salt_bytes);
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
                if let Some(body) = response.body {
                    // The body is a length-prefixed metadata frame carrying the
                    // password-wrapped content key, followed by the ciphertext.
                    let (frame_header, ciphertext) = match split_paste_frame(&body) {
                        Ok(pair) => pair,
                        Err(e) => {
                            popup_ctx
                                .write()
                                .show_error(t!("error-decryption-failed", error: e));
                            progress.set(None);
                            return;
                        }
                    };
                    // Envelope pastes: unwrap the CEK from the frame's metadata.
                    // Legacy pastes have no envelope: the derived KEK IS the key.
                    let encryption_key = match frame_header.key {
                        Some(envelope) => {
                            match unwrap_content_key(
                                &envelope.wrapped_key,
                                &envelope.wrap_nonce,
                                &kek,
                            ) {
                                Ok(ck) => ck,
                                Err(e) => {
                                    popup_ctx
                                        .write()
                                        .show_error(t!("error-decryption-failed", error: e));
                                    progress.set(None);
                                    return;
                                }
                            }
                        }
                        None => kek,
                    };
                    content_key.set(Some(encryption_key));
                    old_password_hash.set(Some(password_hash));
                    try_count.set(Some(frame_header.try_count));
                    ttl.set(Some(frame_header.ttl));
                    burn_after_read.set(frame_header.burn_after_read);
                    let paste_total_chunks = frame_header.total_chunks;
                    let header_nonce = frame_header.nonce;
                    let header_burn_after_read = frame_header.burn_after_read;
                    let content = ciphertext;

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
                            if header_burn_after_read {
                                progress.set(Some(ProgressState {
                                    status: t!("burn-progress"),
                                    progress: 95.0,
                                }));
                                let receipt = compute_burn_receipt(&encryption_key);
                                let burn_result = do_xhr_post(
                                    &format!("{}/api/paste/{}/burn", BASE_URL, current_id),
                                    receipt.to_vec(),
                                    |_, _| {},
                                )
                                .await;
                                match burn_result {
                                    Ok(r) if r.status >= 200 && r.status < 300 => {
                                        popup_ctx.write().show_error(t!("burn-complete"));
                                    }
                                    Ok(r) if r.status == 410 => {
                                        // already burned
                                    }
                                    _ => {}
                                }
                            }
                            can_change_password.set(!header_burn_after_read);
                            paste_content.set(Some(PasteContent {
                                bytes: plaintext,
                                data_type: frame_header.data_type,
                                filename: frame_header.filename,
                                content_type: frame_header.content_type,
                                allow_download: frame_header.allow_download,
                            }));
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
                if let Some(body) = response.body
                    && let Ok(attempt) = bitcode::decode::<FailedAttempt>(&body)
                {
                    try_count.set(Some(attempt.try_count));
                    ttl.set(Some(attempt.ttl));
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Recipient-mode decryption: prove ownership of the recipient account (or
/// hold the sender's ephemeral key), then open the CEK via ECDH symmetry.
#[allow(clippy::too_many_arguments)]
async fn do_recipient_decrypt(
    current_id: &str,
    key: RecipientKey,
    mut popup_ctx: Signal<PopupContext>,
    mut try_count: Signal<Option<u32>>,
    mut ttl: Signal<Option<u64>>,
    mut progress: Signal<Option<ProgressState>>,
    mut paste_content: Signal<Option<PasteContent>>,
    mut burn_after_read: Signal<bool>,
    mut content_key: Signal<Option<[u8; 32]>>,
    mut can_change_password: Signal<bool>,
    mut recipient_session: Signal<Option<RecipientKey>>,
) {
    progress.set(Some(ProgressState {
        status: t!("recipient-authenticating"),
        progress: 30.0,
    }));

    let data_url = format!("{}/api/paste/{}/data", BASE_URL, current_id);

    // Round 1: fetch a single-use challenge sealed to the paste's stored
    // recipient public key, then present the solved proof on /data directly.
    let challenge_resp = do_xhr_get(
        &format!("{}/api/paste/{}/challenge", BASE_URL, current_id),
        vec![],
        |_, _| {},
    )
    .await;
    let challenge: Option<RecipientAuthChallenge> = match challenge_resp {
        Ok(r) if (200..300).contains(&r.status) => r
            .body
            .as_ref()
            .and_then(|b| bitcode::decode::<RecipientAuthChallenge>(b).ok()),
        _ => None,
    };
    let challenge = match challenge {
        Some(c) => c,
        None => {
            popup_ctx.write().show_error(t!("recipient-auth-failed"));
            progress.set(None);
            return;
        }
    };

    let response_nonce = match solve_account_challenge(&key.scalar, &challenge.challenge) {
        Ok(nonce) => nonce,
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-decryption-failed", error: e));
            progress.set(None);
            return;
        }
    };
    let proof = format!(
        "{}:{}",
        to_hex(&key.kid[..20]),
        general_purpose::STANDARD.encode(response_nonce)
    );

    progress.set(Some(ProgressState {
        status: t!("progress-downloading-content"),
        progress: 50.0,
    }));

    let content_result = do_xhr_get(
        &data_url,
        vec![("X-Account-Proof".to_string(), proof)],
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
        Ok(response) if response.status >= 200 && response.status < 300 => {
            let Some(body) = response.body else {
                popup_ctx.write().show_error(t!("error-empty-response"));
                progress.set(None);
                return;
            };
            let (frame_header, ciphertext) = match split_paste_frame(&body) {
                Ok(pair) => pair,
                Err(e) => {
                    popup_ctx
                        .write()
                        .show_error(t!("error-decryption-failed", error: e));
                    progress.set(None);
                    return;
                }
            };
            let Some(envelope) = frame_header.recipient.clone() else {
                popup_ctx
                    .write()
                    .show_error(t!("error-decryption-failed", error: "missing recipient envelope"));
                progress.set(None);
                return;
            };
            // ECDH symmetry: recipient (account scalar) and sender
            // (ephemeral scalar) both derive the same sealing key.
            let encryption_key = match open_content_key_for_recipient(
                &key.scalar,
                &envelope.ephemeral_pub,
                &envelope.nonce,
                &envelope.sealed_cek,
            ) {
                Ok(ck) => ck,
                Err(e) => {
                    popup_ctx
                        .write()
                        .show_error(t!("error-decryption-failed", error: e));
                    progress.set(None);
                    return;
                }
            };
            content_key.set(Some(encryption_key));
            try_count.set(None);
            ttl.set(Some(frame_header.ttl));
            burn_after_read.set(frame_header.burn_after_read);
            recipient_session.set(Some(key));
            let paste_total_chunks = frame_header.total_chunks;
            let header_nonce = frame_header.nonce;
            let header_burn_after_read = frame_header.burn_after_read;
            let content = ciphertext;

            let plaintext_size = match get_plaintext_size(paste_total_chunks, content.len()) {
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
            }
            .await;

            match result {
                Ok(()) => {
                    if header_burn_after_read {
                        let receipt = compute_burn_receipt(&encryption_key);
                        let burn_result = do_xhr_post(
                            &format!("{}/api/paste/{}/burn", BASE_URL, current_id),
                            receipt.to_vec(),
                            |_, _| {},
                        )
                        .await;
                        match burn_result {
                            Ok(r) if r.status >= 200 && r.status < 300 => {
                                popup_ctx.write().show_error(t!("burn-complete"));
                            }
                            Ok(r) if r.status == 410 => {}
                            _ => {}
                        }
                    }
                    can_change_password.set(false);
                    paste_content.set(Some(PasteContent {
                        bytes: plaintext,
                        data_type: frame_header.data_type,
                        filename: frame_header.filename,
                        content_type: frame_header.content_type,
                        allow_download: frame_header.allow_download,
                    }));
                    progress.set(None);
                }
                Err(e) => {
                    popup_ctx
                        .write()
                        .show_error(t!("error-decryption-failed", error: e.to_string()));
                    progress.set(None);
                }
            }
        }
        Ok(response) => {
            popup_ctx
                .write()
                .show_error(t!("error-get-paste-failed", status: response.status.to_string()));
            progress.set(None);
        }
        Err(e) => {
            popup_ctx
                .write()
                .show_error(t!("error-send-request-failed", error: e));
            progress.set(None);
        }
    }
}

struct ChangePasswordParams {
    current_id: String,
    new_password: String,
    content_key: [u8; 32],
    old_hash: [u8; 32],
    popup_ctx: Signal<PopupContext>,
    busy: Signal<bool>,
    new_password_input: Signal<String>,
    confirm_password_input: Signal<String>,
}

async fn do_change_password(params: ChangePasswordParams) {
    let ChangePasswordParams {
        current_id,
        new_password,
        content_key,
        old_hash,
        mut popup_ctx,
        mut busy,
        mut new_password_input,
        mut confirm_password_input,
    } = params;
    busy.set(true);
    let result: Result<(), String> = async {
        // Re-wrap the same content key under the new password; the ciphertext
        // itself is never touched.
        let setup = encrypt_setup(&new_password, &content_key)?;
        let request = ChangePasswordRequest {
            salt: setup.salt,
            password_hash: setup.password_hash,
            key: KeyEnvelope {
                wrap_nonce: setup.wrap_nonce,
                wrapped_key: setup.wrapped_key,
            },
        };
        let encoded_hash = general_purpose::STANDARD.encode(old_hash);
        let response = do_xhr_post_headers(
            &format!("{}/api/paste/{}/password", BASE_URL, current_id),
            bitcode::encode(&request),
            vec![("X-Password-Hash".to_string(), encoded_hash)],
            |_, _| {},
        )
        .await;
        match response {
            Ok(r) if r.status >= 200 && r.status < 300 => Ok(()),
            Ok(r) if r.status == 401 => Err(t!("error-change-password-expired").to_string()),
            Ok(r) => {
                Err(t!("error-change-password-failed", status: r.status.to_string()).to_string())
            }
            Err(e) => Err(t!("error-change-password-failed", status: e).to_string()),
        }
    }
    .await;
    busy.set(false);
    match result {
        Ok(()) => {
            new_password_input.set(String::new());
            confirm_password_input.set(String::new());
            popup_ctx
                .write()
                .show_success(t!("change-password-success"));
        }
        Err(e) => popup_ctx.write().show_error(e),
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
