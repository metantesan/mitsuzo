use crate::BASE_URL;
use crate::Route;
use crate::components::PopupContext;
use crate::sanitize_id;
use crate::utils::{do_xhr_get, do_xhr_post};
use base64::Engine as _;
use dioxus::prelude::*;
use dioxus_i18n::t;
use gloo_timers::future::TimeoutFuture;
use mitsuzo_types::{
    CHUNK_SIZE, CreatePasteHeader, CreatePasteResponse, DataType, GetStatsResponse, MAX_PASTE_SIZE,
};
use mitsuzo_utils::{encrypt_chunk_into, encrypt_setup};
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

#[derive(Clone, Debug)]
pub struct ProgressState {
    pub status: String,
    pub progress: f32,
}

#[component]
pub fn home_view() -> Element {
    let mut content = use_signal(String::new);
    let mut password_input = use_signal(String::new);
    let mut try_count_input = use_signal(|| "5".to_string());
    let mut ttl_seconds_input = use_signal(|| "43200".to_string());
    let mut generated_id: Signal<Option<String>> = use_signal(|| None);
    let mut bin_id_input = use_signal(String::new);
    let navigator = use_navigator();
    let mut file_data: Signal<Option<web_sys::File>> = use_signal(|| None);
    let mut file_name: Signal<Option<String>> = use_signal(|| None);
    let mut file_content_type: Signal<Option<String>> = use_signal(|| None);
    let mut progress: Signal<Option<ProgressState>> = use_signal(|| None);
    let mut popup_ctx = use_context::<Signal<PopupContext>>();
    let mut stats: Signal<Option<GetStatsResponse>> = use_signal(|| None);
    let auto_generated = use_signal(|| false);

    use_future(move || async move {
        let result = do_xhr_get(&format!("{}/api/paste/stats", BASE_URL), vec![], |_, _| {}).await;
        if let Ok(response) = result {
            if response.status >= 200 && response.status < 300 {
                if let Some(body) = response.body {
                    if let Ok(decoded) = bitcode::decode::<GetStatsResponse>(&body) {
                        stats.set(Some(decoded));
                    }
                }
            }
        }
    });

    let create_paste = {
        let mut auto_generated = auto_generated.clone();
        move |_| {
            spawn(async move {
                let password = password_input.read().clone();
                auto_generated.set(password.is_empty());
                let password = if password.is_empty() {
                    let mut buf = [0u8; 16];
                    let _ = getrandom::fill(&mut buf);
                    let auto_pw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
                    password_input.set(auto_pw.clone());
                    auto_pw
                } else {
                    password
                };

                progress.set(Some(ProgressState {
                    status: t!("progress-validating"),
                    progress: 10.0,
                }));

                let try_count = try_count_input.read().clone().parse::<u32>().ok();
                let mut ttl_seconds_option = ttl_seconds_input.read().clone().parse::<u32>().ok();
                if let Some(ref mut ts) = ttl_seconds_option {
                    if *ts > 43200 {
                        *ts = 43200;
                    }
                } else {
                    popup_ctx.write().show_error(t!("error-ttl-invalid"));
                    progress.set(None);
                    return;
                }

                let file_size_for_chunks: u64;
                let data_type: DataType;
                let mut text_fallback: Option<Vec<u8>> = None;
                if let Some(f) = file_data.read().as_ref() {
                    if f.size() as usize > MAX_PASTE_SIZE {
                        popup_ctx
                            .write()
                            .show_error("File exceeds maximum paste size");
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
                    progress.set(Some(ProgressState {
                        status: t!("progress-processing-text"),
                        progress: 20.0,
                    }));
                    file_size_for_chunks = text_content.len() as u64;
                    data_type = DataType::Text;
                    text_fallback = Some(text_content.into_bytes());
                }

                let (salt_bytes, nonce_bytes, encryption_key, password_hash) =
                    match encrypt_setup(&password) {
                        Ok(data) => data,
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
                    ((file_size_for_chunks as usize + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32
                };

                let header = CreatePasteHeader {
                    nonce: nonce_bytes,
                    salt: salt_bytes,
                    password_hash,
                    try_count,
                    ttl_seconds: ttl_seconds_option,
                    data_type,
                    filename: file_name.read().clone(),
                    content_type: file_content_type.read().clone(),
                    total_chunks,
                };

                let header_bytes = bitcode::encode(&header);
                let mut body = Vec::with_capacity(4 + header_bytes.len());
                body.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
                body.extend_from_slice(&header_bytes);

                let last_chunk_plain =
                    file_size_for_chunks as usize - (total_chunks as usize - 1) * CHUNK_SIZE;
                let enc_capacity = if total_chunks <= 1 {
                    file_size_for_chunks as usize + 16
                } else {
                    (total_chunks as usize - 1) * (CHUNK_SIZE + 16) + last_chunk_plain + 16
                };
                body.reserve(enc_capacity);

                progress.set(Some(ProgressState {
                    status: t!("progress-encrypting"),
                    progress: 30.0,
                }));

                let js_file = file_data.read().as_ref().cloned();

                match (text_fallback, js_file) {
                    (Some(text_bytes), _) => {
                        if let Err(e) = encrypt_chunk_into(
                            &text_bytes,
                            &encryption_key,
                            &nonce_bytes,
                            0,
                            &mut body,
                        ) {
                            popup_ctx
                                .write()
                                .show_error(t!("error-encryption-failed", error: e.to_string()));
                            progress.set(None);
                            return;
                        }
                    }
                    (_, Some(file)) => {
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
                                &mut body,
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
                    status: t!("progress-encrypting"),
                    progress: 50.0,
                }));

                progress.set(Some(ProgressState {
                    status: t!("progress-preparing-upload"),
                    progress: 50.0,
                }));

                let result = do_xhr_post(
                &format!("{}/api/paste", BASE_URL),
                body,
                |loaded, total| {
                    if total > 0 {
                        let percent = (loaded as f32 / total as f32) * 50.0;
                        let status_text = t!("progress-upload-percent", percent: format!("{:.0}", (percent / 50.0) * 100.0));
                        progress.set(Some(ProgressState {
                            status: status_text,
                            progress: 50.0 + percent,
                        }));
                    } else if loaded > 0 {
                        let status_text = t!("progress-upload-kb", kb: format!("{:.1}", loaded as f32 / 1024.0));
                        progress.set(Some(ProgressState {
                            status: status_text,
                            progress: 90.0,
                        }));
                    }
                },
            ).await;

                match result {
                    Ok(response) => {
                        if response.status >= 200 && response.status < 300 {
                            if let Some(resp_body) = response.body {
                                match bitcode::decode::<CreatePasteResponse>(&resp_body) {
                                    Ok(decoded_response) => {
                                        generated_id.set(Some(decoded_response.id.clone()));
                                        progress.set(Some(ProgressState {
                                            status: t!("progress-upload-complete"),
                                            progress: 100.0,
                                        }));
                                    }
                                    Err(e) => {
                                        popup_ctx.write().show_error(
                                            t!("error-parse-response-failed", error: e.to_string()),
                                        );
                                        progress.set(None);
                                    }
                                }
                            } else {
                                popup_ctx.write().show_error(t!("error-empty-response"));
                                progress.set(None);
                            }
                        } else {
                            popup_ctx.write().show_error(
                            t!("error-create-paste-failed", status: response.status.to_string()),
                        );
                            progress.set(None);
                        }
                    }
                    Err(e) => {
                        popup_ctx
                            .write()
                            .show_error(t!("error-send-request-failed", error: e));
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

    rsx! {
        div {
            class: "container mx-auto p-4 flex flex-col items-center justify-center min-h-screen",
            h1 {
                class: "text-4xl font-extrabold text-white mb-8",
                {t!("app-title")}
            }

            if let Some(prog) = progress.read().as_ref() {
                div {
                    class: "w-full max-w-xl mb-4 p-4 bg-gray-800 rounded-lg",
                    div {
                        class: "text-sm font-semibold mb-2 text-white text-center",
                        "{prog.status}"
                    }
                    div {
                        class: "w-full bg-gray-700 rounded-full h-3",
                        div {
                            class: "bg-blue-500 h-3 rounded-full transition-all duration-150",
                            style: "width: {prog.progress}%"
                        }
                    }
                }
            }

            if let Some(name) = file_name.read().as_ref() {
                div {
                    class: "w-full max-w-xl p-4 mb-4 bg-gray-700 text-white rounded-lg flex justify-between items-center",
                    span { "{name}" }
                    span {
                        class: "text-gray-400 text-sm ml-2",
                        "{file_size_text()}"
                    }
                    button {
                        class: "text-red-500 hover:text-red-700",
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
                    class: "w-full max-w-xl p-4 mb-4 bg-gray-800 text-white rounded-lg border border-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500",
                    rows: "10",
                    oninput: move |evt| content.set(evt.value()),
                    placeholder: "{t!(\"home-placeholder\")}",
                    value: "{content}"
                }
            }

            div {
                class: "w-full max-w-xl mb-4",
                label {
                    class: "block text-gray-400 text-sm font-bold mb-2",
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
                                if let Some(input) = input {
                                    if let Some(files) = input.files() {
                                        if let Some(file) = files.get(0) {
                                            progress.set(Some(ProgressState { status: "File loaded".to_string(), progress: 100.0 }));
                                            file_data.set(Some(file));
                                            file_name.set(Some(files.get(0).unwrap().name()));
                                            file_content_type.set(Some(files.get(0).unwrap().type_()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    label {
                        class: "w-full p-4 bg-gray-800 text-gray-400 rounded-lg border border-gray-700 border-dashed cursor-pointer block text-center",
                        "for": "file-upload",
                        {t!("choose-file")}
                    }
                }
            }

            input {
                class: "w-full max-w-xl p-4 bg-gray-800 text-white rounded-lg border border-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500",
                r#type: "password",
                placeholder: "{t!(\"password-placeholder\")}",
                oninput: move |evt| password_input.set(evt.value()),
                value: "{password_input}",
            }
            p {
                class: "w-full max-w-xl text-xs text-gray-500 mb-4 text-right",
                "Leave empty for auto-generated password"
            }
            div {
                class: "w-full max-w-xl flex space-x-4 mb-4",
                div {
                    class: "w-1/2",
                    label {
                        class: "block text-gray-400 text-sm font-bold mb-2",
                        {t!("try-count-label")}
                    }
                    input {
                        class: "w-full p-4 bg-gray-800 text-white rounded-lg border border-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500",
                        r#type: "number",
                        oninput: move |evt| try_count_input.set(evt.value()),
                        value: "{try_count_input}",
                    }
                }
                div {
                    class: "w-1/2",
                    label {
                        class: "block text-gray-400 text-sm font-bold mb-2",
                        {t!("ttl-label")}
                    }
                    input {
                        class: "w-full p-4 bg-gray-800 text-white rounded-lg border border-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500",
                        r#type: "number",
                        oninput: move |evt| ttl_seconds_input.set(evt.value()),
                        value: "{ttl_seconds_input}",
                        max: 43200
                    }
                }
            }
            button {
                class: "px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2",
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
                        class: "mt-4 p-4 bg-green-600 text-white rounded-lg shadow-md",
                        p { class: "font-bold text-lg", {{t!("paste-created")}} }
                        div {
                            class: "mt-2",
                            p { class: "text-sm text-green-200", "Full Link:" }
                            input {
                                class: "w-full p-2 mt-1 bg-green-700 text-white rounded text-sm font-mono",
                                value: "{paste_url}",
                                readonly: "true",
                                onclick: move |_| {},
                            }
                        }
                        div {
                            class: "mt-3 grid grid-cols-2 gap-2",
                            div {
                                p { class: "text-sm text-green-200", "Paste ID:" }
                                input {
                                    class: "w-full p-2 mt-1 bg-green-700 text-white rounded text-sm font-mono",
                                    value: "{id}",
                                    readonly: "true",
                                }
                            }
                            if is_auto {
                                div {
                                    p { class: "text-sm text-green-200", "Passcode:" }
                                    input {
                                        class: "w-full p-2 mt-1 bg-green-700 text-white rounded text-sm font-mono",
                                        value: "{password}",
                                        readonly: "true",
                                    }
                                }
                            }
                        }
                        p { class: "mt-2 text-xs text-green-200", {{t!("remember-password")}} }
                    }
                }
            })}

            div {
                class: "mt-8 w-full max-w-xl",
                h2 {
                    class: "text-2xl font-bold text-white mb-4",
                    {t!("view-existing-paste")}
                }
                input {
                    class: "w-full p-4 mb-4 bg-gray-800 text-white rounded-lg border border-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500",
                    r#type: "text",
                    placeholder: "{t!(\"enter-paste-id\")}",
                    oninput: move |evt| bin_id_input.set(sanitize_id(&evt.value())),
                    value: "{bin_id_input}",
                }
                button {
                    class: "px-6 py-3 bg-purple-600 text-white font-semibold rounded-lg shadow-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2",
                    onclick: go_to_paste,
                    {t!("view-paste")}
                }
            }

            div {
                class: "mt-8 w-full max-w-xl p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-xl font-bold text-white mb-4 text-center",
                    {t!("stats-title")}
                }
                p {
                    class: "text-xs text-gray-500 text-center mb-4",
                    {t!("stats-description")}
                }
                h3 {
                    class: "text-sm font-semibold text-white text-center",
                    {t!("all-time")}
                }
                div {
                    class: "grid grid-cols-3 gap-4 text-center",
                    div {
                        p { class: "text-2xl font-bold text-white", "{format_count(stats.read().as_ref().map(|s| s.pastes_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("created")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-green-400", "{format_count(stats.read().as_ref().map(|s| s.requests_success_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("decrypted")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-red-400", "{format_count(stats.read().as_ref().map(|s| s.requests_fail_all_time).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("wrong-password")} }
                    }
                }
                div {
                    class: "border-t border-gray-700 my-4"
                }
                h3 {
                    class: "text-sm font-semibold text-gray-400 text-center mb-2",
                    {t!("today")}
                }
                div {
                    class: "grid grid-cols-3 gap-4 text-center",
                    div {
                        p { class: "text-2xl font-bold text-white", "{format_count(stats.read().as_ref().map(|s| s.pastes_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("created")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-green-400", "{format_count(stats.read().as_ref().map(|s| s.requests_success_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("decrypted")} }
                    }
                    div {
                        p { class: "text-2xl font-bold text-red-400", "{format_count(stats.read().as_ref().map(|s| s.requests_fail_daily).unwrap_or(0))}" }
                        p { class: "text-sm text-gray-400", {t!("wrong-password")} }
                    }
                }
            }
        }
    }
}
