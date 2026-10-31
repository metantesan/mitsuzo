use dioxus::prelude::*;
use mitsuzo_utils::ContentCipherKind;

const CHUNK_SIZE: usize = 64 * 1024;
const MIB: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq)]
struct CipherResult {
    name: &'static str,
    encrypt_mib_s: f64,
    decrypt_mib_s: f64,
}

fn now_ms() -> Result<f64, String> {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|performance| performance.now())
        .ok_or_else(|| "High-resolution browser timer is unavailable".to_string())
}

async fn benchmark_cipher(
    cipher: ContentCipherKind,
    bytes: usize,
    mut progress: impl FnMut(usize) + 'static,
) -> Result<CipherResult, String> {
    let mut key = [0u8; 32];
    let mut nonce = vec![0u8; cipher.nonce_len()];
    getrandom::fill(&mut key).map_err(|error| format!("Random key generation failed: {error}"))?;
    getrandom::fill(&mut nonce)
        .map_err(|error| format!("Random nonce generation failed: {error}"))?;

    // The deterministic input keeps setup out of the timed section. The key and
    // base nonce are fresh for each run, just as they are for a new paste.
    let plaintext: Vec<u8> = (0..bytes)
        .map(|i| ((i * 31 + i / 251) & 0xff) as u8)
        .collect();
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE);
    let mut encrypted = Vec::with_capacity(bytes + chunk_count * 16);
    let encrypt_start = now_ms()?;
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        cipher.encrypt_chunk(&key, &nonce, index as u32, chunk, &mut encrypted)?;
        if (index + 1) % 64 == 0 && index + 1 < chunk_count {
            progress(((index + 1) * CHUNK_SIZE).min(bytes));
            gloo_timers::future::TimeoutFuture::new(0).await;
        }
    }
    let encrypt_seconds = ((now_ms()? - encrypt_start) / 1000.0).max(0.000_001);

    let mut decrypted_chunk = Vec::with_capacity(CHUNK_SIZE);
    let decrypt_start = now_ms()?;
    let mut offset = 0;
    for (index, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let end = offset + chunk.len() + 16;
        let encrypted_chunk = encrypted
            .get(offset..end)
            .ok_or_else(|| "Cipher produced an invalid chunk length".to_string())?;
        cipher.decrypt_chunk(
            &key,
            &nonce,
            index as u32,
            encrypted_chunk,
            &mut decrypted_chunk,
        )?;
        if decrypted_chunk != chunk {
            return Err(format!(
                "{} decryption did not match the input",
                cipher_name(cipher)
            ));
        }
        offset = end;
        decrypted_chunk.clear();
        if (index + 1) % 64 == 0 && index + 1 < chunk_count {
            progress(((index + 1) * CHUNK_SIZE).min(bytes));
            gloo_timers::future::TimeoutFuture::new(0).await;
        }
    }
    let decrypt_seconds = ((now_ms()? - decrypt_start) / 1000.0).max(0.000_001);
    let mib = bytes as f64 / MIB as f64;

    Ok(CipherResult {
        name: cipher_name(cipher),
        encrypt_mib_s: mib / encrypt_seconds,
        decrypt_mib_s: mib / decrypt_seconds,
    })
}

fn cipher_name(cipher: ContentCipherKind) -> &'static str {
    match cipher {
        ContentCipherKind::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        ContentCipherKind::XChaCha20Poly1305 => "XChaCha20-Poly1305",
    }
}

#[component]
pub fn benchmark_view() -> Element {
    let mut size_mib = use_signal(|| 8usize);
    let mut running = use_signal(|| false);
    let mut progress = use_signal(String::new);
    let mut results = use_signal(|| None::<Vec<CipherResult>>);
    let mut error = use_signal(|| None::<String>);

    let run = move |_| {
        if *running.read() {
            return;
        }
        let bytes = *size_mib.read() * MIB;
        running.set(true);
        results.set(None);
        error.set(None);
        progress.set("Preparing benchmark…".to_string());
        spawn(async move {
            let mut measured = Vec::with_capacity(2);
            for cipher in [
                ContentCipherKind::ChaCha20Poly1305,
                ContentCipherKind::XChaCha20Poly1305,
            ] {
                progress.set(format!("Measuring {}…", cipher_name(cipher)));
                let label = cipher_name(cipher).to_string();
                let progress_label = label.clone();
                let mut progress_signal = progress;
                match benchmark_cipher(cipher, bytes, move |completed| {
                    progress_signal.set(format!("{progress_label}: processed {completed} bytes"));
                })
                .await
                {
                    Ok(result) => measured.push(result),
                    Err(reason) => {
                        error.set(Some(format!("{label}: {reason}")));
                        running.set(false);
                        return;
                    }
                }
            }
            results.set(Some(measured));
            progress.set(String::new());
            running.set(false);
        });
    };

    let size_buttons = [1usize, 8, 32, 64];
    let raw_results = results.read().clone().unwrap_or_default();
    let max_rate = raw_results
        .iter()
        .map(|row| row.encrypt_mib_s.max(row.decrypt_mib_s))
        .fold(0.0, f64::max);
    let result_rows: Vec<(CipherResult, f64)> = raw_results
        .into_iter()
        .map(|row| {
            let width = if max_rate > 0.0 {
                row.encrypt_mib_s / max_rate * 100.0
            } else {
                0.0
            };
            (row, width)
        })
        .collect();

    rsx! {
        main {
            class: "max-w-4xl mx-auto px-4 py-10 text-text",
            header {
                class: "mb-10",
                p { class: "text-sm text-accent mb-3", "Browser performance lab" }
                h1 { class: "text-4xl sm:text-5xl font-bold tracking-tight mb-4", "How fast is encryption here?" }
                p { class: "max-w-2xl text-text-secondary leading-relaxed", "Measure the same Rust/WebAssembly content ciphers Mitsuzo uses for paste data. The benchmark runs on this device, in this browser, on one thread." }
            }

            section {
                class: "border border-border bg-surface rounded-xl p-5 sm:p-7 mb-7",
                div { class: "flex flex-col sm:flex-row sm:items-end sm:justify-between gap-5",
                    div {
                        p { class: "text-sm text-text-secondary mb-3", "Data size" }
                        div { class: "flex flex-wrap gap-2", role: "group", aria_label: "Benchmark data size",
                            for size in size_buttons {
                                button {
                                    class: if *size_mib.read() == size { "px-4 py-2 rounded-lg bg-accent text-bg font-semibold" } else { "px-4 py-2 rounded-lg border border-border text-text-secondary hover:text-text hover:border-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent" },
                                    disabled: *running.read(),
                                    aria_pressed: (*size_mib.read() == size).to_string(),
                                    onclick: move |_| size_mib.set(size),
                                    "{size} MiB"
                                }
                            }
                        }
                    }
                    button {
                        class: "px-6 py-3 rounded-lg bg-accent text-bg font-bold hover:bg-accent-hover disabled:opacity-50 disabled:cursor-wait focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
                        disabled: *running.read(),
                        onclick: run,
                        if *running.read() { "Running…" } else { "Run benchmark" }
                    }
                }
                p { class: "mt-5 text-xs leading-relaxed text-text-secondary", "Runs encrypt and decrypt over 64 KiB chunks, verifies decrypted bytes, and reports MiB/s. Key setup and random generation are excluded from the timings. Larger runs need more memory." }
            }

            if *running.read() {
                p { class: "mb-6 text-sm text-accent", role: "status", aria_live: "polite", "{progress}" }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "mb-6 p-4 rounded-lg border border-error/40 text-error bg-error/10", role: "alert", "Benchmark failed: {message}" }
            }

            if !result_rows.is_empty() {
                section {
                    class: "border border-border rounded-xl overflow-hidden",
                    div { class: "grid grid-cols-[minmax(9rem,1.4fr)_1fr_1fr] gap-3 px-5 py-3 bg-elevated text-xs text-text-secondary",
                        span { "Cipher" }
                        span { class: "text-right", "Encrypt · MiB/s" }
                        span { class: "text-right", "Decrypt · MiB/s" }
                    }
                    for item in result_rows.iter() {
                        div { class: "px-5 py-5 border-t border-border",
                            div { class: "grid grid-cols-[minmax(9rem,1.4fr)_1fr_1fr] gap-3 items-baseline",
                                span { class: "font-semibold", "{item.0.name}" }
                                span { class: "text-right font-mono text-lg", "{item.0.encrypt_mib_s:.1}" }
                                span { class: "text-right font-mono text-lg", "{item.0.decrypt_mib_s:.1}" }
                            }
                            div { class: "mt-4 h-1.5 rounded-full bg-elevated overflow-hidden",
                                div {
                                    class: "h-full bg-accent rounded-full",
                                    style: "width: {item.1}%"
                                }
                            }
                        }
                    }
                    p { class: "px-5 py-4 border-t border-border text-xs text-text-secondary", "These results describe this browser and device. The benchmark does not upload data or contact the server." }
                }
            } else if !*running.read() && error.read().is_none() {
                p { class: "text-sm text-text-secondary", "Choose a data size and run the test to see local results." }
            }
        }
    }
}
