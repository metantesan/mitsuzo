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

#[derive(Clone, PartialEq)]
struct BenchmarkProgress {
    step: usize,
    phase: &'static str,
    cipher: String,
    completed_chunks: usize,
    total_chunks: usize,
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
    mut progress: impl FnMut(&'static str, usize, usize) + 'static,
) -> Result<CipherResult, String> {
    let mut key = [0u8; 32];
    let mut nonce = vec![0u8; cipher.nonce_len()];
    getrandom::fill(&mut key).map_err(|error| format!("Random key generation failed: {error}"))?;
    getrandom::fill(&mut nonce)
        .map_err(|error| format!("Random nonce generation failed: {error}"))?;

    // Reuse one 64 KiB buffer so large runs measure cipher throughput without
    // allocating the entire file and ciphertext in browser memory.
    let plaintext: Vec<u8> = (0..CHUNK_SIZE)
        .map(|i| ((i * 31 + i / 251) & 0xff) as u8)
        .collect();
    let chunk_count = bytes.div_ceil(CHUNK_SIZE);
    let mut encrypted = Vec::with_capacity(CHUNK_SIZE + 16);
    let mut paused_ms = 0.0;
    progress("Encrypting", 0, chunk_count);
    gloo_timers::future::TimeoutFuture::new(0).await;
    let encrypt_start = now_ms()?;
    for index in 0..chunk_count {
        let offset = index * CHUNK_SIZE;
        let chunk_len = (bytes - offset).min(CHUNK_SIZE);
        encrypted.clear();
        cipher.encrypt_chunk(
            &key,
            &nonce,
            index as u32,
            &plaintext[..chunk_len],
            &mut encrypted,
        )?;
        if (index + 1) % 64 == 0 && index + 1 < chunk_count {
            let pause_start = now_ms()?;
            progress("Encrypting", index + 1, chunk_count);
            gloo_timers::future::TimeoutFuture::new(0).await;
            paused_ms += now_ms()? - pause_start;
        }
    }
    progress("Encrypting", chunk_count, chunk_count);
    let encrypt_seconds = ((now_ms()? - encrypt_start - paused_ms) / 1000.0).max(0.000_001);

    // Precompute a bounded pool of ciphertexts outside the timed section.
    // Cycling through distinct chunk indexes exercises nonce derivation while
    // avoiding hundreds of MiB of retained ciphertext at the 1 GiB setting.
    let decrypt_pool_len = chunk_count.min(256);
    let mut encrypted_pool = Vec::with_capacity(decrypt_pool_len);
    progress("Preparing decryption samples", 0, decrypt_pool_len);
    gloo_timers::future::TimeoutFuture::new(0).await;
    for index in 0..decrypt_pool_len {
        let mut chunk_ciphertext = Vec::with_capacity(CHUNK_SIZE + 16);
        cipher.encrypt_chunk(
            &key,
            &nonce,
            index as u32,
            &plaintext,
            &mut chunk_ciphertext,
        )?;
        encrypted_pool.push(chunk_ciphertext);
        if (index + 1) % 64 == 0 && index + 1 < decrypt_pool_len {
            progress("Preparing decryption samples", index + 1, decrypt_pool_len);
            gloo_timers::future::TimeoutFuture::new(0).await;
        }
    }
    progress(
        "Preparing decryption samples",
        decrypt_pool_len,
        decrypt_pool_len,
    );

    let mut decrypted_chunk = Vec::with_capacity(CHUNK_SIZE);
    let mut decrypt_paused_ms = 0.0;
    progress("Decrypting", 0, chunk_count);
    gloo_timers::future::TimeoutFuture::new(0).await;
    let decrypt_start = now_ms()?;
    for index in 0..chunk_count {
        let pool_index = index % decrypt_pool_len;
        let chunk_ciphertext = &encrypted_pool[pool_index];
        cipher.decrypt_chunk(
            &key,
            &nonce,
            pool_index as u32,
            chunk_ciphertext,
            &mut decrypted_chunk,
        )?;
        if decrypted_chunk != plaintext {
            return Err(format!(
                "{} decryption did not match the input",
                cipher_name(cipher)
            ));
        }
        decrypted_chunk.clear();
        if (index + 1) % 64 == 0 && index + 1 < chunk_count {
            let pause_start = now_ms()?;
            progress("Decrypting", index + 1, chunk_count);
            gloo_timers::future::TimeoutFuture::new(0).await;
            decrypt_paused_ms += now_ms()? - pause_start;
        }
    }
    progress("Decrypting", chunk_count, chunk_count);
    let decrypt_seconds = ((now_ms()? - decrypt_start - decrypt_paused_ms) / 1000.0).max(0.000_001);
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
    let mut progress = use_signal(|| None::<BenchmarkProgress>);
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
        progress.set(Some(BenchmarkProgress {
            step: 0,
            phase: "Preparing benchmark",
            cipher: "Both ciphers".to_string(),
            completed_chunks: 0,
            total_chunks: 1,
        }));
        spawn(async move {
            let mut measured = Vec::with_capacity(2);
            for (cipher_index, cipher) in [
                ContentCipherKind::ChaCha20Poly1305,
                ContentCipherKind::XChaCha20Poly1305,
            ]
            .into_iter()
            .enumerate()
            {
                let label = cipher_name(cipher).to_string();
                let mut progress_signal = progress;
                match benchmark_cipher(cipher, bytes, move |phase, completed, total| {
                    let step = if phase == "Encrypting" {
                        cipher_index * 2 + 1
                    } else {
                        cipher_index * 2 + 2
                    };
                    progress_signal.set(Some(BenchmarkProgress {
                        step,
                        phase,
                        cipher: label.clone(),
                        completed_chunks: completed,
                        total_chunks: total,
                    }));
                })
                .await
                {
                    Ok(result) => measured.push(result),
                    Err(reason) => {
                        error.set(Some(format!("{}: {reason}", cipher_name(cipher))));
                        progress.set(None);
                        running.set(false);
                        return;
                    }
                }
            }
            results.set(Some(measured));
            progress.set(None);
            running.set(false);
        });
    };

    let size_buttons = [1usize, 8, 64, 256, 1024];
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
    let current_progress = progress.read().clone();

    rsx! {
        main {
            class: "max-w-4xl mx-auto px-4 py-10 text-text",
            header {
                class: "mb-10",
                p { class: "text-sm text-accent mb-3", "Browser performance lab" }
                h1 { class: "text-4xl sm:text-5xl font-bold tracking-tight mb-4", "How fast is encryption here?" }
                p { class: "max-w-2xl text-text-secondary leading-relaxed", "Measure the Rust/WebAssembly content ciphers Mitsuzo uses for paste data. It runs locally in this browser on one thread." }
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
                                    if size == 1024 { "1 GiB" } else { "{size} MiB" }
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
                p { class: "mt-5 text-xs leading-relaxed text-text-secondary", "Runs encrypt and decrypt over 64 KiB chunks, verifies decrypted bytes, and reports MiB/s. A single reusable chunk is used, so large sizes do not need a matching amount of memory. Timer pauses for UI updates are excluded. This measures cipher throughput; browser file reads, full-paste buffering, and network upload are not included." }
            }

            if let Some(current) = current_progress.as_ref() {
                {
                    let percent = if current.total_chunks == 0 {
                        0.0
                    } else {
                        current.completed_chunks as f64 / current.total_chunks as f64 * 100.0
                    };
                    let completed_mib = current.completed_chunks * CHUNK_SIZE / MIB;
                    let total_mib = (current.total_chunks * CHUNK_SIZE).min(*size_mib.read() * MIB) / MIB;
                    rsx! {
                        div {
                            class: "fixed bottom-4 right-4 z-50 w-[calc(100vw-2rem)] max-w-sm rounded-xl border border-border bg-surface p-4 shadow-2xl",
                            role: "status",
                            aria_live: "polite",
                            div { class: "flex items-start justify-between gap-4",
                                div {
                                    p { class: "text-xs font-semibold uppercase tracking-wide text-accent",
                                        if current.step == 0 { "Setup" } else { "Step {current.step} of 4" }
                                    }
                                    p { class: "mt-1 font-semibold text-text", "{current.cipher}" }
                                    p { class: "text-sm text-text-secondary", "{current.phase}" }
                                }
                                span { class: "shrink-0 font-mono text-sm text-text", "{percent:.0}%" }
                            }
                            div { class: "mt-4 h-2 overflow-hidden rounded-full bg-elevated",
                                div {
                                    class: "h-full rounded-full bg-accent transition-[width] duration-200",
                                    style: "width: {percent}%"
                                }
                            }
                            p { class: "mt-2 text-xs text-text-secondary",
                                "{current.completed_chunks} / {current.total_chunks} chunks · {completed_mib} / {total_mib} MiB"
                            }
                            if current.phase == "Preparing decryption samples" {
                                p { class: "mt-1 text-xs text-text-secondary", "Preparing a bounded sample set for the decrypt pass." }
                            }
                        }
                    }
                }
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
