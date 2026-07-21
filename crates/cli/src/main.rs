use base64::Engine;
use clap::{Parser, Subcommand};
use colored::*;
use mitsuzo_types::{
    CHUNK_SIZE, ChunkInfoResponse, CreatePasteHeader, DataType, GetSaltResponse, InitPasteResponse,
    UPLOAD_CHUNK_SIZE,
};
use mitsuzo_utils::{
    compute_password_hash, decrypt_chunk_into, derive_keys, encrypt_chunk_into, encrypt_setup,
    get_chunk_bounds, get_plaintext_size,
};
use reqwest::Client;
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
struct Config {
    base_url: Option<String>,
}

const DEFAULT_BASE_URL: &str = "http://localhost:3030";
const PARALLELISM: usize = 8;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long)]
    base_url: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(short, long)]
        file: Option<String>,
        #[arg(short = 'c', long, default_value = "5")]
        try_count: u32,
        #[arg(short, long, default_value = "43200")]
        ttl: u32,
    },
    Get {
        id: String,
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn get_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(runtime_dir) = dirs::runtime_dir() {
        paths.push(runtime_dir.join("mitsuzo/config.yml"));
    }
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("mitsuzo/config.yml"));
    }
    paths.push(PathBuf::from("/etc/mitsuzo/config.yml"));
    paths
}

fn load_config() -> Option<Config> {
    for path in get_config_paths() {
        if let Ok(file) = std::fs::File::open(path)
            && let Ok(config) = serde_yaml::from_reader(file)
        {
            return Some(config);
        }
    }
    None
}

fn full_chunk_cipher_len() -> usize {
    CHUNK_SIZE + 16
}

fn encrypted_size(total_size: u64, total_chunks: u32) -> usize {
    if total_chunks <= 1 {
        (total_size as usize) + 16
    } else if (total_size as usize) < (total_chunks as usize - 1) * CHUNK_SIZE {
        0
    } else {
        let full = (total_chunks as usize - 1) * full_chunk_cipher_len();
        let last = (total_size as usize) - (total_chunks as usize - 1) * CHUNK_SIZE + 16;
        full + last
    }
}

fn bar_template(main: &str, remainder: &str) -> indicatif::ProgressStyle {
    indicatif::ProgressStyle::with_template(&format!(
        "{{spinner:.cyan}} [{{bar:32.{main}}}] {{percent}}% {{msg}} {remainder}"
    ))
    .unwrap()
    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
    .progress_chars("━╾─")
}

fn make_pb(len: u64, main: &str, remainder: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(len);
    pb.set_style(bar_template(main, remainder));
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?;

    let base_url = cli
        .base_url
        .or_else(|| std::env::var("MITSUZO_BASE_URL").ok())
        .or_else(|| load_config().and_then(|c| c.base_url))
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    match &cli.command {
        Commands::Create {
            file,
            try_count,
            ttl,
        } => {
            let password = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Enter password:".cyan().bold()
            ))?);
            let password_confirm = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Confirm password:".cyan().bold()
            ))?);

            if password != password_confirm {
                eprintln!("{} Passwords do not match.", "Error:".red().bold());
                return Ok(());
            }

            let (content, data_type, filename) = if file.as_deref() == Some("-") || file.is_none() {
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                (buffer, DataType::Text, None)
            } else {
                let file_path = file.as_ref().unwrap();
                let data = std::fs::read(file_path)?;
                (
                    data,
                    DataType::File,
                    PathBuf::from(file_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(String::from),
                )
            };

            let total_enc_chunks = if content.is_empty() {
                1
            } else {
                content.len().div_ceil(CHUNK_SIZE) as u32
            };

            eprintln!(
                "{} {:.2} {} · {} encryption chunks",
                "Input:".bright_black(),
                indicatif::HumanBytes(content.len() as u64),
                if data_type == DataType::Text {
                    "(text)"
                } else {
                    "(file)"
                },
                total_enc_chunks
            );

            let (salt, nonce, mut encryption_key, password_hash) = encrypt_setup(&password)?;

            let header = CreatePasteHeader {
                nonce,
                salt,
                password_hash,
                try_count: Some(*try_count),
                ttl_seconds: Some(*ttl),
                data_type,
                filename,
                content_type: None,
                total_chunks: total_enc_chunks,
                allow_download: true,
            };

            let header_bytes = bitcode::encode(&header);

            let pb = make_pb(total_enc_chunks as u64, "blue", "");
            let done = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let results = Arc::new(std::sync::Mutex::new(Vec::new()));

            std::thread::scope(|s| {
                let n = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);
                let cpt = (total_enc_chunks as usize).div_ceil(n);

                for t in 0..n {
                    let sc = t * cpt;
                    let ec = std::cmp::min(sc + cpt, total_enc_chunks as usize);
                    if sc >= ec {
                        continue;
                    }
                    let k = encryption_key;
                    let nce = nonce;
                    let data = &content;
                    let done = &done;
                    let pb = &pb;
                    let results = &results;

                    s.spawn(move || {
                        let mut local = Vec::new();
                        for i in sc..ec {
                            let start = i * CHUNK_SIZE;
                            let end = std::cmp::min(start + CHUNK_SIZE, data.len());
                            let _ = encrypt_chunk_into(
                                &data[start..end],
                                &k,
                                &nce,
                                i as u32,
                                &mut local,
                            );
                            let prev = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            pb.set_position(prev as u64 + 1);
                            pb.set_message(indicatif::HumanBytes(local.len() as u64).to_string());
                        }
                        results.lock().unwrap().push((t, local));
                    });
                }
            });

            let mut results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
            results.sort_by_key(|(t, _)| *t);
            let ciphertext: Vec<u8> = results.into_iter().flat_map(|(_, buf)| buf).collect();
            encryption_key.zeroize();
            pb.finish_and_clear();

            let init_response = client
                .post(format!("{}/api/paste", base_url))
                .body(header_bytes)
                .send()
                .await?;

            if !init_response.status().is_success() {
                eprintln!(
                    "{} Failed to initialize paste: {}",
                    "Error:".red().bold(),
                    init_response.status()
                );
                return Ok(());
            }

            let init_body = init_response.bytes().await?;
            let decoded: InitPasteResponse = bitcode::decode(&init_body)?;
            let paste_id = decoded.id;

            let chunk_info = client
                .get(format!("{}/api/paste/{}/chunks", base_url, paste_id))
                .send()
                .await?;

            let start_chunk = if chunk_info.status().is_success() {
                if let Ok(body) = chunk_info.bytes().await {
                    bitcode::decode::<ChunkInfoResponse>(&body)
                        .map(|c| c.received)
                        .unwrap_or(0)
                } else {
                    0
                }
            } else {
                0
            };

            let total_up_chunks = ciphertext.len().div_ceil(UPLOAD_CHUNK_SIZE);

            let pb = make_pb(total_up_chunks as u64, "cyan/blue", "({pos}/{len} chunks)");
            pb.set_position(start_chunk as u64);

            let sem = Arc::new(Semaphore::new(PARALLELISM));
            let client = Arc::new(client);
            let pb = Arc::new(pb);
            let url = format!("{}/api/paste/{}/chunk", base_url, paste_id);
            let ct = Arc::new(ciphertext);

            let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut handles = Vec::new();
            for i in start_chunk..total_up_chunks as u32 {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let client = client.clone();
                let pb = pb.clone();
                let url = url.clone();
                let ct = ct.clone();
                let failed = failed.clone();

                handles.push(tokio::spawn(async move {
                    let cs = i as usize * UPLOAD_CHUNK_SIZE;
                    let ce = std::cmp::min(cs + UPLOAD_CHUNK_SIZE, ct.len());
                    let data = ct[cs..ce].to_vec();
                    for retry in 0..3 {
                        let resp = client
                            .put(format!("{}/{}", url, i))
                            .body(data.clone())
                            .send()
                            .await;
                        match resp {
                            Ok(r) if r.status().is_success() => {
                                pb.inc(1);
                                pb.set_message(indicatif::HumanBytes((ce - cs) as u64).to_string());
                                break;
                            }
                            _ if retry < 2 => {
                                tokio::time::sleep(Duration::from_secs(1 << retry)).await;
                            }
                            _ => {
                                failed.store(true, std::sync::atomic::Ordering::Relaxed);
                                pb.println(format!(
                                    "{} Chunk {} failed after 3 retries",
                                    "Error:".red().bold(),
                                    i
                                ));
                            }
                        }
                    }
                    drop(permit);
                }));
            }

            for h in handles {
                let _ = h.await;
            }
            pb.finish_and_clear();

            if failed.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "{} Upload incomplete — some chunks failed.",
                    "Error:".red().bold()
                );
                return Ok(());
            }

            let complete = client
                .post(format!("{}/api/paste/{}/complete", base_url, paste_id))
                .body(Vec::new())
                .send()
                .await?;

            if complete.status().is_success() {
                println!(
                    "{} Paste created with ID: {}",
                    "✓".green().bold(),
                    paste_id.yellow().bold()
                );
            } else {
                eprintln!("{} Failed to complete paste", "Error:".red().bold());
            }
        }
        Commands::Get { id, output } => {
            let password = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Enter password:".cyan().bold()
            ))?);

            let salt_resp = client
                .get(format!("{}/api/paste/{}/salt", base_url, id))
                .send()
                .await?;

            if !salt_resp.status().is_success() {
                eprintln!(
                    "{} Failed to get paste metadata: {}",
                    "Error:".red().bold(),
                    salt_resp.status()
                );
                return Ok(());
            }

            let salt_body = salt_resp.bytes().await?;
            let meta: GetSaltResponse = bitcode::decode(&salt_body)?;

            let enc_bytes = encrypted_size(meta.total_size, meta.total_chunks);

            eprintln!(
                "{} {:.2} plain · {} chunks · {:.2} encrypted",
                "Size:".bright_black(),
                indicatif::HumanBytes(meta.total_size),
                meta.total_chunks,
                indicatif::HumanBytes(enc_bytes as u64),
            );

            let (_encryption_key, mut vk) = derive_keys(&password, &meta.salt)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut ph = compute_password_hash(&vk, &meta.salt);
            let auth = base64::engine::general_purpose::STANDARD.encode(ph);
            ph.zeroize();
            vk.zeroize();

            let pb = make_pb(enc_bytes as u64, "green/yellow", "");
            let num_parts = PARALLELISM.clamp(1, 16);
            let part_size = (enc_bytes as u64).div_ceil(num_parts as u64);

            if enc_bytes == 0 {
                eprintln!(
                    "{} Paste appears incomplete (no data).",
                    "Error:".red().bold()
                );
                return Ok(());
            }

            let buf = Arc::new(std::sync::Mutex::new(vec![0u8; enc_bytes]));
            let dl_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let pb = Arc::new(pb);
            let client = Arc::new(client);
            let url = format!("{}/api/paste/{}/data", base_url, id);

            let mut dl = Vec::new();
            for p in 0..num_parts {
                let s = p as u64 * part_size;
                let e = (s + part_size - 1).min(enc_bytes as u64 - 1);
                if s > e {
                    continue;
                }
                let client = client.clone();
                let url = url.clone();
                let auth = auth.clone();
                let buf = buf.clone();
                let pb = pb.clone();
                let dl_failed = dl_failed.clone();

                dl.push(tokio::spawn(async move {
                    for retry in 0..3 {
                        let range = format!("bytes={}-{}", s, e);
                        if let Ok(resp) = client
                            .get(&url)
                            .header("X-Password-Hash", &auth)
                            .header("Range", &range)
                            .send()
                            .await
                            && let Ok(data) = resp.bytes().await
                        {
                            let mut b = buf.lock().unwrap();
                            b[s as usize..][..data.len()].copy_from_slice(&data);
                            pb.inc(data.len() as u64);
                            pb.set_message(
                                indicatif::HumanBytes(pb.position()).to_string(),
                            );
                            break;
                        }
                        if retry < 2 {
                            tokio::time::sleep(Duration::from_secs(1 << retry)).await;
                        } else {
                            dl_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }));
            }
            for h in dl {
                let _ = h.await;
            }
            pb.finish_and_clear();

            if dl_failed.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "{} Download incomplete — some ranges failed.",
                    "Error:".red().bold()
                );
                return Ok(());
            }

            let encrypted = Arc::try_unwrap(buf).unwrap().into_inner().unwrap();

            let (mut ek, _) = derive_keys(&password, &meta.salt)?;

            let done = Arc::new(AtomicU32::new(0));
            let total = meta.total_chunks;
            let pb = make_pb(total as u64, "magenta/yellow", "");

            let plain_size = get_plaintext_size(total, encrypted.len())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let out = Arc::new(std::sync::Mutex::new(Vec::with_capacity(plain_size)));

            std::thread::scope(|s| {
                let n = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);
                let cpt = (total as usize).div_ceil(n);

                for t in 0..n {
                    let sc = t * cpt;
                    let ec = std::cmp::min(sc + cpt, total as usize);
                    if sc >= ec {
                        continue;
                    }
                    let k = ek;
                    let nonce = meta.nonce;
                    let enc = &encrypted;
                    let out = &out;
                    let done = &done;
                    let pb = &pb;

                    s.spawn(move || {
                        let mut local = Vec::new();
                        for i in sc..ec {
                            let (a, b) = get_chunk_bounds(total, i as u32, enc.len());
                            let _ =
                                decrypt_chunk_into(&enc[a..b], &k, &nonce, i as u32, &mut local);
                            let prev = done.fetch_add(1, Ordering::Relaxed) as u64;
                            if prev.is_multiple_of(4) || prev + 1 == total as u64 {
                                pb.set_position(prev + 1);
                                pb.set_message(
                                    indicatif::HumanBytes(local.len() as u64).to_string(),
                                );
                            }
                        }
                        let mut o = out.lock().unwrap();
                        o.extend_from_slice(&local);
                    });
                }
            });

            ek.zeroize();
            pb.finish_and_clear();

            let decrypted = Arc::try_unwrap(out).unwrap().into_inner().unwrap();

            if let Some(output_path) = output {
                if output_path == "-" {
                    io::stdout().write_all(&decrypted)?;
                } else {
                    std::fs::write(output_path, &decrypted)?;
                    println!(
                        "{} Saved to {} ({:.2})",
                        "✓".green().bold(),
                        output_path.yellow(),
                        indicatif::HumanBytes(decrypted.len() as u64)
                    );
                }
            } else {
                match meta.data_type {
                    DataType::File => {
                        if let Some(fname) = meta.filename {
                            let safe = PathBuf::from(&fname)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map(String::from)
                                .unwrap_or_else(|| format!("paste_{}", id));
                            std::fs::write(&safe, &decrypted)?;
                            println!(
                                "{} Saved to {} ({:.2})",
                                "✓".green().bold(),
                                safe.yellow(),
                                indicatif::HumanBytes(decrypted.len() as u64)
                            );
                        } else {
                            io::stdout().write_all(&decrypted)?;
                        }
                    }
                    DataType::Text => {
                        io::stdout().write_all(&decrypted)?;
                    }
                }
            }
        }
    }

    Ok(())
}
