use base64::Engine;
use bip39::Mnemonic;
use clap::{Parser, Subcommand};
use colored::*;
use mitsuzo_types::{
    AccountKeyBlob, AccountProfileResponse, CHUNK_SIZE, ChangePasswordRequest, ChunkInfoResponse,
    CreatePasteHeader, DataType, GetSaltResponse, InitPasteResponse, KeyEnvelope, PasteAuthMode,
    PasteRecipientInfo, RecipientAuthChallenge, RecipientEnvelope, RegisterAccountRequest,
    UPLOAD_CHUNK_SIZE, split_paste_frame,
};
use mitsuzo_utils::{
    compute_burn_receipt, compute_password_hash, decrypt_chunk_into, derive_account_scalar,
    derive_keys, encrypt_chunk_into, encrypt_setup, generate_content_key, generate_x25519_keypair,
    get_chunk_bounds, get_ciphertext_size, kid_from_pubkey, lock_account_key, open_challenge,
    open_content_key_for_recipient, pubkey_from_scalar, seal_content_key_for_recipient,
    unlock_account_key, unwrap_content_key,
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
        #[arg(short = 'b', long)]
        burn_after_read: bool,
        /// Encrypt to a user account kid (0x… prefix or full hash) instead of a password.
        #[arg(short = 'T', long)]
        to: Option<String>,
    },
    Get {
        id: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    Passwd {
        id: String,
    },
    Account {
        #[command(subcommand)]
        action: AccountCommand,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Create a new account: generates a 24-word seed phrase, shows it once
    /// for backup, locks the derived key in ~/.config/mitsuzo/account.enc
    /// and registers the public key with the server.
    Register {
        #[arg(short, long)]
        name: String,
    },
    /// Unlock the local account and print its profile.
    Login {},
    /// Recover a local account from an existing seed phrase.
    Import {
        #[arg(short, long)]
        name: String,
        phrase: Option<String>,
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

fn account_path() -> PathBuf {
    dirs::config_dir()
        .map(|d| d.join("mitsuzo/account.enc"))
        .unwrap_or_else(|| PathBuf::from("account.enc"))
}

fn read_account_blob() -> eyre::Result<AccountKeyBlob> {
    let bytes = std::fs::read(account_path())?;
    Ok(bitcode::decode(&bytes)?)
}

fn write_account_blob(blob: &AccountKeyBlob) -> eyre::Result<()> {
    if let Some(parent) = account_path().parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(account_path(), bitcode::encode(blob))?;
    Ok(())
}

/// Unlock the local account blob with the account password, returning
/// `(scalar, pubkey, kid)`.
fn unlock_account(password: &str) -> eyre::Result<([u8; 32], [u8; 32], [u8; 32])> {
    let blob = read_account_blob()?;
    let scalar = unlock_account_key(&blob, password).map_err(|e| eyre::eyre!("{}", e))?;
    let pubkey = pubkey_from_scalar(&scalar);
    let kid = kid_from_pubkey(&pubkey);
    Ok((scalar, pubkey, kid))
}

fn generate_mnemonic() -> eyre::Result<String> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)?;
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    Ok(mnemonic.to_string())
}

type KeyMaterial = (String, [u8; 32], [u8; 32], [u8; 32]);

fn mnemonic_to_scalar(phrase: &str) -> eyre::Result<KeyMaterial> {
    let mnemonic = Mnemonic::parse(phrase.trim())?;
    let seed = mnemonic.to_seed("");
    let scalar = derive_account_scalar(&seed);
    let pubkey = pubkey_from_scalar(&scalar);
    let kid = kid_from_pubkey(&pubkey);
    Ok((mnemonic.to_string(), scalar, pubkey, kid))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn prompt_new_password() -> eyre::Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password(format!(
        "{} ",
        "Account password:".cyan().bold()
    ))?);
    let confirm =
        rpassword::prompt_password(format!("{} ", "Confirm account password:".cyan().bold()))?;
    if password.as_str() != confirm {
        eyre::bail!("{} Passwords do not match.", "Error:".red().bold());
    }
    Ok(password)
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

fn print_profile(label: &str, profile: &AccountProfileResponse) {
    println!("{}", label.cyan().bold());
    println!("  Name:   {}", profile.name);
    println!("  Kid:    0x{}", hex(&profile.kid_prefix));
    println!("  Pubkey: 0x{}", hex(&profile.pubkey));
}

fn prompt_mnemonic() -> eyre::Result<Option<String>> {
    eprint!("{} ", "Seed phrase (24 words):".cyan());
    io::stdout().flush()?;
    let mut phrase = String::new();
    io::stdin().read_line(&mut phrase)?;
    let phrase = phrase.trim().to_string();
    if phrase.is_empty() {
        Ok(None)
    } else {
        Ok(Some(phrase))
    }
}

/// Register a new account from a generated or imported seed phrase. Derives
/// the X25519 key, locks it in `~/.config/mitsuzo/account.enc` (same blob
/// format as the browser), and POSTs the public profile to the server.
async fn register_account(
    client: &Client,
    base_url: &str,
    name: &str,
    phrase: Option<String>,
) -> eyre::Result<()> {
    let (normalized, scalar, pubkey, kid) = match phrase {
        Some(phrase) => mnemonic_to_scalar(&phrase)?,
        None => {
            let mnemonic = generate_mnemonic()?;
            eprintln!(
                "{}",
                "Your one-time backup seed phrase — write it down, it is the only way to recover this account:"
                    .yellow()
                    .bold()
            );
            eprintln!("{}", mnemonic.yellow().bold());
            eprint!("{} ", "Press Enter after you have backed it up.".cyan());
            io::stdout().flush()?;
            io::stdin().read_line(&mut String::new())?;
            mnemonic_to_scalar(&mnemonic)?
        }
    };
    let _ = normalized;
    let password = prompt_new_password()?;
    let blob = lock_account_key(&scalar, &password)
        .map_err(|e| eyre::eyre!("Failed to lock account key: {}", e))?;
    write_account_blob(&blob)?;

    let request = RegisterAccountRequest {
        kid,
        pubkey,
        name: name.to_string(),
    };
    let resp = client
        .post(format!("{}/api/account", base_url))
        .body(bitcode::encode(&request))
        .send()
        .await?;
    if resp.status().is_success() {
        let profile: AccountProfileResponse = bitcode::decode(&resp.bytes().await?)?;
        print_profile("Registered account:", &profile);
    } else if resp.status() == reqwest::StatusCode::CONFLICT {
        eprintln!(
            "{} An account with this key already exists — use `mitsuzo account login` instead.",
            "Error:".red().bold()
        );
    } else {
        eprintln!(
            "{} Failed to register account: {}",
            "Error:".red().bold(),
            resp.status()
        );
    }
    Ok(())
}

/// Unlock the local account blob and fetch/print the public profile.
async fn login_account(client: &Client, base_url: &str) -> eyre::Result<()> {
    let password = Zeroizing::new(rpassword::prompt_password(format!(
        "{} ",
        "Account password:".cyan().bold()
    ))?);
    let (_scalar, _pubkey, kid) =
        unlock_account(&password).map_err(|e| eyre::eyre!("{} {}", "Error:".red().bold(), e))?;
    let resp = client
        .get(format!("{}/api/account/{}", base_url, hex(&kid)))
        .send()
        .await?;
    if resp.status().is_success() {
        let profile: AccountProfileResponse = bitcode::decode(&resp.bytes().await?)?;
        print_profile("Logged in as:", &profile);
    } else {
        eprintln!(
            "{} Failed to fetch account profile: {}",
            "Error:".red().bold(),
            resp.status()
        );
    }
    Ok(())
}

/// Fetch a recipient-mode paste by proving ownership of the local account.
/// The server issues a single-use challenge and returns it on the challenge
/// endpoint; we solve it and present `X-Account-Proof` on `/data`. The
/// challenge is single-use, so the body is fetched in one request rather than
/// parallel ranges.
async fn account_paste_get(
    client: &Client,
    base_url: &str,
    id: &str,
    output: &Option<String>,
    recipient: Option<&PasteRecipientInfo>,
) -> eyre::Result<()> {
    let password = Zeroizing::new(rpassword::prompt_password(format!(
        "{} ",
        "Account password:".cyan().bold()
    ))?);
    let (scalar, _pubkey, kid) = unlock_account(&password)?;

    // The salt probe already told us who this paste belongs to — check it
    // before issuing any challenge, so a wrong account produces a clear
    // message instead of an opaque AEAD failure.
    if let Some(info) = recipient
        && info.kid != kid
    {
        let name = info.name.as_deref().unwrap_or("an unknown account");
        eprintln!(
            "{} This paste is encrypted to {} (0x{}). Your account is 0x{} — you are not the recipient.",
            "Error:".red().bold(),
            name,
            hex(&info.kid_prefix),
            hex(&kid[..20]),
        );
        return Ok(());
    }

    let data_url = format!("{}/api/paste/{}/data", base_url, id);

    // Round 1: fetch a single-use challenge sealed to the paste's stored
    // recipient public key, then present the solved proof on /data directly.
    let challenge_resp = client
        .get(format!("{}/api/paste/{}/challenge", base_url, id))
        .send()
        .await?;
    let status = challenge_resp.status();
    let body = challenge_resp.bytes().await?;
    if !status.is_success() {
        eprintln!(
            "{} Failed to fetch challenge: {}",
            "Error:".red().bold(),
            status
        );
        return Ok(());
    }
    let challenge: RecipientAuthChallenge = match bitcode::decode(&body) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("{} Invalid challenge body.", "Error:".red().bold());
            return Ok(());
        }
    };

    let response_nonce = match open_challenge(
        &scalar,
        &challenge.challenge.ephemeral_pub,
        &challenge.challenge.nonce,
        &challenge.challenge.sealed,
    ) {
        Ok(nonce) => nonce,
        Err(_) => {
            eprintln!(
                "{} Failed to solve the account challenge — wrong account password?",
                "Error:".red().bold()
            );
            return Ok(());
        }
    };
    let proof = format!(
        "{}:{}",
        hex(&kid[..20]),
        base64::engine::general_purpose::STANDARD.encode(response_nonce)
    );

    // Round 2: full-body request with the proof.
    let data_resp = client
        .get(&data_url)
        .header("X-Account-Proof", proof)
        .send()
        .await?;
    if !data_resp.status().is_success() {
        eprintln!(
            "{} Failed to fetch paste: {}",
            "Error:".red().bold(),
            data_resp.status()
        );
        return Ok(());
    }
    let body = data_resp.bytes().await?;
    let (frame_header, ciphertext) =
        split_paste_frame(&body).map_err(|e| eyre::eyre!("Invalid paste frame: {}", e))?;
    let Some(recipient) = frame_header.recipient.clone() else {
        eprintln!("{} Missing recipient envelope.", "Error:".red().bold());
        return Ok(());
    };
    let ek = match open_content_key_for_recipient(
        &scalar,
        &recipient.ephemeral_pub,
        &recipient.nonce,
        &recipient.sealed_cek,
    ) {
        Ok(key) => key,
        Err(e) => {
            eprintln!(
                "{} Failed to open content key: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(());
        }
    };

    eprintln!(
        "{} {:.2} plain · {} chunks · {:.2} encrypted",
        "Size:".bright_black(),
        indicatif::HumanBytes(frame_header.total_size),
        frame_header.total_chunks,
        indicatif::HumanBytes(get_ciphertext_size(frame_header.total_size as usize) as u64),
    );

    finish_decrypt(
        client,
        base_url,
        id,
        &frame_header,
        ek,
        ciphertext.to_vec(),
        output,
    )
    .await
}

/// Shared tail of `get`: send the burn receipt (if any), decrypt all chunks,
/// and write the plaintext to stdout, a file, or a path.
async fn finish_decrypt(
    client: &Client,
    base_url: &str,
    id: &str,
    meta: &mitsuzo_types::GetPasteHeader,
    mut ek: [u8; 32],
    encrypted: Vec<u8>,
    output: &Option<String>,
) -> eyre::Result<()> {
    if meta.burn_after_read {
        let receipt = compute_burn_receipt(&ek);
        let burn_resp = client
            .post(format!("{}/api/paste/{}/burn", base_url, id))
            .body(receipt.to_vec())
            .send()
            .await?;
        match burn_resp.status() {
            s if s.is_success() => {
                eprintln!("{} Paste burned after reading", "✓".green().bold());
            }
            s if s == reqwest::StatusCode::GONE => {}
            _ => {}
        }
    }

    let done = Arc::new(AtomicU32::new(0));
    let total = meta.total_chunks;
    let pb = make_pb(total as u64, "magenta/yellow", "");

    // Collect each thread's decrypted region keyed by region index; threads
    // finish in arbitrary order, so appending directly would jumble output.
    type Region = (usize, Vec<u8>);
    let results: Arc<std::sync::Mutex<Vec<Region>>> = Arc::new(std::sync::Mutex::new(
        Vec::with_capacity((total as usize) + 1),
    ));

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
            let results = &results;
            let done = &done;
            let pb = &pb;

            s.spawn(move || {
                let mut local = Vec::new();
                for i in sc..ec {
                    let (a, b) = get_chunk_bounds(total, i as u32, enc.len());
                    let _ = decrypt_chunk_into(&enc[a..b], &k, &nonce, i as u32, &mut local);
                    let prev = done.fetch_add(1, Ordering::Relaxed) as u64;
                    if prev.is_multiple_of(4) || prev + 1 == total as u64 {
                        pb.set_position(prev + 1);
                        pb.set_message(indicatif::HumanBytes(local.len() as u64).to_string());
                    }
                }
                // Store by region index: threads finish in arbitrary order, so
                // appending directly would jumble the plaintext.
                let mut r = results.lock().unwrap();
                r.push((t, local));
            });
        }
    });

    ek.zeroize();
    pb.finish_and_clear();

    let mut results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    results.sort_by_key(|(t, _)| *t);
    let decrypted: Vec<u8> = results.into_iter().flat_map(|(_, buf)| buf).collect();

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
        match &meta.data_type {
            DataType::File => {
                if let Some(fname) = &meta.filename {
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
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
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
            burn_after_read,
            to,
        } => {
            // Recipient mode: resolve the target account's public key first.
            let recipient_profile = if let Some(to) = &to {
                let resp = client
                    .get(format!("{}/api/account/{}", base_url, to))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    eyre::bail!(
                        "{} Failed to look up account {}: HTTP {}",
                        "Error:".red().bold(),
                        to,
                        resp.status()
                    );
                }
                let profile: AccountProfileResponse = bitcode::decode(&resp.bytes().await?)?;
                eprintln!(
                    "{} Encrypting to account {} (0x{})",
                    "Recipient:".cyan().bold(),
                    profile.name,
                    hex(&profile.kid_prefix)
                );
                Some(profile)
            } else {
                None
            };

            let password = if recipient_profile.is_none() {
                Some(Zeroizing::new(rpassword::prompt_password(format!(
                    "{} ",
                    "Enter password:".cyan().bold()
                ))?))
            } else {
                None
            };
            if let Some(password) = &password {
                let password_confirm = Zeroizing::new(rpassword::prompt_password(format!(
                    "{} ",
                    "Confirm password:".cyan().bold()
                ))?);
                if password.as_str() != password_confirm.as_str() {
                    eprintln!("{} Passwords do not match.", "Error:".red().bold());
                    return Ok(());
                }
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

            let content_key = Zeroizing::new(
                generate_content_key().map_err(|e| eyre::eyre!("Key generation failed: {}", e))?,
            );

            let recipient = recipient_profile.as_ref();
            let (salt, nonce, password_hash, key_envelope, envelope, recipient_pub) =
                if let Some(profile) = recipient {
                    // Recipient mode: no password setup; seal the CEK to the
                    // recipient account's public key via X25519 ECDH.
                    let mut base_nonce = [0u8; 12];
                    getrandom::fill(&mut base_nonce)?;
                    let (eph_priv, eph_pub) = generate_x25519_keypair()
                        .map_err(|e| eyre::eyre!("Keypair generation failed: {}", e))?;
                    let (env_nonce, sealed_cek) =
                        seal_content_key_for_recipient(&eph_priv, &profile.pubkey, &content_key)
                            .map_err(|e| eyre::eyre!("Failed to seal content key: {}", e))?;
                    let envelope = RecipientEnvelope {
                        recipient_kid: profile.kid,
                        ephemeral_pub: eph_pub,
                        nonce: env_nonce,
                        sealed_cek,
                    };
                    (
                        None,
                        base_nonce,
                        None,
                        None,
                        Some(envelope),
                        Some(profile.pubkey),
                    )
                } else {
                    let setup =
                        encrypt_setup(password.as_ref().map_or("", |p| p.as_str()), &content_key)
                            .map_err(|e| eyre::eyre!("Encryption setup failed: {}", e))?;
                    let key_envelope = KeyEnvelope {
                        wrap_nonce: setup.wrap_nonce,
                        wrapped_key: setup.wrapped_key,
                    };
                    (
                        Some(setup.salt),
                        setup.base_nonce,
                        Some(setup.password_hash),
                        Some(key_envelope),
                        None,
                        None,
                    )
                };

            let mut header = CreatePasteHeader {
                nonce,
                salt,
                password_hash,
                key: key_envelope,
                try_count: if envelope.is_some() {
                    None
                } else {
                    Some(*try_count)
                },
                ttl_seconds: Some(*ttl),
                data_type,
                filename,
                content_type: None,
                total_chunks: total_enc_chunks,
                allow_download: true,
                burn_after_read: *burn_after_read,
                burn_receipt_hash: [0u8; 32],
                recipient: envelope,
                recipient_pub,
            };

            if *burn_after_read {
                header.burn_receipt_hash = compute_burn_receipt(&content_key);
            }

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
                    let k = *content_key;
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
            drop(content_key);
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
            let salt_info = bitcode::decode::<GetSaltResponse>(&salt_body)?;

            // `mode: Recipient` ⇒ the paste is sealed to a user account
            // instead of a password: prove ownership via the account
            // challenge flow.
            if salt_info.mode == PasteAuthMode::Recipient {
                return account_paste_get(
                    &client,
                    &base_url,
                    id,
                    output,
                    salt_info.recipient.as_ref(),
                )
                .await;
            }
            let Some(salt_bytes) = salt_info.salt else {
                eprintln!(
                    "{} Paste metadata is missing the password salt.",
                    "Error:".red().bold()
                );
                return Ok(());
            };

            let password = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Enter password:".cyan().bold()
            ))?);

            let (derived_key, mut vk) = derive_keys(&password, &salt_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut ph = compute_password_hash(&vk, &salt_bytes);
            let auth = base64::engine::general_purpose::STANDARD.encode(ph);
            ph.zeroize();
            vk.zeroize();

            let data_url = format!("{}/api/paste/{}/data", base_url, id);

            // All metadata rides in the authenticated blob frame. A tiny range
            // request fetches it (nonce, chunks, filename, wrapped key) without
            // downloading the whole ciphertext.
            let meta_resp = client
                .get(&data_url)
                .header("X-Password-Hash", &auth)
                .header("Range", "bytes=0-0")
                .send()
                .await?;
            if !meta_resp.status().is_success() {
                eprintln!(
                    "{} {}",
                    "Error:".red().bold(),
                    if meta_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                        "Wrong password."
                    } else {
                        "Failed to fetch paste."
                    }
                );
                return Ok(());
            }
            let meta_body = meta_resp.bytes().await?;
            let (meta, _) = split_paste_frame(&meta_body)
                .map_err(|e| eyre::eyre!("Invalid paste frame: {}", e))?;

            let enc_bytes = get_ciphertext_size(meta.total_size as usize);

            eprintln!(
                "{} {:.2} plain · {} chunks · {:.2} encrypted",
                "Size:".bright_black(),
                indicatif::HumanBytes(meta.total_size),
                meta.total_chunks,
                indicatif::HumanBytes(enc_bytes as u64),
            );

            if enc_bytes == 0 {
                eprintln!(
                    "{} Paste appears incomplete (no data).",
                    "Error:".red().bold()
                );
                return Ok(());
            }

            let pb = make_pb(enc_bytes as u64, "green/yellow", "");
            let num_parts = PARALLELISM.clamp(1, 16);
            let part_size = (enc_bytes as u64).div_ceil(num_parts as u64);

            let buf = Arc::new(std::sync::Mutex::new(vec![0u8; enc_bytes]));
            let dl_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let pb = Arc::new(pb);
            let client = Arc::new(client);
            let url = data_url;

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
                            && let Ok((_, slice)) = split_paste_frame(&data)
                        {
                            let mut b = buf.lock().unwrap();
                            b[s as usize..][..slice.len()].copy_from_slice(slice);
                            pb.inc(slice.len() as u64);
                            pb.set_message(indicatif::HumanBytes(pb.position()).to_string());
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

            // The password-wrapped content key rides in the blob metadata frame
            // fetched above, served only after the server verified the password.
            // Legacy pastes have no envelope: the derived KEK IS the content key.
            let ek = match &meta.key {
                Some(envelope) => {
                    unwrap_content_key(&envelope.wrapped_key, &envelope.wrap_nonce, &derived_key)
                        .map_err(|e| eyre::eyre!("Key unwrap failed: {}", e))?
                }
                None => derived_key,
            };

            finish_decrypt(&client, &base_url, id, &meta, ek, encrypted, output).await?;
        }
        Commands::Account { action } => match action {
            AccountCommand::Register { name } => {
                register_account(&client, &base_url, name, None).await?;
            }
            AccountCommand::Import { name, phrase } => {
                let phrase = match phrase {
                    Some(p) => Some(p.clone()),
                    None => prompt_mnemonic()?,
                };
                register_account(&client, &base_url, name, phrase).await?;
            }
            AccountCommand::Login {} => {
                login_account(&client, &base_url).await?;
            }
        },
        Commands::Passwd { id } => {
            let current_password = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Current password:".cyan().bold()
            ))?);
            let new_password = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "New password:".cyan().bold()
            ))?);
            let new_password_confirm = Zeroizing::new(rpassword::prompt_password(format!(
                "{} ",
                "Confirm new password:".cyan().bold()
            ))?);

            if new_password.is_empty() {
                eprintln!("{} New password cannot be empty.", "Error:".red().bold());
                return Ok(());
            }
            if new_password != new_password_confirm {
                eprintln!("{} Passwords do not match.", "Error:".red().bold());
                return Ok(());
            }

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
            let meta: GetSaltResponse = bitcode::decode(&salt_resp.bytes().await?)?;
            if meta.mode == PasteAuthMode::Recipient {
                eprintln!(
                    "{} Paste is sealed to a user account — password change is not available.",
                    "Error:".red().bold()
                );
                return Ok(());
            }
            let Some(salt_bytes) = meta.salt else {
                eprintln!(
                    "{} Paste metadata is missing the password salt.",
                    "Error:".red().bold()
                );
                return Ok(());
            };

            eprintln!("{} Deriving keys (Argon2id)...", "·".bright_black());

            let (derived_key, mut vk) = derive_keys(&current_password, &salt_bytes)
                .map_err(|e| eyre::eyre!("Key derivation failed: {}", e))?;
            let mut ph = compute_password_hash(&vk, &salt_bytes);
            let auth = base64::engine::general_purpose::STANDARD.encode(ph);
            ph.zeroize();
            vk.zeroize();

            // The wrapped content key is only served with the ciphertext, after
            // the server validates the password. A tiny range request
            // retrieves the metadata frame without downloading the blob.
            let key_resp = client
                .get(format!("{}/api/paste/{}/data", base_url, id))
                .header("X-Password-Hash", &auth)
                .header("Range", "bytes=0-0")
                .send()
                .await?;
            if !key_resp.status().is_success() {
                eprintln!("{} Wrong password.", "Error:".red().bold());
                return Ok(());
            }
            let key_body = key_resp.bytes().await?;
            let envelope = match split_paste_frame(&key_body) {
                Ok((hdr, _)) => hdr.key,
                Err(e) => return Err(eyre::eyre!("Invalid paste frame: {}", e)),
            };

            // Content key: unwrap the envelope. For legacy pastes the derived
            // key IS the content key — changing the password here upgrades the
            // paste to envelope encryption.
            let content_key = Zeroizing::new(match envelope {
                Some(envelope) => {
                    unwrap_content_key(&envelope.wrapped_key, &envelope.wrap_nonce, &derived_key)
                        .map_err(|e| eyre::eyre!("Wrong password: {}", e))?
                }
                None => derived_key,
            });

            let new_setup = encrypt_setup(&new_password, &content_key)
                .map_err(|e| eyre::eyre!("Encryption setup failed: {}", e))?;

            let request = ChangePasswordRequest {
                salt: new_setup.salt,
                password_hash: new_setup.password_hash,
                key: KeyEnvelope {
                    wrap_nonce: new_setup.wrap_nonce,
                    wrapped_key: new_setup.wrapped_key,
                },
            };

            let resp = client
                .post(format!("{}/api/paste/{}/password", base_url, id))
                .header("X-Password-Hash", auth)
                .body(bitcode::encode(&request))
                .send()
                .await?;

            if resp.status().is_success() {
                println!(
                    "{} Password changed for paste {} — content was not re-encrypted",
                    "✓".green().bold(),
                    id.yellow().bold()
                );
            } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                eprintln!("{} Wrong password.", "Error:".red().bold());
            } else {
                eprintln!(
                    "{} Failed to change password: {}",
                    "Error:".red().bold(),
                    resp.status()
                );
            }
        }
    }

    Ok(())
}
