use base64::Engine;
use clap::{Parser, Subcommand};
use mitsuzo_types::{
    CreatePasteHeader, CreatePasteResponse, DataType, GetPasteHeader, GetSaltResponse,
};
use mitsuzo_utils::{
    compute_password_hash, decrypt_chunk_into, derive_keys, encrypt_into, encrypt_setup,
    get_chunk_bounds, get_plaintext_size,
};
use reqwest::Client;
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Deserialize)]
struct Config {
    base_url: Option<String>,
}

const DEFAULT_BASE_URL: &str = "http://localhost:3030";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// The base URL of the mitsuzo server.
    #[arg(short, long)]
    base_url: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new paste
    Create {
        /// The content of the paste. If not provided or set to '-', it will be read from stdin.
        #[arg(short, long)]
        file: Option<String>,

        /// The number of times the paste can be tried before it's deleted.
        #[arg(short = 'c', long, default_value = "5")]
        try_count: u32,

        /// The time to live of the paste in seconds.
        #[arg(short, long, default_value = "43200")]
        ttl: u32,
    },
    /// Get a paste
    Get {
        /// The ID of the paste to retrieve.
        id: String,

        /// Output file path. If not provided, the original filename is used. Use '-' for stdout.
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::new();

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
            let password = rpassword::prompt_password("Enter password: ")?;
            let password_confirm = rpassword::prompt_password("Confirm password: ")?;

            if password != password_confirm {
                eprintln!("Passwords do not match.");
                return Ok(());
            }

            let (content, data_type, filename) = if file.as_deref() == Some("-") || file.is_none() {
                let mut buffer = Vec::new();
                io::stdin().read_to_end(&mut buffer)?;
                (buffer, DataType::Text, None)
            } else {
                let file_path = file.as_ref().unwrap();
                (
                    std::fs::read(file_path)?,
                    DataType::File,
                    PathBuf::from(file_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(String::from),
                )
            };

            let (salt, nonce, encryption_key, password_hash) = encrypt_setup(&password)?;

            let total_chunks = if content.is_empty() {
                1
            } else {
                content.len().div_ceil(65536) as u32
            };

            let header = CreatePasteHeader {
                nonce,
                salt,
                password_hash,
                try_count: Some(*try_count),
                ttl_seconds: Some(*ttl),
                data_type,
                filename,
                content_type: None,
                total_chunks,
            };

            let header_bytes = bitcode::encode(&header);
            let mut body = Vec::with_capacity(4 + header_bytes.len());
            body.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(&header_bytes);

            encrypt_into(&content, &encryption_key, &nonce, &mut body)?;

            let response = client
                .post(format!("{}/api/paste", base_url))
                .body(body)
                .send()
                .await?;

            if response.status().is_success() {
                let response_body = response.bytes().await?;
                let decoded_response: CreatePasteResponse = bitcode::decode(&response_body)?;
                println!("Paste created with ID: {}", decoded_response.id);
            } else {
                eprintln!("Failed to create paste: {}", response.status());
            }
        }
        Commands::Get { id, output } => {
            let password = rpassword::prompt_password("Enter password: ")?;

            let salt_response = client
                .get(format!("{}/api/paste/{}/salt", base_url, id))
                .send()
                .await?;

            if !salt_response.status().is_success() {
                eprintln!("Failed to get salt: {}", salt_response.status());
                return Ok(());
            }

            let salt_body = salt_response.bytes().await?;
            let decoded_salt: GetSaltResponse = bitcode::decode(&salt_body)?;

            let (_encryption_key, validation_key) = derive_keys(&password, &decoded_salt.salt)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let password_hash = compute_password_hash(&validation_key, &decoded_salt.salt);
            let encoded_hash = base64::engine::general_purpose::STANDARD.encode(password_hash);

            let response = client
                .get(format!("{}/api/paste/{}", base_url, id))
                .header("X-Password-Hash", encoded_hash)
                .send()
                .await?;

            if response.status().is_success() {
                let mut response_body = response.bytes().await?;
                let header_len =
                    u32::from_le_bytes(response_body[..4].try_into().unwrap()) as usize;
                let header_end = 4 + header_len;
                let header: GetPasteHeader = bitcode::decode(&response_body[4..header_end])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let encrypted = response_body.split_off(header_end);

                let paste_total_chunks = if header.total_chunks > 0 {
                    header.total_chunks
                } else {
                    decoded_salt.total_chunks
                };

                let plaintext_size = get_plaintext_size(paste_total_chunks, encrypted.len())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let mut decrypted_content = Vec::with_capacity(plaintext_size);
                let (_encryption_key, _) = derive_keys(&password, &decoded_salt.salt)?;

                for i in 0..paste_total_chunks {
                    let (start, end) = get_chunk_bounds(paste_total_chunks, i, encrypted.len());
                    decrypt_chunk_into(
                        &encrypted[start..end],
                        &_encryption_key,
                        &header.nonce,
                        i,
                        &mut decrypted_content,
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }

                if let Some(output_path) = output {
                    if output_path == "-" {
                        io::stdout().write_all(&decrypted_content)?;
                    } else {
                        let mut file = std::fs::File::create(output_path)?;
                        file.write_all(&decrypted_content)?;
                    }
                } else {
                    match header.data_type {
                        DataType::File => {
                            if let Some(filename) = header.filename {
                                let mut file = std::fs::File::create(&filename)?;
                                file.write_all(&decrypted_content)?;
                                eprintln!("Saved paste to file {}", filename);
                            } else {
                                io::stdout().write_all(&decrypted_content)?;
                            }
                        }
                        DataType::Text => {
                            io::stdout().write_all(&decrypted_content)?;
                        }
                    }
                }
            } else {
                eprintln!("Failed to get paste: {}", response.status());
            }
        }
    }

    println!();
    Ok(())
}
