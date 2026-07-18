use argon2::{Argon2, Params};
use orion::hazardous::aead::chacha20poly1305;
use sha2::{Digest, Sha256};

const CHUNK_SIZE: usize = 65536;
const HMAC_BLOCK: usize = 64;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = key.to_vec();
    if k.len() > HMAC_BLOCK {
        let mut hasher = Sha256::new();
        hasher.update(&k);
        k = hasher.finalize().to_vec();
    }
    k.resize(HMAC_BLOCK, 0);

    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5cu8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

pub fn get_argon2_params() -> Result<Params, String> {
    Params::new(19456, 2, 1, Some(64)).map_err(|e| format!("Failed to create Argon2 params: {}", e))
}

pub fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        get_argon2_params()?,
    );
    let mut output = [0u8; 64];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| format!("Failed to derive key: {}", e))?;
    let encryption_key: [u8; 32] = output[..32].try_into().unwrap();
    let validation_key: [u8; 32] = output[32..].try_into().unwrap();
    Ok((encryption_key, validation_key))
}

pub fn compute_password_hash(validation_key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    hmac_sha256(validation_key, salt)
}

pub fn decrypt_with_key_into(
    ciphertext: &[u8],
    encryption_key: &[u8; 32],
    nonce: &[u8; 12],
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let key = chacha20poly1305::SecretKey::from_slice(encryption_key)
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(*nonce);
    if ciphertext.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }
    let offset = output.len();
    output.resize(offset + ciphertext.len() - 16, 0);
    chacha20poly1305::open(&key, &nonce_obj, ciphertext, None, &mut output[offset..])
        .map_err(|e| format!("Failed to decrypt: {:?}. Password may be incorrect.", e))?;
    Ok(())
}

pub fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= idx_bytes[i];
    }
    nonce
}

pub fn encrypt_chunk_into(
    plaintext: &[u8],
    encryption_key: &[u8; 32],
    base_nonce: &[u8; 12],
    chunk_index: u32,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index);
    let key = chacha20poly1305::SecretKey::from_slice(encryption_key)
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(chunk_nonce);
    let offset = output.len();
    output.resize(offset + plaintext.len() + 16, 0);
    chacha20poly1305::seal(&key, &nonce_obj, plaintext, None, &mut output[offset..])
        .map_err(|e| format!("Failed to encrypt: {:?}", e))?;
    Ok(())
}

pub fn decrypt_chunk_into(
    ciphertext: &[u8],
    encryption_key: &[u8; 32],
    base_nonce: &[u8; 12],
    chunk_index: u32,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index);
    decrypt_with_key_into(ciphertext, encryption_key, &chunk_nonce, output)
}

fn generate_salt() -> Result<[u8; 16], String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("Failed to generate salt: {}", e))?;
    Ok(salt)
}

fn generate_nonce() -> Result<[u8; 12], String> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| format!("Failed to generate nonce: {}", e))?;
    Ok(nonce)
}

const FULL_CHUNK_CIPHER_LEN: usize = CHUNK_SIZE + 16;

#[allow(clippy::type_complexity)]
pub fn encrypt_setup(password: &str) -> Result<([u8; 16], [u8; 12], [u8; 32], [u8; 32]), String> {
    let salt = generate_salt()?;
    let (encryption_key, validation_key) = derive_keys(password, &salt)?;
    let base_nonce = generate_nonce()?;
    let password_hash = compute_password_hash(&validation_key, &salt);
    Ok((salt, base_nonce, encryption_key, password_hash))
}

pub fn encrypt_into(
    plaintext: &[u8],
    encryption_key: &[u8; 32],
    base_nonce: &[u8; 12],
    output: &mut Vec<u8>,
) -> Result<u32, String> {
    let total_chunks = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(CHUNK_SIZE) as u32
    };

    output.reserve(if total_chunks == 1 {
        plaintext.len() + 16
    } else {
        (total_chunks as usize - 1) * FULL_CHUNK_CIPHER_LEN
            + (plaintext.len() - (total_chunks as usize - 1) * CHUNK_SIZE)
            + 16
    });

    for i in 0..total_chunks {
        let start = i as usize * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, plaintext.len());
        let chunk = &plaintext[start..end];
        encrypt_chunk_into(chunk, encryption_key, base_nonce, i, output)?;
    }

    Ok(total_chunks)
}

#[allow(clippy::type_complexity)]
pub fn encrypt_content(
    plaintext: &[u8],
    password: &str,
) -> Result<(Vec<u8>, [u8; 12], [u8; 16], [u8; 32], u32), String> {
    let (salt, base_nonce, encryption_key, password_hash) = encrypt_setup(password)?;
    let mut ciphertext = Vec::new();
    let total_chunks = encrypt_into(plaintext, &encryption_key, &base_nonce, &mut ciphertext)?;
    Ok((ciphertext, base_nonce, salt, password_hash, total_chunks))
}

/// Compute byte range for a chunk in the ciphertext
pub fn get_chunk_bounds(
    total_chunks: u32,
    chunk_index: u32,
    ciphertext_len: usize,
) -> (usize, usize) {
    let start = chunk_index as usize * FULL_CHUNK_CIPHER_LEN;
    let end = if chunk_index == total_chunks - 1 {
        ciphertext_len
    } else {
        start + FULL_CHUNK_CIPHER_LEN
    };
    (start, end)
}

/// Compute total plaintext size from ciphertext length
pub fn get_plaintext_size(total_chunks: u32, ciphertext_len: usize) -> Result<usize, String> {
    if total_chunks == 0 {
        return Err("total_chunks cannot be 0".to_string());
    }
    if total_chunks == 1 {
        return ciphertext_len
            .checked_sub(16)
            .ok_or_else(|| "Invalid single chunk".to_string());
    }
    let full_chunks = (total_chunks - 1) as usize;
    let full_chunks_cipher_len = full_chunks * FULL_CHUNK_CIPHER_LEN;
    let last_chunk_cipher_len = ciphertext_len
        .checked_sub(full_chunks_cipher_len)
        .ok_or_else(|| "Invalid ciphertext length".to_string())?;
    if last_chunk_cipher_len == 0 || last_chunk_cipher_len > FULL_CHUNK_CIPHER_LEN {
        return Err("Invalid last chunk length".to_string());
    }
    Ok(full_chunks * CHUNK_SIZE + (last_chunk_cipher_len - 16))
}

pub fn decrypt_into(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    password: &str,
    salt: &[u8],
    total_chunks: u32,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let (encryption_key, _validation_key) = derive_keys(password, salt)?;

    if total_chunks == 1 {
        return decrypt_with_key_into(ciphertext, &encryption_key, nonce, output);
    }

    let full_chunks = (total_chunks - 1) as usize;
    let full_chunks_cipher_len = full_chunks * FULL_CHUNK_CIPHER_LEN;
    let last_chunk_cipher_len = ciphertext
        .len()
        .checked_sub(full_chunks_cipher_len)
        .ok_or_else(|| "Invalid ciphertext length for chunked data".to_string())?;

    if last_chunk_cipher_len == 0 || last_chunk_cipher_len > FULL_CHUNK_CIPHER_LEN {
        return Err("Invalid last chunk ciphertext length".to_string());
    }

    let total_plaintext_size = full_chunks * CHUNK_SIZE + (last_chunk_cipher_len - 16);
    output.reserve(total_plaintext_size);

    for i in 0..total_chunks {
        let start = i as usize * FULL_CHUNK_CIPHER_LEN;
        let end = if i == total_chunks - 1 {
            ciphertext.len()
        } else {
            start + FULL_CHUNK_CIPHER_LEN
        };
        let chunk_cipher = &ciphertext[start..end];
        decrypt_chunk_into(chunk_cipher, &encryption_key, nonce, i, output)?;
    }

    Ok(())
}

pub fn decrypt_content(
    ciphertext: &[u8],
    nonce: &[u8],
    password: &str,
    salt: &[u8],
    total_chunks: u32,
) -> Result<Vec<u8>, String> {
    let base_nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| "Nonce must be 12 bytes".to_string())?;
    let mut output = Vec::new();
    decrypt_into(
        ciphertext,
        &base_nonce,
        password,
        salt,
        total_chunks,
        &mut output,
    )?;
    Ok(output)
}
