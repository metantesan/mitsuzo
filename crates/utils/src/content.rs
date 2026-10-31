/// Generate a random 32-byte content encryption key (CEK).
pub fn generate_content_key() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| format!("Failed to generate content key: {}", e))?;
    Ok(key)
}

use crate::EncryptionSetup;
use crate::password::{generate_salt, hkdf_expand_sha256};
use crate::{
    CHUNK_SIZE, chacha, compute_password_hash, decrypt_chunk_into, decrypt_with_key_into,
    derive_keys, encrypt_chunk_into, wrap_content_key,
};

const FULL_CHUNK_CIPHER_LEN: usize = CHUNK_SIZE + 16;

/// Compute the exact ciphertext length produced by encrypting `plaintext_len` bytes.
pub fn get_ciphertext_size(plaintext_len: usize) -> usize {
    let chunks = plaintext_len.div_ceil(CHUNK_SIZE).max(1);
    if chunks == 1 {
        plaintext_len + 16
    } else {
        (chunks - 1) * FULL_CHUNK_CIPHER_LEN + (plaintext_len - (chunks - 1) * CHUNK_SIZE) + 16
    }
}

pub fn encrypt_setup(password: &str, content_key: &[u8; 32]) -> Result<EncryptionSetup, String> {
    let salt = generate_salt()?;
    let (wrap_key, validation_key) = derive_keys(password, &salt)?;
    let base_nonce = chacha::generate_nonce()?;
    let (wrap_nonce, wrapped_key) = wrap_content_key(content_key, &wrap_key)?;
    let password_hash = compute_password_hash(&validation_key, &salt);
    Ok(EncryptionSetup {
        salt,
        base_nonce,
        wrap_nonce,
        wrapped_key,
        password_hash,
    })
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

pub struct EncryptedContent {
    pub ciphertext: Vec<u8>,
    pub base_nonce: [u8; 12],
    pub wrap_nonce: [u8; 12],
    pub wrapped_key: [u8; 48],
    pub salt: [u8; 16],
    pub password_hash: [u8; 32],
    pub total_chunks: u32,
}

pub fn encrypt_content(plaintext: &[u8], password: &str) -> Result<EncryptedContent, String> {
    let content_key = generate_content_key()?;
    let setup = encrypt_setup(password, &content_key)?;
    let mut ciphertext = Vec::new();
    let total_chunks = encrypt_into(plaintext, &content_key, &setup.base_nonce, &mut ciphertext)?;
    Ok(EncryptedContent {
        ciphertext,
        base_nonce: setup.base_nonce,
        wrap_nonce: setup.wrap_nonce,
        wrapped_key: setup.wrapped_key,
        salt: setup.salt,
        password_hash: setup.password_hash,
        total_chunks,
    })
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

const BURN_RECEIPT_INFO: &[u8] = b"mitsuzo-burn-receipt";

pub fn compute_burn_receipt(encryption_key: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_sha256(encryption_key, BURN_RECEIPT_INFO)
}

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
