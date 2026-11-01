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
use orion::hazardous::hash::blake3::Blake3;
use zeroize::Zeroize;

const FULL_CHUNK_CIPHER_LEN: usize = CHUNK_SIZE + 16;
const FILE_COMMITMENT_MAGIC: &[u8; 8] = b"MITSU3E1";

pub fn blake3_digest(data: &[u8]) -> Result<[u8; 32], String> {
    let mut hasher = Blake3::new();
    hasher
        .absorb(data)
        .map_err(|e| format!("BLAKE3 hashing failed: {e}"))?;
    let mut digest = [0u8; 32];
    hasher
        .squeeze(&mut digest)
        .map_err(|e| format!("BLAKE3 hashing failed: {e}"))?;
    Ok(digest)
}

#[derive(Clone, Copy, Debug)]
pub struct Blake3CommitmentContext<'a> {
    pub paste_id: &'a str,
    pub total_chunks: u32,
    pub plaintext_len: u64,
    pub metadata: &'a [u8],
}

/// Seal an authenticated end-of-file record for the explicitly versioned file
/// format. `metadata` must be the canonical encoding of the public file
/// metadata (including the paste ID, type, name, and content type).
pub fn encrypt_blake3_commitment(
    cipher: crate::ContentCipherKind,
    key: &[u8; 32],
    nonce: &[u8],
    context: Blake3CommitmentContext<'_>,
    plaintext_hash: &[u8; 32],
    output: &mut Vec<u8>,
) -> Result<(), String> {
    if context.total_chunks == 0
        || context.paste_id.is_empty()
        || context.paste_id.len() > u16::MAX as usize
    {
        return Err("Invalid paste ID length".to_string());
    }
    let mut commitment = Vec::with_capacity(86 + context.paste_id.len());
    commitment.extend_from_slice(FILE_COMMITMENT_MAGIC);
    commitment.extend_from_slice(&(context.paste_id.len() as u16).to_le_bytes());
    commitment.extend_from_slice(context.paste_id.as_bytes());
    commitment.extend_from_slice(&context.total_chunks.to_le_bytes());
    commitment.extend_from_slice(&context.plaintext_len.to_le_bytes());
    let mut metadata_hasher = Blake3::new();
    metadata_hasher
        .absorb(b"mitsuzo-file-metadata-v3")
        .and_then(|()| metadata_hasher.absorb(context.metadata))
        .map_err(|e| format!("BLAKE3 metadata hashing failed: {e}"))?;
    let mut metadata_hash = [0u8; 32];
    metadata_hasher
        .squeeze(&mut metadata_hash)
        .map_err(|e| format!("BLAKE3 metadata hashing failed: {e}"))?;
    commitment.extend_from_slice(&metadata_hash);
    commitment.extend_from_slice(plaintext_hash);
    metadata_hash.zeroize();
    let result = cipher.encrypt_chunk(key, nonce, context.total_chunks, &commitment, output);
    commitment.zeroize();
    result
}

/// Authenticate and validate the end-of-file record before accepting file
/// contents. The caller must only invoke this for the explicitly marked
/// BLAKE3 format; legacy files do not carry this record.
pub fn verify_blake3_commitment(
    cipher: crate::ContentCipherKind,
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    context: Blake3CommitmentContext<'_>,
) -> Result<[u8; 32], String> {
    if context.total_chunks == 0
        || context.paste_id.is_empty()
        || context.paste_id.len() > u16::MAX as usize
    {
        return Err("Invalid file commitment context".to_string());
    }
    let mut opened = Vec::new();
    cipher.decrypt_chunk(key, nonce, context.total_chunks, ciphertext, &mut opened)?;
    let expected_len = 8 + 2 + context.paste_id.len() + 4 + 8 + 64;
    if opened.len() != expected_len {
        opened.zeroize();
        return Err("Malformed file commitment".to_string());
    }
    let id_len = u16::from_le_bytes(opened[8..10].try_into().expect("fixed-size slice")) as usize;
    let chunk_count = u32::from_le_bytes(
        opened[10 + context.paste_id.len()..14 + context.paste_id.len()]
            .try_into()
            .expect("fixed-size slice"),
    );
    let plaintext_len = u64::from_le_bytes(
        opened[14 + context.paste_id.len()..22 + context.paste_id.len()]
            .try_into()
            .expect("fixed-size slice"),
    );
    let metadata_hash = match blake3_metadata_hash(context.metadata) {
        Ok(hash) => hash,
        Err(error) => {
            opened.zeroize();
            return Err(error);
        }
    };
    let valid = &opened[..8] == FILE_COMMITMENT_MAGIC
        && id_len == context.paste_id.len()
        && &opened[10..10 + context.paste_id.len()] == context.paste_id.as_bytes()
        && chunk_count == context.total_chunks
        && plaintext_len == context.plaintext_len
        && opened[22 + context.paste_id.len()..54 + context.paste_id.len()] == metadata_hash;
    let expected_hash: [u8; 32] = opened[54 + context.paste_id.len()..86 + context.paste_id.len()]
        .try_into()
        .expect("fixed-size slice");
    opened.zeroize();
    if valid {
        Ok(expected_hash)
    } else {
        Err("File commitment does not match this paste".to_string())
    }
}

fn blake3_metadata_hash(metadata: &[u8]) -> Result<[u8; 32], String> {
    let mut hasher = Blake3::new();
    hasher
        .absorb(b"mitsuzo-file-metadata-v3")
        .and_then(|()| hasher.absorb(metadata))
        .map_err(|e| format!("BLAKE3 metadata hashing failed: {e}"))?;
    let mut digest = [0u8; 32];
    hasher
        .squeeze(&mut digest)
        .map_err(|e| format!("BLAKE3 metadata hashing failed: {e}"))?;
    Ok(digest)
}

/// Compute the exact ciphertext length produced by encrypting `plaintext_len` bytes.
pub fn get_ciphertext_size(plaintext_len: usize) -> usize {
    try_get_ciphertext_size(plaintext_len).unwrap_or(usize::MAX)
}

fn try_get_ciphertext_size(plaintext_len: usize) -> Option<usize> {
    let chunks = plaintext_len.div_ceil(CHUNK_SIZE).max(1);
    if chunks == 1 {
        plaintext_len.checked_add(16)
    } else {
        (chunks - 1)
            .checked_mul(FULL_CHUNK_CIPHER_LEN)?
            .checked_add(plaintext_len.checked_sub((chunks - 1).checked_mul(CHUNK_SIZE)?)?)?
            .checked_add(16)
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
        u32::try_from(plaintext.len().div_ceil(CHUNK_SIZE))
            .map_err(|_| "Too many encryption chunks".to_string())?
    };

    let expected_len = try_get_ciphertext_size(plaintext.len())
        .ok_or_else(|| "Ciphertext size overflow".to_string())?;
    let _output_end = output
        .len()
        .checked_add(expected_len)
        .ok_or_else(|| "Ciphertext output length overflow".to_string())?;
    output.reserve(expected_len);

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
    let content_key = zeroize::Zeroizing::new(generate_content_key()?);
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
    if total_chunks == 0 || chunk_index >= total_chunks {
        return (ciphertext_len, ciphertext_len);
    }
    let start = (chunk_index as usize)
        .checked_mul(FULL_CHUNK_CIPHER_LEN)
        .unwrap_or(ciphertext_len)
        .min(ciphertext_len);
    let end = if chunk_index == total_chunks - 1 {
        ciphertext_len
    } else {
        start
            .checked_add(FULL_CHUNK_CIPHER_LEN)
            .unwrap_or(ciphertext_len)
            .min(ciphertext_len)
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
        if !(16..=FULL_CHUNK_CIPHER_LEN).contains(&ciphertext_len) {
            return Err("Invalid single chunk length".to_string());
        }
        return ciphertext_len
            .checked_sub(16)
            .ok_or_else(|| "Invalid single chunk".to_string());
    }
    let full_chunks =
        usize::try_from(total_chunks - 1).map_err(|_| "Invalid chunk count".to_string())?;
    let full_chunks_cipher_len = full_chunks
        .checked_mul(FULL_CHUNK_CIPHER_LEN)
        .ok_or_else(|| "Invalid ciphertext length".to_string())?;
    let last_chunk_cipher_len = ciphertext_len
        .checked_sub(full_chunks_cipher_len)
        .ok_or_else(|| "Invalid ciphertext length".to_string())?;
    if !(16..=FULL_CHUNK_CIPHER_LEN).contains(&last_chunk_cipher_len) {
        return Err("Invalid last chunk length".to_string());
    }
    let last_plaintext_len = last_chunk_cipher_len
        .checked_sub(16)
        .ok_or_else(|| "Invalid last chunk length".to_string())?;
    full_chunks
        .checked_mul(CHUNK_SIZE)
        .and_then(|size| size.checked_add(last_plaintext_len))
        .ok_or_else(|| "Plaintext size overflow".to_string())
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

    let total_plaintext_size = get_plaintext_size(total_chunks, ciphertext.len())?;

    if total_chunks == 1 {
        return decrypt_with_key_into(ciphertext, &encryption_key, nonce, output);
    }

    if total_chunks == 0 {
        return Err("total_chunks cannot be 0".to_string());
    }
    let full_chunks =
        usize::try_from(total_chunks - 1).map_err(|_| "Invalid chunk count".to_string())?;
    let full_chunks_cipher_len = full_chunks
        .checked_mul(FULL_CHUNK_CIPHER_LEN)
        .ok_or_else(|| "Invalid ciphertext length".to_string())?;
    let last_chunk_cipher_len = ciphertext
        .len()
        .checked_sub(full_chunks_cipher_len)
        .ok_or_else(|| "Invalid ciphertext length for chunked data".to_string())?;

    if !(16..=FULL_CHUNK_CIPHER_LEN).contains(&last_chunk_cipher_len) {
        return Err("Invalid last chunk ciphertext length".to_string());
    }

    output.reserve(total_plaintext_size);
    let original_len = output.len();

    for i in 0..total_chunks {
        let start = i as usize * FULL_CHUNK_CIPHER_LEN;
        let end = if i == total_chunks - 1 {
            ciphertext.len()
        } else {
            start + FULL_CHUNK_CIPHER_LEN
        };
        let chunk_cipher = &ciphertext[start..end];
        if let Err(error) = decrypt_chunk_into(chunk_cipher, &encryption_key, nonce, i, output) {
            output[original_len..].zeroize();
            output.truncate(original_len);
            return Err(error);
        }
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
