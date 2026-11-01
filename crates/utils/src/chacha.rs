use orion::hazardous::aead::chacha20poly1305;
use zeroize::Zeroize;

pub(crate) fn generate_nonce() -> Result<[u8; 12], String> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| format!("Failed to generate nonce: {}", e))?;
    Ok(nonce)
}

pub fn decrypt_with_key_into(
    ciphertext: &[u8],
    encryption_key: &[u8; 32],
    nonce: &[u8; 12],
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let key = chacha20poly1305::SecretKey::try_from(encryption_key.as_slice())
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(*nonce);
    if ciphertext.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }
    let offset = output.len();
    let plaintext_len = ciphertext.len() - 16;
    let end = offset
        .checked_add(plaintext_len)
        .ok_or_else(|| "Plaintext output length overflow".to_string())?;
    output.resize(end, 0);
    if let Err(e) = chacha20poly1305::ChaCha20Poly1305::open(
        &key,
        &nonce_obj,
        ciphertext,
        None,
        &mut output[offset..],
    ) {
        output[offset..].zeroize();
        output.truncate(offset);
        return Err(format!(
            "Failed to decrypt: {:?}. Password may be incorrect.",
            e
        ));
    }
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
    let key = chacha20poly1305::SecretKey::try_from(encryption_key.as_slice())
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(chunk_nonce);
    let offset = output.len();
    let end = offset
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(16))
        .ok_or_else(|| "Ciphertext output length overflow".to_string())?;
    output.resize(end, 0);
    if let Err(e) = chacha20poly1305::ChaCha20Poly1305::seal(
        &key,
        &nonce_obj,
        plaintext,
        None,
        &mut output[offset..],
    ) {
        output[offset..].zeroize();
        output.truncate(offset);
        return Err(format!("Failed to encrypt: {:?}", e));
    }
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

/// Wrap the content key with a password-derived key-encryption key (KEK).
/// Returns `(wrap_nonce, wrapped_key)` where `wrapped_key` is 48 bytes
/// (32-byte CEK + 16-byte Poly1305 tag).
pub(crate) fn wrap_content_key_raw(
    content_key: &[u8; 32],
    kek: &[u8; 32],
) -> Result<([u8; 12], [u8; 48]), String> {
    let wrap_nonce = generate_nonce()?;
    let key = chacha20poly1305::SecretKey::try_from(kek.as_slice())
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(wrap_nonce);
    let mut wrapped = [0u8; 48];
    chacha20poly1305::ChaCha20Poly1305::seal(&key, &nonce_obj, content_key, None, &mut wrapped)
        .map_err(|e| format!("Failed to wrap key: {:?}", e))?;
    Ok((wrap_nonce, wrapped))
}

/// Unwrap the content key with a password-derived key-encryption key (KEK).
pub(crate) fn unwrap_content_key_raw(
    wrapped_key: &[u8; 48],
    wrap_nonce: &[u8; 12],
    kek: &[u8; 32],
) -> Result<[u8; 32], String> {
    let key = chacha20poly1305::SecretKey::try_from(kek.as_slice())
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(*wrap_nonce);
    let mut content_key = [0u8; 32];
    if chacha20poly1305::ChaCha20Poly1305::open(
        &key,
        &nonce_obj,
        wrapped_key,
        None,
        &mut content_key,
    )
    .is_err()
    {
        content_key.zeroize();
        return Err("Failed to unwrap key. Password may be incorrect.".to_string());
    }
    Ok(content_key)
}
