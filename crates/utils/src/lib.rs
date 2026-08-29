use argon2::{Argon2, Params};
use orion::hazardous::aead::chacha20poly1305;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

const ENCRYPTION_KEY_INFO: &[u8] = b"mitsuzo-encryption-key";
const VALIDATION_KEY_INFO: &[u8] = b"mitsuzo-validation-key";

fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(info.len() + 1);
    data.extend_from_slice(info);
    data.push(0x01);
    hmac_sha256(prk, &data)
}

pub struct EncryptionSetup {
    pub salt: [u8; 16],
    pub base_nonce: [u8; 12],
    pub wrap_nonce: [u8; 12],
    pub wrapped_key: [u8; 48],
    pub password_hash: [u8; 32],
}

pub fn get_argon2_params() -> Result<Params, String> {
    Params::new(19456, 2, 1, Some(32)).map_err(|e| format!("Failed to create Argon2 params: {}", e))
}

pub fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        get_argon2_params()?,
    );
    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut master_key)
        .map_err(|e| format!("Failed to derive key: {}", e))?;

    let encryption_key = hkdf_expand_sha256(&master_key, ENCRYPTION_KEY_INFO);
    let validation_key = hkdf_expand_sha256(&master_key, VALIDATION_KEY_INFO);

    master_key.zeroize();

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

/// Generate a random 32-byte content encryption key (CEK).
pub fn generate_content_key() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| format!("Failed to generate content key: {}", e))?;
    Ok(key)
}

/// Wrap the content key with a password-derived key-encryption key (KEK).
/// Returns `(wrap_nonce, wrapped_key)` where `wrapped_key` is 48 bytes
/// (32-byte CEK + 16-byte Poly1305 tag).
pub fn wrap_content_key(
    content_key: &[u8; 32],
    kek: &[u8; 32],
) -> Result<([u8; 12], [u8; 48]), String> {
    let wrap_nonce = generate_nonce()?;
    let key = chacha20poly1305::SecretKey::from_slice(kek)
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(wrap_nonce);
    let mut wrapped = [0u8; 48];
    chacha20poly1305::seal(&key, &nonce_obj, content_key, None, &mut wrapped)
        .map_err(|e| format!("Failed to wrap key: {:?}", e))?;
    Ok((wrap_nonce, wrapped))
}

/// Unwrap the content key with a password-derived key-encryption key (KEK).
pub fn unwrap_content_key(
    wrapped_key: &[u8; 48],
    wrap_nonce: &[u8; 12],
    kek: &[u8; 32],
) -> Result<[u8; 32], String> {
    let key = chacha20poly1305::SecretKey::from_slice(kek)
        .map_err(|e| format!("Invalid key: {:?}", e))?;
    let nonce_obj = chacha20poly1305::Nonce::from(*wrap_nonce);
    let mut content_key = [0u8; 32];
    chacha20poly1305::open(&key, &nonce_obj, wrapped_key, None, &mut content_key)
        .map_err(|_| "Failed to unwrap key. Password may be incorrect.".to_string())?;
    Ok(content_key)
}

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
    let base_nonce = generate_nonce()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let cek = generate_content_key().unwrap();
        let kek = generate_content_key().unwrap();
        let (wrap_nonce, wrapped) = wrap_content_key(&cek, &kek).unwrap();
        assert_ne!(&wrapped[..32], cek);
        let unwrapped = unwrap_content_key(&wrapped, &wrap_nonce, &kek).unwrap();
        assert_eq!(unwrapped, cek);
    }

    #[test]
    fn unwrap_with_wrong_kek_fails() {
        let cek = generate_content_key().unwrap();
        let kek = generate_content_key().unwrap();
        let wrong_kek = generate_content_key().unwrap();
        let (wrap_nonce, wrapped) = wrap_content_key(&cek, &kek).unwrap();
        assert!(unwrap_content_key(&wrapped, &wrap_nonce, &wrong_kek).is_err());
    }

    #[test]
    fn password_change_rewrap_only() {
        let plaintext = b"hello mitsuzo".repeat(1000);
        let old_password = "correct horse battery staple";
        let new_password = "new password 42";

        let cek = generate_content_key().unwrap();
        let setup = encrypt_setup(old_password, &cek).unwrap();

        // Encrypt with the random CEK (envelope scheme)
        let mut ciphertext = Vec::new();
        let total_chunks =
            encrypt_into(&plaintext, &cek, &setup.base_nonce, &mut ciphertext).unwrap();

        // Change password: unwrap with old KEK, rewrap with new KEK
        let (old_kek, _) = derive_keys(old_password, &setup.salt).unwrap();
        let unwrapped_cek =
            unwrap_content_key(&setup.wrapped_key, &setup.wrap_nonce, &old_kek).unwrap();
        assert_eq!(unwrapped_cek, cek);

        let new_setup = encrypt_setup(new_password, &unwrapped_cek).unwrap();

        // Ciphertext is untouched; password-based (legacy) decryption now fails,
        // but CEK-based decryption succeeds after unwrapping from the new wrap.
        let (new_kek, _) = derive_keys(new_password, &new_setup.salt).unwrap();
        let recovered_cek =
            unwrap_content_key(&new_setup.wrapped_key, &new_setup.wrap_nonce, &new_kek).unwrap();
        assert_eq!(recovered_cek, cek);

        let mut decrypted = Vec::new();
        assert!(
            decrypt_into(
                &ciphertext,
                &setup.base_nonce,
                new_password,
                &setup.salt,
                total_chunks,
                &mut decrypted
            )
            .is_err()
        );
        decrypted.clear();
        decrypt_with_key_into(
            &ciphertext,
            &recovered_cek,
            &setup.base_nonce,
            &mut decrypted,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);

        // Old password no longer unwraps the new wrap
        assert!(
            unwrap_content_key(&new_setup.wrapped_key, &new_setup.wrap_nonce, &old_kek).is_err()
        );
    }

    #[test]
    fn burn_receipt_stable_across_password_change() {
        let cek = generate_content_key().unwrap();
        let _setup = encrypt_setup("old", &cek).unwrap();
        let receipt_before = compute_burn_receipt(&cek);
        let receipt_after = compute_burn_receipt(&cek);
        assert_eq!(receipt_before, receipt_after);
    }

    #[test]
    fn legacy_direct_key_still_decrypts() {
        let plaintext = b"legacy paste data".repeat(3);
        let password = "legacy password";

        // Old scheme: encryption key derived directly from the password
        let setup_salt = [7u8; 16];
        let (encryption_key, _validation_key) = derive_keys(password, &setup_salt).unwrap();
        let base_nonce = [9u8; 12];
        let mut ciphertext = Vec::new();
        let total_chunks =
            encrypt_into(&plaintext, &encryption_key, &base_nonce, &mut ciphertext).unwrap();

        // Legacy decrypt path: derive keys and decrypt directly
        let mut decrypted = Vec::new();
        decrypt_into(
            &ciphertext,
            &base_nonce,
            password,
            &setup_salt,
            total_chunks,
            &mut decrypted,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chunked_envelope_round_trip() {
        let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let password = "chunky";
        let cek = generate_content_key().unwrap();
        let setup = encrypt_setup(password, &cek).unwrap();

        let mut ciphertext = Vec::new();
        let total_chunks =
            encrypt_into(&plaintext, &cek, &setup.base_nonce, &mut ciphertext).unwrap();

        let (kek, _) = derive_keys(password, &setup.salt).unwrap();
        let unwrapped = unwrap_content_key(&setup.wrapped_key, &setup.wrap_nonce, &kek).unwrap();

        let mut decrypted = Vec::with_capacity(plaintext.len());
        for i in 0..total_chunks {
            let (start, end) = get_chunk_bounds(total_chunks, i, ciphertext.len());
            decrypt_chunk_into(
                &ciphertext[start..end],
                &unwrapped,
                &setup.base_nonce,
                i,
                &mut decrypted,
            )
            .unwrap();
        }
        assert_eq!(decrypted, plaintext);
    }
}
