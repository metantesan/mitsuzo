use argon2::{Argon2, Params};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const HMAC_BLOCK: usize = 64;

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
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

pub(crate) fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
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

pub(crate) fn derive_argon2id_keys(
    password: &str,
    salt: &[u8],
) -> Result<([u8; 32], [u8; 32]), String> {
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

pub(crate) fn generate_salt() -> Result<[u8; 16], String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("Failed to generate salt: {}", e))?;
    Ok(salt)
}
