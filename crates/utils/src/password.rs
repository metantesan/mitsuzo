use orion::hazardous::{
    kdf::argon2::{Argon2, CostParams, ID, Sequential},
    kdf::hkdf::{Hkdf, SHA256},
    mac::hmac::sha256::{HmacSha256, SecretKey as HmacKey},
};
use zeroize::Zeroize;

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = HmacKey::try_from(key).expect("HMAC accepts any key length");
    HmacSha256::hmac(&key, data)
        .expect("HMAC-SHA256 input processing should not fail")
        .unprotected_as_ref()
        .try_into()
        .expect("HMAC-SHA256 outputs 32 bytes")
}

const ENCRYPTION_KEY_INFO: &[u8] = b"mitsuzo-encryption-key";
const VALIDATION_KEY_INFO: &[u8] = b"mitsuzo-validation-key";

pub(crate) fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let prk = orion::hazardous::mac::hmac::sha256::Tag::from(*prk);
    let mut output = [0u8; 32];
    Hkdf::<SHA256>::expand(&prk, Some(info), &mut output)
        .expect("single-block HKDF-SHA256 expansion should not fail");
    output
}

pub struct EncryptionSetup {
    pub salt: [u8; 16],
    pub base_nonce: [u8; 12],
    pub wrap_nonce: [u8; 12],
    pub wrapped_key: [u8; 48],
    pub password_hash: [u8; 32],
}

pub fn get_argon2_params() -> Result<CostParams, String> {
    CostParams::new(2, 19_456, 1).map_err(|e| format!("Failed to create Argon2 parameters: {e}"))
}

pub(crate) fn derive_argon2id_keys(
    password: &str,
    salt: &[u8],
) -> Result<([u8; 32], [u8; 32]), String> {
    let params = get_argon2_params()?;
    let mut master_key = [0u8; 32];
    Argon2::<ID, Sequential>::derive_key(
        password.as_bytes(),
        salt,
        &params,
        None,
        None,
        &mut master_key,
    )
    .map_err(|e| format!("Failed to derive key: {e}"))?;

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

#[cfg(test)]
mod tests {
    use super::{Argon2, ID, Sequential, get_argon2_params, hkdf_expand_sha256, hmac_sha256};

    #[test]
    fn orion_hmac_and_hkdf_match_rfc5869_sha256_vectors() {
        let hmac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hmac,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );

        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expanded = hkdf_expand_sha256(&prk, &info);
        assert_eq!(
            expanded,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf,
            ]
        );
    }

    #[test]
    fn orion_argon2id_matches_existing_argon2id_output() {
        let password = b"compatibility password";
        let salt = [0x5a; 16];
        let params = get_argon2_params().unwrap();
        let mut output = [0; 32];
        Argon2::<ID, Sequential>::derive_key(password, &salt, &params, None, None, &mut output)
            .unwrap();
        assert_eq!(
            output,
            [
                0x95, 0x02, 0x37, 0x83, 0x96, 0x00, 0xa1, 0xed, 0x85, 0xb6, 0x5f, 0x14, 0x9e, 0x81,
                0x03, 0x94, 0xf7, 0xeb, 0x5b, 0x87, 0x3a, 0x3a, 0x4f, 0x7f, 0xf3, 0x04, 0xb5, 0x5b,
                0x75, 0x5b, 0xaf, 0x69,
            ]
        );
    }
}
