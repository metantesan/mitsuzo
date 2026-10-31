mod account;
mod chacha;
mod cipher;
mod content;
mod password;
mod xchacha;
pub use account::{KeyAgreement, X25519, *};
pub use chacha::{
    decrypt_chunk_into, decrypt_with_key_into, derive_chunk_nonce, encrypt_chunk_into,
};
pub use cipher::{
    Argon2idHkdfSha256, ChaChaKeyWrap, ContentCipher, ContentCipherKind, KeyEncryption,
    PasswordKeyDerivation, derive_keys, unwrap_content_key, wrap_content_key,
};
pub use content::generate_content_key;
pub use content::*;
pub use password::{EncryptionSetup, compute_password_hash, get_argon2_params};
pub(crate) use password::{generate_salt, hkdf_expand_sha256, hmac_sha256};
pub use xchacha::{
    decrypt_xchacha_chunk_into, derive_xchacha_chunk_nonce, encrypt_xchacha_chunk_into,
};

const CHUNK_SIZE: usize = 65536;
#[cfg(test)]
mod tests;
