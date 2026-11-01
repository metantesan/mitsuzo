mod account;
mod chacha;
mod cipher;
mod content;
mod password;
mod xchacha;
mod xwing;
mod xwing_recipient;
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
pub use orion::hazardous::hash::blake3::Blake3 as Blake3Hasher;
pub use password::{EncryptionSetup, compute_password_hash, get_argon2_params};
pub(crate) use password::{generate_salt, hkdf_expand_sha256, hmac_sha256};
pub use xchacha::{
    decrypt_xchacha_chunk_into, derive_xchacha_chunk_nonce, encrypt_xchacha_chunk_into,
};
pub use xwing::{
    KeyEncapsulation, XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE, XWingAccountKeyEncapsulation,
    XWingKeyEncapsulation, derive_legacy_xwing_public_key, derive_xwing_account_public_key,
};
pub use xwing_recipient::{
    XWingContentKeyEnvelope, open_content_key_for_legacy_xwing, open_content_key_for_xwing_account,
    open_content_key_for_xwing_shared, seal_content_key_for_xwing,
};

const CHUNK_SIZE: usize = 65536;
#[cfg(test)]
mod tests;
