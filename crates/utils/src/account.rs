use crate::{
    derive_keys, generate_salt, hkdf_expand_sha256, hmac_sha256, unwrap_content_key,
    wrap_content_key,
};
use mitsuzo_types::AccountKeyBlob;
use orion::hazardous::hash::sha2::sha256::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Recipient key agreement abstraction; implementations return a shared secret.
pub trait KeyAgreement {
    fn shared_secret(private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], String>;
}

pub struct X25519;
impl KeyAgreement for X25519 {
    fn shared_secret(private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], String> {
        let our = StaticSecret::from(*private);
        let their = PublicKey::from(*public);
        Ok(our.diffie_hellman(&their).to_bytes())
    }
}

const ACCOUNT_KEY_INFO: &[u8] = b"mitsuzo-account-x25519";
const CHALLENGE_KEY_INFO: &[u8] = b"mitsuzo-challenge-key";
const RECIPIENT_KEY_INFO: &[u8] = b"mitsuzo-recipient-key";

/// Standard HKDF-SHA256 extract: `PRK = HMAC-SHA256(salt = Zeros(32), ikm)`.
/// The existing `hkdf_expand_sha256` provides the expand step (single block).
fn hkdf_extract_sha256(ikm: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32];
    hmac_sha256(&salt, ikm)
}

/// Derive the account's X25519 scalar from its BIP39 seed phrase (64 bytes).
/// `HKDF-SHA256(seed, info = "mitsuzo-account-x25519")`, clamped to a valid
/// X25519 scalar. Fully recoverable from the seed phrase alone.
pub fn derive_account_scalar(bip39_seed: &[u8; 64]) -> [u8; 32] {
    let prk = hkdf_extract_sha256(bip39_seed);
    let mut scalar = hkdf_expand_sha256(&prk, ACCOUNT_KEY_INFO);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// X25519 base-point multiplication: derive the public key from a scalar.
pub fn pubkey_from_scalar(scalar: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*scalar);
    PublicKey::from(&secret).to_bytes()
}

/// Full 32-byte account id: `SHA-256(pubkey)`.
pub fn kid_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    sha256_digest(pubkey)
}

/// Calculate SHA-256 through Orion for non-password protocol hashes.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data)
        .expect("SHA-256 digest should not fail")
        .as_ref()
        .try_into()
        .expect("SHA-256 outputs 32 bytes")
}

/// X-Wing account id: SHA-256 of the X-Wing public key.
pub fn kid_from_xwing_pubkey(pubkey: &[u8]) -> [u8; 32] {
    sha256_digest(pubkey)
}

/// Verify that a profile returned for a user-supplied full or prefix account
/// ID is the same account the caller requested.
pub fn account_id_matches_query(query: &str, kid: &[u8; 32]) -> bool {
    let query = query
        .trim()
        .strip_prefix("0x")
        .or_else(|| query.trim().strip_prefix("0X"))
        .unwrap_or(query.trim())
        .to_ascii_lowercase();
    let hex: String = kid.iter().map(|byte| format!("{byte:02x}")).collect();
    match query.len() {
        40 => hex.starts_with(&query),
        64 => hex == query,
        _ => false,
    }
}

/// 20-byte display prefix used in profile URLs (`0x` + 40 hex chars).
pub fn kid_prefix_from_pubkey(pubkey: &[u8; 32]) -> [u8; 20] {
    let full = kid_from_pubkey(pubkey);
    let mut prefix = [0u8; 20];
    prefix.copy_from_slice(&full[..20]);
    prefix
}

/// Generate a fresh X25519 keypair from the system RNG.
pub fn generate_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let mut scalar = [0u8; 32];
    getrandom::fill(&mut scalar).map_err(|e| format!("Failed to generate keypair: {}", e))?;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let pubkey = pubkey_from_scalar(&scalar);
    Ok((scalar, pubkey))
}

/// X25519 ECDH shared secret between a private key and a public key.
pub fn ecdh_shared_secret(private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], String> {
    X25519::shared_secret(private, public)
}

/// Seal a 32-byte secret (the challenge response) to `recipient_pub` using
/// the ephemeral private key. The AEAD key is
/// `HKDF-SHA256(ECDH(ephemeral_priv, recipient_pub), "mitsuzo-challenge-key")`,
/// so anyone holding a private key that completes the same ECDH (the account
/// holder OR the envelope's ephemeral key holder) can recover the secret.
/// Returns `(aead_nonce, sealed)` where `sealed` is 48 bytes.
pub fn seal_challenge(
    ephemeral_priv: &[u8; 32],
    recipient_pub: &[u8; 32],
    secret: &[u8; 32],
) -> Result<([u8; 12], [u8; 48]), String> {
    let shared = ecdh_shared_secret(ephemeral_priv, recipient_pub)?;
    let key = hkdf_expand_sha256(&shared, CHALLENGE_KEY_INFO);
    wrap_content_key(secret, &key)
}

/// Recover the 32-byte challenge response nonce from a sealed challenge.
pub fn open_challenge(
    private: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    nonce: &[u8; 12],
    sealed: &[u8; 48],
) -> Result<[u8; 32], String> {
    let shared = ecdh_shared_secret(private, ephemeral_pub)?;
    let key = hkdf_expand_sha256(&shared, CHALLENGE_KEY_INFO);
    unwrap_content_key(sealed, nonce, &key)
}

/// Wrap the account's X25519 scalar under a password-derived KEK.
/// `salt` is random per blob; the KEK comes from the same Argon2id + HKDF
/// pipeline as paste envelopes.
pub fn lock_account_key(scalar: &[u8; 32], password: &str) -> Result<AccountKeyBlob, String> {
    let salt = generate_salt()?;
    let (kek, _) = derive_keys(password, &salt)?;
    let (wrap_nonce, wrapped) = wrap_content_key(scalar, &kek)?;
    Ok(AccountKeyBlob {
        salt,
        wrap_nonce,
        wrapped,
    })
}

/// Unwrap the account scalar from a password-encrypted blob. Fails on a
/// wrong password (ChaCha20-Poly1305 tag check).
pub fn unlock_account_key(blob: &AccountKeyBlob, password: &str) -> Result<[u8; 32], String> {
    let (kek, _) = derive_keys(password, &blob.salt)?;
    unwrap_content_key(&blob.wrapped, &blob.wrap_nonce, &kek)
}

/// Derive the AEAD key that seals a CEK for a recipient account from the
/// shared ECDH secret.
pub fn derive_recipient_cek_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_sha256(shared_secret, RECIPIENT_KEY_INFO)
}

/// Seal a content key to a recipient account. Symmetric under X25519 ECDH:
/// the recipient opens it with `ECDH(recipient_scalar, ephemeral_pub)` and a
/// sender holding `ephemeral_priv` opens it with
/// `ECDH(ephemeral_priv, recipient_pub)` — the same shared secret.
/// Returns `(aead_nonce, sealed_cek)` with `sealed_cek` 48 bytes.
pub fn seal_content_key_for_recipient(
    ephemeral_priv: &[u8; 32],
    recipient_pub: &[u8; 32],
    content_key: &[u8; 32],
) -> Result<([u8; 12], [u8; 48]), String> {
    let shared = ecdh_shared_secret(ephemeral_priv, recipient_pub)?;
    let key = derive_recipient_cek_key(&shared);
    wrap_content_key(content_key, &key)
}

/// Open a recipient-sealed content key with either the recipient account
/// scalar or the sender's ephemeral private key.
pub fn open_content_key_for_recipient(
    private: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    nonce: &[u8; 12],
    sealed_cek: &[u8; 48],
) -> Result<[u8; 32], String> {
    let shared = ecdh_shared_secret(private, ephemeral_pub)?;
    let key = derive_recipient_cek_key(&shared);
    unwrap_content_key(sealed_cek, nonce, &key)
}
