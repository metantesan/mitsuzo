use crate::{
    KeyEncapsulation, XWingKeyEncapsulation, hkdf_expand_sha256, unwrap_content_key,
    wrap_content_key,
};

const RECIPIENT_KEY_INFO: &[u8] = b"mitsuzo-xwing-recipient-key-v1";

/// Encapsulate to a recipient, then wrap the paste's content key. The returned
/// shared secret is held by the sender only for reopening this paste in-session.
pub fn seal_content_key_for_xwing(
    public_key: &[u8],
    content_key: &[u8; 32],
) -> Result<([u8; 32], Vec<u8>, [u8; 12], [u8; 48]), String> {
    let (shared_secret, ciphertext) = XWingKeyEncapsulation::encapsulate(public_key)?;
    let wrap_key = derive_wrap_key(&shared_secret);
    let (nonce, sealed) = wrap_content_key(content_key, &wrap_key)?;
    Ok((shared_secret, ciphertext, nonce, sealed))
}

/// Decapsulate an X-Wing envelope and unwrap its content key.
pub fn open_content_key_for_xwing(
    seed: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    sealed: &[u8; 48],
) -> Result<[u8; 32], String> {
    let shared_secret = XWingKeyEncapsulation::decapsulate(seed, ciphertext)?;
    open_content_key_for_xwing_shared(&shared_secret, nonce, sealed)
}

/// Sender-side opening with the encapsulation shared secret retained in memory.
pub fn open_content_key_for_xwing_shared(
    shared_secret: &[u8; 32],
    nonce: &[u8; 12],
    sealed: &[u8; 48],
) -> Result<[u8; 32], String> {
    let wrap_key = derive_wrap_key(shared_secret);
    unwrap_content_key(sealed, nonce, &wrap_key)
}

fn derive_wrap_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_sha256(shared_secret, RECIPIENT_KEY_INFO)
}
