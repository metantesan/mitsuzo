use orion::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, KeyPair};
use zeroize::Zeroize;

pub const XWING_PUBLIC_KEY_SIZE: usize = orion::kem::EK_SIZE;
pub const XWING_CIPHERTEXT_SIZE: usize = orion::kem::CIPHERTEXT_SIZE;

/// Key encapsulation abstraction for recipient key establishment.
pub trait KeyEncapsulation {
    const PUBLIC_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;

    /// Check a public key's encoding without generating a ciphertext.
    fn validate_public_key(public_key: &[u8]) -> Result<(), String>;

    /// Derive a public encapsulation key from a stable 32-byte secret seed.
    fn public_key(seed: &[u8; 32]) -> Result<Vec<u8>, String>;

    /// Encapsulate a fresh shared secret to a recipient public key.
    fn encapsulate(public_key: &[u8]) -> Result<([u8; 32], Vec<u8>), String>;

    /// Recover the shared secret with the recipient's stable secret seed.
    fn decapsulate(seed: &[u8; 32], ciphertext: &[u8]) -> Result<[u8; 32], String>;
}

/// Orion's X-Wing hybrid KEM: ML-KEM-768 combined with X25519.
pub struct XWingKeyEncapsulation;

impl KeyEncapsulation for XWingKeyEncapsulation {
    const PUBLIC_KEY_SIZE: usize = XWING_PUBLIC_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize = XWING_CIPHERTEXT_SIZE;

    fn validate_public_key(public_key: &[u8]) -> Result<(), String> {
        EncapsulationKey::try_from(public_key)
            .map(|_| ())
            .map_err(|_| "Invalid X-Wing public key".to_string())
    }

    fn public_key(seed: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut decapsulation_seed = derive_xwing_seed(seed);
        let decapsulation_key = DecapsulationKey::from(decapsulation_seed);
        decapsulation_seed.zeroize();
        let encapsulation_key = EncapsulationKey::try_from(&decapsulation_key)
            .map_err(|_| "Failed to derive X-Wing public key".to_string())?;
        Ok(encapsulation_key.as_ref().to_vec())
    }

    fn encapsulate(public_key: &[u8]) -> Result<([u8; 32], Vec<u8>), String> {
        let encapsulation_key = EncapsulationKey::try_from(public_key)
            .map_err(|_| "Invalid X-Wing public key".to_string())?;
        let (shared_secret, ciphertext) = encapsulation_key
            .encap()
            .map_err(|_| "X-Wing encapsulation failed".to_string())?;
        let secret = shared_secret
            .unprotected_as_ref()
            .try_into()
            .map_err(|_| "Invalid X-Wing shared-secret length".to_string())?;
        Ok((secret, ciphertext.as_ref().to_vec()))
    }

    fn decapsulate(seed: &[u8; 32], ciphertext: &[u8]) -> Result<[u8; 32], String> {
        let ciphertext = Ciphertext::try_from(ciphertext)
            .map_err(|_| "Invalid X-Wing ciphertext".to_string())?;
        let mut decapsulation_seed = derive_xwing_seed(seed);
        let decapsulation_key = DecapsulationKey::from(decapsulation_seed);
        decapsulation_seed.zeroize();
        let key_pair = KeyPair::try_from(&decapsulation_key)
            .map_err(|_| "Failed to derive X-Wing decapsulation key".to_string())?;
        let shared_secret = key_pair
            .decap(&ciphertext)
            .map_err(|_| "X-Wing decapsulation failed".to_string())?;
        shared_secret
            .unprotected_as_ref()
            .try_into()
            .map_err(|_| "Invalid X-Wing shared-secret length".to_string())
    }
}

/// Domain-separated X-Wing secret seed derived from the account's existing
/// X25519 scalar. This keeps the PQ key recoverable from the same BIP39 seed.
pub fn derive_xwing_public_key(account_scalar: &[u8; 32]) -> Result<Vec<u8>, String> {
    XWingKeyEncapsulation::public_key(account_scalar)
}

fn derive_xwing_seed(account_scalar: &[u8; 32]) -> [u8; 32] {
    crate::hkdf_expand_sha256(account_scalar, b"mitsuzo-account-xwing-v1")
}
