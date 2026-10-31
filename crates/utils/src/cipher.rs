/// Content AEAD abstraction. Implementations preserve their own nonce format.
pub trait ContentCipher {
    const NONCE_LEN: usize;

    fn encrypt_chunk(
        key: &[u8; 32],
        base_nonce: &[u8],
        index: u32,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String>;

    fn decrypt_chunk(
        key: &[u8; 32],
        base_nonce: &[u8],
        index: u32,
        ciphertext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String>;
}

pub struct ChaCha20Poly1305;
pub struct XChaCha20Poly1305;

impl ContentCipher for ChaCha20Poly1305 {
    const NONCE_LEN: usize = 12;
    fn encrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        crate::encrypt_chunk_into(
            plaintext,
            key,
            nonce
                .try_into()
                .map_err(|_| "ChaCha nonce must be 12 bytes")?,
            index,
            output,
        )
    }
    fn decrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        ciphertext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        crate::decrypt_chunk_into(
            ciphertext,
            key,
            nonce
                .try_into()
                .map_err(|_| "ChaCha nonce must be 12 bytes")?,
            index,
            output,
        )
    }
}

impl ContentCipher for XChaCha20Poly1305 {
    const NONCE_LEN: usize = 24;
    fn encrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        crate::encrypt_xchacha_chunk_into(
            plaintext,
            key,
            nonce
                .try_into()
                .map_err(|_| "XChaCha nonce must be 24 bytes")?,
            index,
            output,
        )
    }
    fn decrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        ciphertext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        crate::decrypt_xchacha_chunk_into(
            ciphertext,
            key,
            nonce
                .try_into()
                .map_err(|_| "XChaCha nonce must be 24 bytes")?,
            index,
            output,
        )
    }
}

/// User-selectable content cipher for new paste creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentCipherKind {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl ContentCipherKind {
    pub fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub fn encrypt_chunk(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), String> {
        match self {
            Self::ChaCha20Poly1305 => {
                ChaCha20Poly1305::encrypt_chunk(key, nonce, index, input, out)
            }
            Self::XChaCha20Poly1305 => {
                XChaCha20Poly1305::encrypt_chunk(key, nonce, index, input, out)
            }
        }
    }

    pub fn decrypt_chunk(
        self,
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), String> {
        match self {
            Self::ChaCha20Poly1305 => {
                ChaCha20Poly1305::decrypt_chunk(key, nonce, index, input, out)
            }
            Self::XChaCha20Poly1305 => {
                XChaCha20Poly1305::decrypt_chunk(key, nonce, index, input, out)
            }
        }
    }
}

impl ContentCipher for ContentCipherKind {
    const NONCE_LEN: usize = 24;
    fn encrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        plaintext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        Self::XChaCha20Poly1305.encrypt_chunk(key, nonce, index, plaintext, output)
    }
    fn decrypt_chunk(
        key: &[u8; 32],
        nonce: &[u8],
        index: u32,
        ciphertext: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        Self::XChaCha20Poly1305.decrypt_chunk(key, nonce, index, ciphertext, output)
    }
}

/// Password key derivation and validation key production.
pub trait PasswordKeyDerivation {
    fn derive(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), String>;
}

pub fn derive_keys(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    Argon2idHkdfSha256::derive(password, salt)
}

pub struct Argon2idHkdfSha256;
impl PasswordKeyDerivation for Argon2idHkdfSha256 {
    fn derive(password: &str, salt: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
        crate::password::derive_argon2id_keys(password, salt)
    }
}

/// Key wrapping is deliberately independent from bulk content encryption.
pub trait KeyEncryption {
    type Nonce;
    type Sealed;
    fn seal(key: &[u8; 32], plaintext: &[u8; 32]) -> Result<(Self::Nonce, Self::Sealed), String>;
    fn open(key: &[u8; 32], nonce: &Self::Nonce, sealed: &Self::Sealed)
    -> Result<[u8; 32], String>;
}

pub struct ChaChaKeyWrap;
impl KeyEncryption for ChaChaKeyWrap {
    type Nonce = [u8; 12];
    type Sealed = [u8; 48];
    fn seal(key: &[u8; 32], plaintext: &[u8; 32]) -> Result<(Self::Nonce, Self::Sealed), String> {
        crate::chacha::wrap_content_key_raw(plaintext, key)
    }
    fn open(
        key: &[u8; 32],
        nonce: &Self::Nonce,
        sealed: &Self::Sealed,
    ) -> Result<[u8; 32], String> {
        crate::chacha::unwrap_content_key_raw(sealed, nonce, key)
    }
}

pub fn wrap_content_key(
    plaintext: &[u8; 32],
    key: &[u8; 32],
) -> Result<([u8; 12], [u8; 48]), String> {
    ChaChaKeyWrap::seal(key, plaintext)
}

pub fn unwrap_content_key(
    sealed: &[u8; 48],
    nonce: &[u8; 12],
    key: &[u8; 32],
) -> Result<[u8; 32], String> {
    ChaChaKeyWrap::open(key, nonce, sealed)
}
