use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 65536;
pub const UPLOAD_CHUNK_SIZE: usize = 16_777_216;
pub const MAX_PASTE_SIZE: usize = 1_073_741_824;

/// Serde support for 48-byte arrays (serde only implements arrays up to 32).
mod serde_bytes_48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        let len = v.len();
        v.try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))
    }
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub enum DataType {
    Text,
    File,
}

/// Password-wrapped content encryption key (envelope encryption).
/// `wrapped_key` is the 32-byte CEK + 16-byte Poly1305 tag, sealed
/// with a key derived from the paste password via Argon2id + HKDF.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct KeyEnvelope {
    pub wrap_nonce: [u8; 12],
    #[serde(with = "serde_bytes_48")]
    pub wrapped_key: [u8; 48],
}

/// A content key sealed to a recipient account's X25519 public key.
/// `ephemeral_pub` is the sender's one-shot X25519 public key;
/// `sealed_cek` is the 32-byte CEK + 16-byte Poly1305 tag sealed with
/// `HKDF-SHA256(ECDH(ephemeral_priv, recipient_pub), "mitsuzo-recipient-key")`.
/// By X25519 symmetry the same `sealed_cek` opens with the recipient's
/// account scalar (`ECDH(recipient_priv, ephemeral_pub)`), so both the
/// recipient and the sender (who retains `ephemeral_priv`) can decrypt.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct RecipientEnvelope {
    /// Full 32-byte SHA-256 of the recipient's public key.
    pub recipient_kid: [u8; 32],
    /// One-shot sender public key.
    pub ephemeral_pub: [u8; 32],
    /// ChaCha20-Poly1305 nonce used to seal the CEK.
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes_48")]
    pub sealed_cek: [u8; 48],
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct CreatePasteHeader {
    pub nonce: [u8; 12],
    pub salt: Option<[u8; 16]>,
    pub password_hash: Option<[u8; 32]>,
    pub key: Option<KeyEnvelope>,
    pub try_count: Option<u32>,
    pub ttl_seconds: Option<u32>,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: u32,
    pub allow_download: bool,
    pub burn_after_read: bool,
    pub burn_receipt_hash: [u8; 32],
    /// Recipient mode: set when the paste is encrypted to an account. When
    /// set, `salt`/`password_hash`/`key` must all be `None` (and vice versa).
    /// Carries the recipient's public key so the server can authenticate a
    /// futute `/data` fetch even if the account is later deleted.
    pub recipient: Option<RecipientEnvelope>,
    pub recipient_pub: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct InitPasteResponse {
    pub id: String,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct ChunkInfoResponse {
    pub received: u32,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetPasteHeader {
    pub id: String,
    pub nonce: [u8; 12],
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_size: u64,
    pub total_chunks: u32,
    pub allow_download: bool,
    /// Password-wrapped content key, delivered only with the authenticated
    /// blob. `None` for legacy pastes created before envelope encryption.
    pub key: Option<KeyEnvelope>,
    /// Remaining tries after this successful decryption.
    pub try_count: u32,
    /// Seconds until the paste expires (0/MAX when it never expires).
    pub ttl: u64,
    pub burn_after_read: bool,
    /// Present for recipient-mode pastes: carries the envelope the client
    /// needs to open the CEK via ECDH after authenticating.
    pub recipient: Option<RecipientEnvelope>,
}

impl GetPasteHeader {
    /// Serialize as a length-prefixed metadata frame: `[u32 LE len][bitcode]`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let header_bytes = bitcode::encode(self);
        let mut out = Vec::with_capacity(4 + header_bytes.len());
        out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out
    }
}

/// Split a framed paste body into its metadata header and the trailing
/// ciphertext.
pub fn split_paste_frame(data: &[u8]) -> Result<(GetPasteHeader, &[u8]), String> {
    if data.len() < 4 {
        return Err("truncated paste frame".to_string());
    }
    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if 4 + len > data.len() {
        return Err("truncated paste frame".to_string());
    }
    let header: GetPasteHeader = bitcode::decode(&data[4..4 + len]).map_err(|e| e.to_string())?;
    Ok((header, &data[4 + len..]))
}

/// The recipient account a paste is encrypted to, served pre-auth so the
/// client can tell the user exactly which account must be unlocked.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct PasteRecipientInfo {
    /// Full 32-byte SHA-256 of the recipient's public key.
    pub kid: [u8; 32],
    /// 20-byte display prefix (`0x` + 40 hex in URLs).
    pub kid_prefix: [u8; 20],
    /// Registered display name, if the account still exists on the server.
    pub name: Option<String>,
}

/// How a paste authenticates. Served explicitly in the `/salt` probe so
/// clients never have to infer the mode from `salt: None` or a 404.
#[derive(
    Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, Copy, PartialEq,
)]
pub enum PasteAuthMode {
    /// Sealed to a password; authenticated with `X-Password-Hash`.
    Password,
    /// Sealed to a user account's X25519 key; authenticated with
    /// `X-Account-Proof` after solving the server challenge.
    Recipient,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetSaltResponse {
    /// Explicit auth mode. Unlike guessing from `salt: None` / a 404, this
    /// is unambiguous: `Password` always carries the Argon2id salt, and
    /// `Recipient` always carries a recipient.
    pub mode: PasteAuthMode,
    /// Argon2id salt for password-mode pastes. `None` for recipient mode.
    /// Served without authentication — the client needs it to derive the
    /// validation key before it can produce the password hash. All other
    /// metadata requires X-Password-Hash (or X-Account-Proof) and is
    /// delivered in the authenticated /data metadata frame.
    pub salt: Option<Vec<u8>>,
    /// Who can decrypt this paste. `Some` only for recipient-mode pastes.
    pub recipient: Option<PasteRecipientInfo>,
}

/// Body of an unauthenticated (401) attempt against a content or password
/// endpoint. Carries the remaining try count and TTL so the UI can stay in
/// sync with the server's enforcement.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct FailedAttempt {
    pub try_count: u32,
    pub ttl: u64,
}

/// Body of `POST /paste/{id}/password`. New credentials only — the old
/// password hash travels in the `X-Password-Hash` header for authentication.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct ChangePasswordRequest {
    pub salt: [u8; 16],
    pub password_hash: [u8; 32],
    pub key: KeyEnvelope,
}

#[derive(bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct PasteMeta {
    pub try_count: u32,
    pub expiration_timestamp: u64,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: u32,
    pub allow_download: bool,
    pub burn_after_read: bool,
    /// Recipient account public key for recipient-mode pastes. Lets the
    /// server seal a `/data` challenge even if the account is later removed.
    pub recipient_pub: Option<[u8; 32]>,
    /// Full 32-byte SHA-256 of the recipient's public key.
    pub recipient_kid: Option<[u8; 32]>,
}

/// Frozen snapshot of the pre-account `PasteMeta` wire format, used only to
/// migrate existing sled rows to the version with `recipient_pub`/`recipient_kid`.
#[derive(bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct LegacyPasteMeta {
    pub try_count: u32,
    pub expiration_timestamp: u64,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: u32,
    pub allow_download: bool,
    pub burn_after_read: bool,
}

pub struct PasteListing {
    pub id: String,
    pub size: u64,
    pub data_type: DataType,
    pub filename: Option<String>,
}

/// Password-encrypted portable account key blob. The X25519 scalar is
/// ChaCha20-Poly1305-wrapped with the key-encryption key derived from the
/// account password via Argon2id (`mitsuzo_utils::derive_keys`). Identical
/// format in the browser (`localStorage`) and the CLI
/// (`~/.config/mitsuzo/account.enc`) so one account works in both clients.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct AccountKeyBlob {
    pub salt: [u8; 16],
    pub wrap_nonce: [u8; 12],
    #[serde(with = "serde_bytes_48")]
    pub wrapped: [u8; 48],
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct RegisterAccountRequest {
    /// Full 32-byte SHA-256 of `pubkey`. The server recomputes and rejects on mismatch.
    pub kid: [u8; 32],
    pub pubkey: [u8; 32],
    pub name: String,
}

/// Persisted account record (sled `acct:` namespace).
#[derive(bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct AccountRecord {
    pub kid: [u8; 32],
    pub pubkey: [u8; 32],
    pub name: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct AccountProfileResponse {
    /// Full 32-byte SHA-256 of the public key.
    pub kid: [u8; 32],
    /// 20-byte display prefix (`0x` + 40 hex chars in URLs).
    pub kid_prefix: [u8; 20],
    pub pubkey: [u8; 32],
    pub name: String,
}

/// Server-issued login challenge. `ephemeral_pub` is the server's one-shot
/// X25519 public key; `sealed` holds a random 32-byte response nonce sealed
/// with `HKDF-SHA256(ECDH(server_ephemeral_priv, account_pubkey), "mitsuzo-challenge-key")`.
/// The client recovers the nonce via `ECDH(account_scalar, ephemeral_pub)`
/// and returns it in an `X-Account-Proof` header or a `ChangeNameRequest`.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct ChallengeResponse {
    pub ephemeral_pub: [u8; 32],
    /// ChaCha20-Poly1305 nonce used to seal `sealed`.
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes_48")]
    pub sealed: [u8; 48],
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct ChangeNameRequest {
    pub name: String,
    /// The 32-byte response nonce recovered by solving the challenge.
    pub challenge_response: [u8; 32],
}

/// Body of the 401 issued by the recipient branch of `/api/paste/{id}/data`.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct RecipientAuthChallenge {
    pub challenge: ChallengeResponse,
}

/// A paste addressed to a user account, listed in that account's inbox.
#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct PasteInboxListing {
    pub id: String,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct InboxResponse {
    pub pastes: Vec<PasteInboxListing>,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetStatsResponse {
    pub pastes_all_time: u64,
    pub pastes_daily: u64,
    pub requests_success_all_time: u64,
    pub requests_success_daily: u64,
    pub requests_fail_all_time: u64,
    pub requests_fail_daily: u64,
    pub demo_mode: bool,
    pub max_ttl_seconds: u32,
    pub max_file_size: u64,
}
