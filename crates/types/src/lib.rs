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

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct CreatePasteHeader {
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
    pub password_hash: [u8; 32],
    pub key: KeyEnvelope,
    pub try_count: Option<u32>,
    pub ttl_seconds: Option<u32>,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: u32,
    pub allow_download: bool,
    pub burn_after_read: bool,
    pub burn_receipt_hash: [u8; 32],
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
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetSaltResponse {
    pub salt: Vec<u8>,
    pub try_count: u32,
    pub ttl: u64,
    pub total_chunks: u32,
    pub total_size: u64,
    pub nonce: [u8; 12],
    pub key: Option<KeyEnvelope>,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub allow_download: bool,
    pub burn_after_read: bool,
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
}

pub struct PasteListing {
    pub id: String,
    pub size: u64,
    pub data_type: DataType,
    pub filename: Option<String>,
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
