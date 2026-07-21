use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 65536;
pub const UPLOAD_CHUNK_SIZE: usize = 16_777_216;
pub const MAX_PASTE_SIZE: usize = 1_073_741_824;

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub enum DataType {
    Text,
    File,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct CreatePasteHeader {
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
    pub password_hash: [u8; 32],
    pub try_count: Option<u32>,
    pub ttl_seconds: Option<u32>,
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: u32,
    pub allow_download: bool,
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
    pub data_type: DataType,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub allow_download: bool,
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetStatsResponse {
    pub pastes_all_time: u64,
    pub pastes_daily: u64,
    pub requests_success_all_time: u64,
    pub requests_success_daily: u64,
    pub requests_fail_all_time: u64,
    pub requests_fail_daily: u64,
}
