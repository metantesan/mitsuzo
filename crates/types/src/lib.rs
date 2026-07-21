use bitcode;
use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 65536;

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
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct CreatePasteResponse {
    pub id: String,
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
}

#[derive(Serialize, Deserialize, bitcode::Encode, bitcode::Decode, Debug, Clone, PartialEq)]
pub struct GetSaltResponse {
    pub salt: Vec<u8>,
    pub try_count: u32,
    pub ttl: u64,
    pub total_chunks: u32,
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

/// Assemble a framed payload: [4-byte header_len][header_bytes][content_bytes]
pub fn write_framed(header_bytes: &[u8], content: &[u8]) -> Vec<u8> {
    let header_len = header_bytes.len();
    let mut buf = Vec::with_capacity(4 + header_len + content.len());
    buf.extend_from_slice(&(header_len as u32).to_le_bytes());
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(content);
    buf
}

/// Split framed data into (header_bytes, content_bytes)
pub fn read_framed(data: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if data.len() < 4 {
        return Err("data too short");
    }
    let header_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    let header_end = 4 + header_len;
    if data.len() < header_end {
        return Err("data too short for header");
    }
    Ok((&data[4..header_end], &data[header_end..]))
}
