use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "pastes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub try_count: i32,
    pub expiration_timestamp: i64,
    pub data_type: Vec<u8>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub total_chunks: i32,
    pub received_chunks: i32,
    pub allow_download: bool,
    pub burn_after_read: bool,
    pub recipient_pub: Option<Vec<u8>>,
    pub recipient_kid: Option<Vec<u8>>,
    pub burn_receipt_hash: Vec<u8>,
    pub burned: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
