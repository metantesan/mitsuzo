use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "paste_recipients")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub paste_id: String,
    pub recipient_kid: Vec<u8>,
    pub ephemeral_pub: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sealed_cek: Vec<u8>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
