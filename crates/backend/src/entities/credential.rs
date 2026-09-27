use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "paste_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub paste_id: String,
    pub salt: Option<Vec<u8>>,
    pub password_hash: Option<Vec<u8>>,
    pub wrap_nonce: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
