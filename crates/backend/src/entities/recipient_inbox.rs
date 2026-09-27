use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "recipient_inbox")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub recipient_kid: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub paste_id: String,
    pub listing: Vec<u8>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
