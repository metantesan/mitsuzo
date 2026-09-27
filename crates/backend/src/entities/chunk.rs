use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "paste_chunks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub paste_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub chunk_index: i32,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
