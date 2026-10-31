use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260927_000001_initial::Migration),
            Box::new(m20261013_000002_upload_token::Migration),
            Box::new(m20261031_000003_paste_version::Migration),
        ]
    }
}

mod m20261031_000003_paste_version {
    use super::Pastes;
    use sea_orm::sea_query::{Expr, Query};
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261031_000003_paste_version"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Pastes::Table)
                        .add_column(
                            ColumnDef::new(Pastes::Version)
                                .string()
                                .not_null()
                                .default("argon2id-hkdf-sha256-chacha20poly1305"),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .exec_stmt(
                    Query::update()
                        .table(Pastes::Table)
                        .value(Pastes::Version, "x25519-hkdf-sha256-chacha20poly1305")
                        .and_where(Expr::col(Pastes::RecipientKid).is_not_null())
                        .to_owned(),
                )
                .await?;
            Ok(())
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Pastes::Table)
                        .drop_column(Pastes::Version)
                        .to_owned(),
                )
                .await
        }
    }
}

mod m20260927_000001_initial {
    use super::{
        Accounts, AppState, PasteChunks, PasteCredentials, PasteRecipients, Pastes, RecipientInbox,
        Stats,
    };
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    #[async_trait::async_trait]
    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260927_000001_initial"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_table(
                    Table::create()
                        .table(Pastes::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(Pastes::Id).string().not_null().primary_key())
                        .col(ColumnDef::new(Pastes::TryCount).unsigned().not_null())
                        .col(
                            ColumnDef::new(Pastes::ExpirationTimestamp)
                                .unsigned()
                                .not_null(),
                        )
                        .col(ColumnDef::new(Pastes::DataType).binary().not_null())
                        .col(ColumnDef::new(Pastes::Filename).string())
                        .col(ColumnDef::new(Pastes::ContentType).string())
                        .col(ColumnDef::new(Pastes::TotalChunks).unsigned().not_null())
                        .col(ColumnDef::new(Pastes::ReceivedChunks).unsigned().not_null())
                        .col(ColumnDef::new(Pastes::AllowDownload).boolean().not_null())
                        .col(ColumnDef::new(Pastes::BurnAfterRead).boolean().not_null())
                        .col(ColumnDef::new(Pastes::RecipientPub).binary())
                        .col(ColumnDef::new(Pastes::RecipientKid).binary())
                        .col(ColumnDef::new(Pastes::BurnReceiptHash).binary().not_null())
                        .col(ColumnDef::new(Pastes::Burned).boolean().not_null())
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(PasteCredentials::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(PasteCredentials::PasteId)
                                .string()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(PasteCredentials::Salt).binary())
                        .col(ColumnDef::new(PasteCredentials::PasswordHash).binary())
                        .col(ColumnDef::new(PasteCredentials::WrapNonce).binary())
                        .col(ColumnDef::new(PasteCredentials::WrappedKey).binary())
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(PasteRecipients::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(PasteRecipients::PasteId)
                                .string()
                                .not_null()
                                .primary_key(),
                        )
                        .col(
                            ColumnDef::new(PasteRecipients::RecipientKid)
                                .binary()
                                .not_null(),
                        )
                        .col(
                            ColumnDef::new(PasteRecipients::EphemeralPub)
                                .binary()
                                .not_null(),
                        )
                        .col(ColumnDef::new(PasteRecipients::Nonce).binary().not_null())
                        .col(
                            ColumnDef::new(PasteRecipients::SealedCek)
                                .binary()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(PasteChunks::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(PasteChunks::PasteId).string().not_null())
                        .col(
                            ColumnDef::new(PasteChunks::ChunkIndex)
                                .unsigned()
                                .not_null(),
                        )
                        .primary_key(
                            Index::create()
                                .col(PasteChunks::PasteId)
                                .col(PasteChunks::ChunkIndex),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(RecipientInbox::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(RecipientInbox::RecipientKid)
                                .binary()
                                .not_null(),
                        )
                        .col(ColumnDef::new(RecipientInbox::PasteId).string().not_null())
                        .col(ColumnDef::new(RecipientInbox::Listing).binary().not_null())
                        .primary_key(
                            Index::create()
                                .col(RecipientInbox::RecipientKid)
                                .col(RecipientInbox::PasteId),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(Accounts::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Accounts::Kid)
                                .binary()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Accounts::Pubkey).binary().not_null())
                        .col(ColumnDef::new(Accounts::Name).string().not_null())
                        .col(ColumnDef::new(Accounts::CreatedAt).unsigned().not_null())
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(Stats::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(Stats::Key).string().not_null().primary_key())
                        .col(ColumnDef::new(Stats::Value).unsigned().not_null())
                        .to_owned(),
                )
                .await?;
            manager
                .create_table(
                    Table::create()
                        .table(AppState::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(AppState::Key)
                                .string()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(AppState::Value).binary().not_null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(AppState::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(Stats::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(Accounts::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(RecipientInbox::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(PasteChunks::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(PasteRecipients::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(PasteCredentials::Table).to_owned())
                .await?;
            manager
                .drop_table(Table::drop().table(Pastes::Table).to_owned())
                .await?;
            Ok(())
        }
    }
}

mod m20261013_000002_upload_token {
    use super::Pastes;
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    #[async_trait::async_trait]
    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20261013_000002_upload_token"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Pastes::Table)
                        .add_column(ColumnDef::new(Pastes::UploadTokenHash).binary().null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Pastes::Table)
                        .drop_column(Pastes::UploadTokenHash)
                        .to_owned(),
                )
                .await
        }
    }
}

#[derive(Iden)]
enum Pastes {
    Table,
    Id,
    Version,
    TryCount,
    ExpirationTimestamp,
    DataType,
    Filename,
    ContentType,
    TotalChunks,
    ReceivedChunks,
    AllowDownload,
    BurnAfterRead,
    RecipientPub,
    RecipientKid,
    BurnReceiptHash,
    Burned,
    UploadTokenHash,
}
#[derive(Iden)]
enum PasteCredentials {
    Table,
    PasteId,
    Salt,
    PasswordHash,
    WrapNonce,
    WrappedKey,
}
#[derive(Iden)]
enum PasteRecipients {
    Table,
    PasteId,
    RecipientKid,
    EphemeralPub,
    Nonce,
    SealedCek,
}
#[derive(Iden)]
enum PasteChunks {
    Table,
    PasteId,
    ChunkIndex,
}
#[derive(Iden)]
enum RecipientInbox {
    Table,
    RecipientKid,
    PasteId,
    Listing,
}
#[derive(Iden)]
enum Accounts {
    Table,
    Kid,
    Pubkey,
    Name,
    CreatedAt,
}
#[derive(Iden)]
enum Stats {
    Table,
    Key,
    Value,
}
#[derive(Iden)]
enum AppState {
    Table,
    Key,
    Value,
}
