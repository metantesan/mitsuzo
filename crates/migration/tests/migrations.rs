use mitsuzo_migration::Migrator;
use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use sea_orm_migration::MigratorTrait;

#[tokio::test]
async fn migrations_are_idempotent_and_reversible() {
    let db = Database::connect("sqlite::memory:").await.unwrap();

    Migrator::up(&db, None).await.unwrap();
    let applied_once = Migrator::get_applied_migrations(&db).await.unwrap();
    assert_eq!(applied_once.len(), 3);

    // Startup may call the migrator more than once; this must be harmless.
    Migrator::up(&db, None).await.unwrap();
    let applied_twice = Migrator::get_applied_migrations(&db).await.unwrap();
    let once_names: Vec<_> = applied_once.iter().map(|m| m.name()).collect();
    let twice_names: Vec<_> = applied_twice.iter().map(|m| m.name()).collect();
    assert_eq!(twice_names, once_names);

    Migrator::down(&db, None).await.unwrap();
    assert!(
        Migrator::get_applied_migrations(&db)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn existing_pastes_are_classified_by_recipient_mode() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, Some(2)).await.unwrap();
    for (id, recipient) in [("password", "NULL"), ("recipient", "X'01'")] {
        db.execute_unprepared(&format!(
            "INSERT INTO pastes (id, try_count, expiration_timestamp, data_type, total_chunks, received_chunks, allow_download, burn_after_read, recipient_kid, burn_receipt_hash, burned) VALUES ('{id}', 0, 0, X'00', 1, 0, 1, 0, {recipient}, X'00', 0)"
        )).await.unwrap();
    }
    Migrator::up(&db, None).await.unwrap();
    for (id, expected) in [
        ("password", "argon2id-hkdf-sha256-chacha20poly1305"),
        ("recipient", "x25519-hkdf-sha256-chacha20poly1305"),
    ] {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT version FROM pastes WHERE id = ?",
                [id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "version").unwrap(), expected);
    }
}
