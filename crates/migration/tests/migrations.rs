use mitsuzo_migration::Migrator;
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;

#[tokio::test]
async fn migrations_are_idempotent_and_reversible() {
    let db = Database::connect("sqlite::memory:").await.unwrap();

    Migrator::up(&db, None).await.unwrap();
    let applied_once = Migrator::get_applied_migrations(&db).await.unwrap();
    assert_eq!(applied_once.len(), 1);

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
