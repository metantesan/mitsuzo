use backend::entities::{
    account, chunk, credential, paste, recipient, recipient_inbox, stat, state,
};
use bitcode::encode;
use mitsuzo_migration::Migrator;
use mitsuzo_types::{DataType, PasteInboxListing};
use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

async fn test_database() -> sea_orm::DatabaseConnection {
    let id = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "mitsuzo-seaorm-test-{}-{id}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

#[tokio::test]
async fn normalized_entities_round_trip() {
    let db = test_database().await;

    account::ActiveModel {
        kid: Set(vec![7; 32]),
        pubkey: Set(vec![8; 32]),
        name: Set("alice".to_owned()),
        created_at: Set(123),
    }
    .insert(&db)
    .await
    .unwrap();

    paste::ActiveModel {
        id: Set("paste-1".to_owned()),
        try_count: Set(3),
        expiration_timestamp: Set(0),
        data_type: Set(encode(&DataType::Text)),
        filename: Set(None),
        content_type: Set(Some("text/plain".to_owned())),
        total_chunks: Set(1),
        received_chunks: Set(0),
        allow_download: Set(true),
        burn_after_read: Set(false),
        recipient_pub: Set(None),
        recipient_kid: Set(None),
        burn_receipt_hash: Set(vec![0; 32]),
        burned: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();

    credential::ActiveModel {
        paste_id: Set("paste-1".to_owned()),
        salt: Set(Some(vec![1; 16])),
        password_hash: Set(Some(vec![2; 32])),
        wrap_nonce: Set(None),
        wrapped_key: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    chunk::ActiveModel {
        paste_id: Set("paste-1".to_owned()),
        chunk_index: Set(0),
    }
    .insert(&db)
    .await
    .unwrap();

    let account = account::Entity::find_by_id(vec![7; 32])
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.name, "alice");
    let paste = paste::Entity::find_by_id("paste-1".to_owned())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paste.try_count, 3);
    assert_eq!(chunk::Entity::find().all(&db).await.unwrap().len(), 1);
}

#[tokio::test]
async fn cloned_connections_can_write_concurrently() {
    let db = test_database().await;
    let left = db.clone();
    let right = db.clone();

    let (a, b) = tokio::join!(
        async move {
            stat::ActiveModel {
                key: Set("left".to_owned()),
                value: Set(1),
            }
            .insert(&left)
            .await
        },
        async move {
            state::ActiveModel {
                key: Set("migration-complete".to_owned()),
                value: Set(vec![1]),
            }
            .insert(&right)
            .await
        }
    );
    a.unwrap();
    b.unwrap();

    assert_eq!(
        stat::Entity::find_by_id("left")
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .value,
        1
    );
    assert!(
        state::Entity::find_by_id("migration-complete")
            .one(&db)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn recipient_entities_store_normalized_inbox_data() {
    let db = test_database().await;
    paste::ActiveModel {
        id: Set("recipient-paste".to_owned()),
        try_count: Set(0),
        expiration_timestamp: Set(0),
        data_type: Set(encode(&DataType::Text)),
        filename: Set(None),
        content_type: Set(None),
        total_chunks: Set(0),
        received_chunks: Set(0),
        allow_download: Set(false),
        burn_after_read: Set(false),
        recipient_pub: Set(Some(vec![3; 32])),
        recipient_kid: Set(Some(vec![4; 32])),
        burn_receipt_hash: Set(vec![0; 32]),
        burned: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();
    recipient::ActiveModel {
        paste_id: Set("recipient-paste".to_owned()),
        recipient_kid: Set(vec![4; 32]),
        ephemeral_pub: Set(vec![5; 32]),
        nonce: Set(vec![6; 12]),
        sealed_cek: Set(vec![7; 48]),
    }
    .insert(&db)
    .await
    .unwrap();
    let listing = PasteInboxListing {
        id: "recipient-paste".to_owned(),
        data_type: DataType::Text,
        filename: None,
        created_at: 10,
    };
    recipient_inbox::ActiveModel {
        recipient_kid: Set(vec![4; 32]),
        paste_id: Set("recipient-paste".to_owned()),
        listing: Set(encode(&listing)),
    }
    .insert(&db)
    .await
    .unwrap();

    assert_eq!(recipient::Entity::find().all(&db).await.unwrap().len(), 1);
    assert_eq!(
        recipient_inbox::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}
