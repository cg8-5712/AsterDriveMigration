use super::super::*;
use sea_orm::{ConnectionTrait, DbBackend, Schema};

pub(super) fn sqlite_url(path: &std::path::Path) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        path.to_string_lossy().replace('\\', "/")
    )
}

pub(super) async fn create_table<E: EntityTrait>(db: &DatabaseConnection, entity: E) -> Result<()> {
    let schema = Schema::new(DbBackend::Sqlite);
    db.execute(&schema.create_table_from_entity(entity)).await?;
    Ok(())
}

pub(super) async fn create_source_schema(db: &DatabaseConnection) -> Result<()> {
    create_table(db, cr::nodes::Entity).await?;
    create_table(db, cr::groups::Entity).await?;
    create_table(db, cr::users::Entity).await?;
    create_table(db, cr::storage_policies::Entity).await?;
    create_table(db, cr::files::Entity).await?;
    create_table(db, cr::entities::Entity).await?;
    create_table(db, cr::file_entities::Entity).await?;
    create_table(db, cr::shares::Entity).await?;
    create_table(db, cr::metadata::Entity).await?;
    create_table(db, cr::direct_links::Entity).await?;
    create_table(db, cr::tasks::Entity).await?;
    Ok(())
}

pub(super) async fn create_target_schema(db: &DatabaseConnection) -> Result<()> {
    aster_drive_schema_migration::Migrator::up(db, None)
        .await
        .wrap_err("apply upstream AsterDrive schema migrations for test target")?;
    Ok(())
}

pub(super) async fn seed_source(db: &DatabaseConnection) -> Result<()> {
    let now = chrono::Utc::now().fixed_offset();
    let policy = cr::storage_policies::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        name: Set("Local".to_string()),
        r#type: Set("local".to_string()),
        server: Set(None),
        bucket_name: Set(None),
        is_private: Set(Some(true)),
        access_key: Set(None),
        secret_key: Set(None),
        max_size: Set(None),
        dir_name_rule: Set(None),
        file_name_rule: Set(None),
        settings: Set(Some(json!({"chunk_size": 0}))),
        node_id: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await?;
    let group = cr::groups::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        name: Set("Administrators".to_string()),
        max_storage: Set(Some(1024 * 1024)),
        speed_limit: Set(None),
        permissions: Set(vec![1]),
        settings: Set(None),
        storage_policy_id: Set(Some(policy.id)),
        ..Default::default()
    }
    .insert(db)
    .await?;
    let user = cr::users::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        email: Set("admin@example.test".to_string()),
        nick: Set("admin".to_string()),
        password: Set(Some("legacy:hash".to_string())),
        status: Set("active".to_string()),
        storage: Set(128),
        two_factor_secret: Set(None),
        avatar: Set(None),
        settings: Set(None),
        group_users: Set(group.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    let folder = cr::files::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        r#type: Set(1),
        name: Set("Documents".to_string()),
        size: Set(0),
        primary_entity: Set(None),
        is_symbolic: Set(false),
        props: Set(None),
        file_children: Set(None),
        storage_policy_files: Set(Some(policy.id)),
        owner_id: Set(user.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    let entity = cr::entities::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        r#type: Set(0),
        source: Set("uploads/object.bin".to_string()),
        size: Set(128),
        reference_count: Set(1),
        upload_session_id: Set(None),
        recycle_options: Set(None),
        storage_policy_entities: Set(policy.id),
        created_by: Set(Some(user.id)),
        ..Default::default()
    }
    .insert(db)
    .await?;
    let file = cr::files::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        r#type: Set(0),
        name: Set("hello.txt".to_string()),
        size: Set(128),
        primary_entity: Set(Some(entity.id)),
        is_symbolic: Set(false),
        props: Set(None),
        file_children: Set(Some(folder.id)),
        storage_policy_files: Set(Some(policy.id)),
        owner_id: Set(user.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    cr::file_entities::ActiveModel {
        file_id: Set(file.id),
        entity_id: Set(entity.id),
    }
    .insert(db)
    .await?;
    cr::metadata::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        name: Set("author".to_string()),
        value: Set("Cloudreve".to_string()),
        is_public: Set(true),
        file_id: Set(file.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    cr::metadata::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        name: Set("tag:Important".to_string()),
        value: Set("#abc".to_string()),
        is_public: Set(true),
        file_id: Set(file.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    cr::shares::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        password: Set(Some("share-password".to_string())),
        views: Set(4),
        downloads: Set(2),
        expires: Set(None),
        remain_downloads: Set(Some(3)),
        file_shares: Set(Some(file.id)),
        user_shares: Set(Some(user.id)),
        props: Set(None),
        ..Default::default()
    }
    .insert(db)
    .await?;
    cr::direct_links::ActiveModel {
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        name: Set("legacy-name.txt".to_string()),
        downloads: Set(7),
        speed: Set(1024),
        file_id: Set(file.id),
        ..Default::default()
    }
    .insert(db)
    .await?;
    for status in ["completed", "processing"] {
        cr::tasks::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            r#type: Set("remote_download".to_string()),
            status: Set(status.to_string()),
            public_state: Set(json!({"progress": 50})),
            private_state: Set(Some("legacy-private-state".to_string())),
            correlation_id: Set(None),
            user_tasks: Set(Some(user.id)),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

pub(super) async fn seed_extra_blob_entities(
    db: &DatabaseConnection,
    count: usize,
) -> Result<Vec<i64>> {
    let now = chrono::Utc::now().fixed_offset();
    let policy_id = cr::storage_policies::Entity::find()
        .one(db)
        .await?
        .expect("seeded storage policy")
        .id;
    let user_id = cr::users::Entity::find()
        .one(db)
        .await?
        .expect("seeded user")
        .id;
    let mut ids = Vec::with_capacity(count);
    for index in 0..count {
        let entity = cr::entities::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            r#type: Set(0),
            source: Set(format!("uploads/extra-{index}.bin")),
            size: Set(256 + index as i64),
            reference_count: Set(1),
            upload_session_id: Set(None),
            recycle_options: Set(None),
            storage_policy_entities: Set(policy_id),
            created_by: Set(Some(user_id)),
            ..Default::default()
        }
        .insert(db)
        .await?;
        ids.push(entity.id);
    }
    Ok(ids)
}

pub(super) async fn seed_extra_files(
    db: &DatabaseConnection,
    entity_ids: &[i64],
) -> Result<Vec<i64>> {
    let now = chrono::Utc::now().fixed_offset();
    let policy_id = cr::storage_policies::Entity::find()
        .one(db)
        .await?
        .expect("seeded storage policy")
        .id;
    let user_id = cr::users::Entity::find()
        .one(db)
        .await?
        .expect("seeded user")
        .id;
    let folder_id = cr::files::Entity::find()
        .filter(cr::files::Column::Type.eq(1))
        .one(db)
        .await?
        .expect("seeded folder")
        .id;
    let mut ids = Vec::with_capacity(entity_ids.len());
    for (index, entity_id) in entity_ids.iter().copied().enumerate() {
        let file = cr::files::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            r#type: Set(0),
            name: Set(format!("extra-{index}.txt")),
            size: Set(256 + index as i64),
            primary_entity: Set(Some(entity_id)),
            is_symbolic: Set(false),
            props: Set(None),
            file_children: Set(Some(folder_id)),
            storage_policy_files: Set(Some(policy_id)),
            owner_id: Set(user_id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        cr::file_entities::ActiveModel {
            file_id: Set(file.id),
            entity_id: Set(entity_id),
        }
        .insert(db)
        .await?;
        ids.push(file.id);
    }
    if entity_ids.len() >= 2 {
        cr::file_entities::ActiveModel {
            file_id: Set(ids[0]),
            entity_id: Set(entity_ids[1]),
        }
        .insert(db)
        .await?;
    }
    Ok(ids)
}
