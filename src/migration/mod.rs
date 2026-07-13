use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use color_eyre::eyre::{Result, WrapErr, bail};
use sea_orm::{
    ActiveModelTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait, Set,
    TransactionTrait,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use asterdrive_entities as ad;
use cloudreve_entities as cr;

#[derive(Debug, Clone)]
pub struct MigrationOptions {
    pub source_url: String,
    pub target_url: String,
    pub default_password: String,
    pub local_base_path: String,
    pub include_deleted: bool,
    pub allow_non_empty_target: bool,
    pub skip_unsupported_policies: bool,
    pub dry_run: bool,
}

#[derive(Debug, Default, Clone)]
pub struct MigrationReport {
    pub source_users: u64,
    pub source_groups: u64,
    pub source_policies: u64,
    pub source_folders: u64,
    pub source_files: u64,
    pub source_entities: u64,
    pub source_shares: u64,
    pub migrated_users: usize,
    pub migrated_policy_groups: usize,
    pub migrated_policies: usize,
    pub migrated_folders: usize,
    pub migrated_files: usize,
    pub migrated_blobs: usize,
    pub migrated_versions: usize,
    pub migrated_shares: usize,
    pub migrated_properties: usize,
    pub skipped: usize,
    pub dry_run: bool,
    pub warnings: Vec<String>,
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        writeln!(output, "Cloudreve -> AsterDrive migration report")?;
        writeln!(
            output,
            "source: users={}, groups={}, policies={}, folders={}, files={}, entities={}, shares={}",
            self.source_users,
            self.source_groups,
            self.source_policies,
            self.source_folders,
            self.source_files,
            self.source_entities,
            self.source_shares
        )?;
        if self.dry_run {
            writeln!(output, "mode: dry-run (target was not modified)")?;
        } else {
            writeln!(
                output,
                "migrated: users={}, policy_groups={}, policies={}, folders={}, files={}, blobs={}, versions={}, shares={}, properties={}",
                self.migrated_users,
                self.migrated_policy_groups,
                self.migrated_policies,
                self.migrated_folders,
                self.migrated_files,
                self.migrated_blobs,
                self.migrated_versions,
                self.migrated_shares,
                self.migrated_properties
            )?;
            writeln!(output, "skipped: {}", self.skipped)?;
        }
        if !self.warnings.is_empty() {
            writeln!(output, "warnings:")?;
            for warning in &self.warnings {
                writeln!(output, "- {warning}")?;
            }
        }
        formatter.write_str(output.trim_end())
    }
}

pub async fn inspect(
    source_url: &str,
    target_url: &str,
    include_deleted: bool,
) -> Result<MigrationReport> {
    let source = connect(source_url, "Cloudreve").await?;
    let target = connect(target_url, "AsterDrive").await?;
    let source_data = SourceData::load(&source, include_deleted).await?;
    validate_target_schema(&target).await?;
    let mut report = source_data.report();
    report.dry_run = true;
    report.warnings.extend(source_data.compatibility_warnings());
    Ok(report)
}

pub async fn migrate(options: MigrationOptions) -> Result<MigrationReport> {
    if options.default_password.chars().count() < 8 {
        bail!("--default-password must contain at least 8 characters");
    }

    let source = connect(&options.source_url, "Cloudreve").await?;
    let target = connect(&options.target_url, "AsterDrive").await?;
    let source_data = SourceData::load(&source, options.include_deleted).await?;
    validate_target_schema(&target).await?;
    ensure_target_safe(&target, options.allow_non_empty_target).await?;

    let unsupported = source_data.unsupported_policy_types();
    if !unsupported.is_empty() && !options.skip_unsupported_policies {
        bail!(
            "unsupported Cloudreve storage policy types: {}; rerun with --skip-unsupported-policies to omit their files",
            unsupported.join(", ")
        );
    }

    let mut report = source_data.report();
    report.dry_run = options.dry_run;
    report.warnings.extend(source_data.compatibility_warnings());
    if options.dry_run {
        return Ok(report);
    }

    let password_hash = hash_password(&options.default_password)?;
    let transaction = target
        .begin()
        .await
        .wrap_err("begin AsterDrive transaction")?;
    let mut context = MigrationContext::default();

    migrate_policies(
        &transaction,
        &source_data,
        &options,
        &mut context,
        &mut report,
    )
    .await?;
    migrate_policy_groups(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_users(
        &transaction,
        &source_data,
        &password_hash,
        &mut context,
        &mut report,
    )
    .await?;
    migrate_folders(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_blobs(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_files(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_metadata(&transaction, &source_data, &context, &mut report).await?;
    migrate_shares(&transaction, &source_data, &context, &mut report).await?;

    transaction
        .commit()
        .await
        .wrap_err("commit AsterDrive migration transaction")?;
    Ok(report)
}

async fn connect(url: &str, label: &str) -> Result<DatabaseConnection> {
    Database::connect(url)
        .await
        .wrap_err_with(|| format!("connect to {label} database"))
}

async fn validate_target_schema(db: &DatabaseConnection) -> Result<()> {
    ad::users::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive schema is unavailable; run AD database migrations first")?;
    ad::storage_policies::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive storage_policies table is unavailable")?;
    ad::files::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive files table is unavailable")?;
    Ok(())
}

async fn ensure_target_safe(db: &DatabaseConnection, allow_non_empty: bool) -> Result<()> {
    if allow_non_empty {
        return Ok(());
    }
    let counts = [
        ("users", ad::users::Entity::find().count(db).await?),
        ("folders", ad::folders::Entity::find().count(db).await?),
        ("files", ad::files::Entity::find().count(db).await?),
        (
            "file_blobs",
            ad::file_blobs::Entity::find().count(db).await?,
        ),
        ("shares", ad::shares::Entity::find().count(db).await?),
    ];
    let occupied: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(table, count)| format!("{table}={count}"))
        .collect();
    if !occupied.is_empty() {
        bail!(
            "target AD database is not empty ({}); use a freshly migrated database or pass --allow-non-empty-target",
            occupied.join(", ")
        );
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("create password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| color_eyre::eyre::eyre!("hash temporary AD password: {error}"))
}

#[derive(Default)]
struct MigrationContext {
    policies: HashMap<i64, i64>,
    policy_groups: HashMap<i64, i64>,
    users: HashMap<i64, i64>,
    usernames: HashMap<i64, String>,
    folders: HashMap<i64, i64>,
    blobs: HashMap<i64, i64>,
    files: HashMap<i64, i64>,
}

struct SourceData {
    groups: Vec<cr::groups::Model>,
    users: Vec<cr::users::Model>,
    policies: Vec<cr::storage_policies::Model>,
    files: Vec<cr::files::Model>,
    entities: Vec<cr::entities::Model>,
    file_entities: Vec<cr::file_entities::Model>,
    shares: Vec<cr::shares::Model>,
    metadata: Vec<cr::metadata::Model>,
}

impl SourceData {
    async fn load(db: &DatabaseConnection, include_deleted: bool) -> Result<Self> {
        let groups = cr::groups::Entity::find().all(db).await?;
        let users = cr::users::Entity::find().all(db).await?;
        let policies = cr::storage_policies::Entity::find().all(db).await?;
        let files = cr::files::Entity::find().all(db).await?;
        let entities = cr::entities::Entity::find().all(db).await?;
        let file_entities = cr::file_entities::Entity::find().all(db).await?;
        let shares = cr::shares::Entity::find().all(db).await?;
        let metadata = cr::metadata::Entity::find().all(db).await?;

        Ok(Self {
            groups: filter_deleted(groups, include_deleted, |model| model.deleted_at.is_some()),
            users: filter_deleted(users, include_deleted, |model| model.deleted_at.is_some()),
            policies: filter_deleted(policies, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            files,
            entities: filter_deleted(entities, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            file_entities,
            shares: filter_deleted(shares, include_deleted, |model| model.deleted_at.is_some()),
            metadata: filter_deleted(metadata, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
        })
    }

    fn report(&self) -> MigrationReport {
        MigrationReport {
            source_users: self.users.len() as u64,
            source_groups: self.groups.len() as u64,
            source_policies: self.policies.len() as u64,
            source_folders: self.files.iter().filter(|file| file.r#type == 1).count() as u64,
            source_files: self.files.iter().filter(|file| file.r#type == 0).count() as u64,
            source_entities: self.entities.len() as u64,
            source_shares: self.shares.len() as u64,
            ..Default::default()
        }
    }

    fn unsupported_policy_types(&self) -> Vec<String> {
        let mut values: Vec<String> = self
            .policies
            .iter()
            .filter_map(unsupported_policy_reason)
            .collect();
        values.sort();
        values.dedup();
        values
    }

    fn compatibility_warnings(&self) -> Vec<String> {
        let mut warnings = vec![
            "Cloudreve user passwords use SHA/legacy MD5 formats and are replaced by the supplied temporary Argon2 password; every migrated user is marked must_change_password".to_string(),
            "OAuth grants, login sessions, background tasks and Cloudreve filesystem events are intentionally not migrated".to_string(),
            "Cloudreve Passkeys, WebDAV credentials and two-factor secrets are not portable to AD and must be enrolled again".to_string(),
            "file objects are reused in their existing local/object-storage locations; the migration does not duplicate object bytes".to_string(),
        ];
        let symbolic = self.files.iter().filter(|file| file.is_symbolic).count();
        if symbolic > 0 {
            warnings.push(format!(
                "{symbolic} symbolic/placeholder Cloudreve files cannot be represented in AD and will be skipped"
            ));
        }
        let unsupported = self.unsupported_policy_types();
        if !unsupported.is_empty() {
            warnings.push(format!(
                "unsupported storage policy types detected: {}",
                unsupported.join(", ")
            ));
        }
        warnings
    }
}

fn filter_deleted<T, F>(items: Vec<T>, include_deleted: bool, deleted: F) -> Vec<T>
where
    F: Fn(&T) -> bool,
{
    if include_deleted {
        items
    } else {
        items.into_iter().filter(|item| !deleted(item)).collect()
    }
}

fn map_driver_type(source: &str) -> Option<&'static str> {
    match source {
        "local" => Some("local"),
        "s3" | "oss" | "ks3" | "obs" => Some("s3"),
        "cos" => Some("tencent_cos"),
        _ => None,
    }
}

fn unsupported_policy_reason(policy: &cr::storage_policies::Model) -> Option<String> {
    if map_driver_type(&policy.r#type).is_none() {
        return Some(policy.r#type.clone());
    }
    if source_settings(&policy.settings)
        .get("encryption")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Some(format!("{} (Cloudreve encryption enabled)", policy.r#type));
    }
    None
}

fn source_settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
}

fn policy_options(policy: &cr::storage_policies::Model) -> String {
    let settings = source_settings(&policy.settings);
    let path_style = settings
        .get("s3_path_style")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    json!({
        "s3_path_style": path_style,
        "object_storage_upload_strategy": "relay_stream",
        "object_storage_download_strategy": "relay_stream",
        "cloudreve_source": settings,
        "cloudreve_policy_type": policy.r#type,
    })
    .to_string()
}

fn allowed_types(policy: &cr::storage_policies::Model) -> String {
    source_settings(&policy.settings)
        .get("file_type")
        .cloned()
        .unwrap_or_else(|| json!([]))
        .to_string()
}

fn chunk_size(policy: &cr::storage_policies::Model) -> i64 {
    source_settings(&policy.settings)
        .get("chunk_size")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn group_is_admin(group: &cr::groups::Model) -> bool {
    group
        .permissions
        .first()
        .is_some_and(|permissions| permissions & 1 == 1)
}

fn opaque_blob_key(entity_id: i64) -> String {
    format!("cloudreve-{entity_id:016x}")
}

fn share_token(share_id: i64) -> String {
    let digest = Sha256::digest(format!("cloudreve-share-{share_id}").as_bytes());
    format!("cr-{share_id}-{}", &format!("{digest:x}")[..16])
}

fn unique_username(source: &str, source_id: i64, used: &mut HashSet<String>) -> String {
    let mut base: String = source
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect();
    if base.is_empty() {
        base = format!("cloudreve-user-{source_id}");
    }
    if used.insert(base.clone()) {
        return base;
    }
    let suffix = format!("-{source_id}");
    let keep = 64usize.saturating_sub(suffix.chars().count());
    let mut candidate: String = base.chars().take(keep).collect();
    candidate.push_str(&suffix);
    let mut discriminator = 2;
    while !used.insert(candidate.clone()) {
        let suffix = format!("-{source_id}-{discriminator}");
        let keep = 64usize.saturating_sub(suffix.chars().count());
        candidate = base.chars().take(keep).collect();
        candidate.push_str(&suffix);
        discriminator += 1;
    }
    candidate
}

fn file_classification(name: &str) -> (String, Option<String>, String, String) {
    let mime = mime_guess::from_path(name)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let lowercase = name.to_ascii_lowercase();
    let extension = lowercase
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_string())
        .unwrap_or_default();
    let compound_extension = ["tar.gz", "tar.bz2", "tar.xz", "user.js"]
        .into_iter()
        .find(|candidate| lowercase.ends_with(candidate))
        .map(str::to_string);
    let category = if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else if mime.starts_with("audio/") {
        "audio"
    } else if ["zip", "rar", "7z", "gz", "bz2", "xz", "tar"].contains(&extension.as_str()) {
        "archive"
    } else if ["xls", "xlsx", "csv", "ods"].contains(&extension.as_str()) {
        "spreadsheet"
    } else if ["ppt", "pptx", "odp"].contains(&extension.as_str()) {
        "presentation"
    } else if [
        "rs", "go", "js", "ts", "py", "java", "c", "cpp", "html", "css", "json", "yaml", "yml",
        "toml",
    ]
    .contains(&extension.as_str())
    {
        "code"
    } else if mime.starts_with("text/")
        || ["pdf", "doc", "docx", "odt", "md"].contains(&extension.as_str())
    {
        "document"
    } else {
        "other"
    };
    (mime, compound_extension, extension, category.to_string())
}

mod phases;
use phases::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, DbBackend, Schema};

    #[test]
    fn classifies_common_file_types() {
        assert_eq!(file_classification("photo.JPG").3, "image");
        assert_eq!(
            file_classification("backup.tar.gz").1.as_deref(),
            Some("tar.gz")
        );
        assert_eq!(file_classification("main.rs").3, "code");
    }

    #[test]
    fn maps_supported_storage_drivers_conservatively() {
        assert_eq!(map_driver_type("local"), Some("local"));
        assert_eq!(map_driver_type("oss"), Some("s3"));
        assert_eq!(map_driver_type("cos"), Some("tencent_cos"));
        assert_eq!(map_driver_type("onedrive"), None);
        assert_eq!(map_driver_type("qiniu"), None);
    }

    #[tokio::test]
    async fn migrates_minimal_cloudreve_database() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        source.close().await?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "C:/cloudreve".to_string(),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
        })
        .await?;

        assert_eq!(report.migrated_users, 1);
        assert_eq!(report.migrated_folders, 1);
        assert_eq!(report.migrated_files, 1);
        assert_eq!(report.migrated_blobs, 1);
        assert_eq!(report.migrated_shares, 1);
        assert_eq!(report.migrated_properties, 1);

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::users::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::folders::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::files::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::file_blobs::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::shares::Entity::find().count(&target).await?, 1);
        assert_eq!(
            ad::entity_properties::Entity::find().count(&target).await?,
            1
        );
        let blob = ad::file_blobs::Entity::find().one(&target).await?.unwrap();
        assert_eq!(blob.storage_path, "uploads/object.bin");
        let user = ad::users::Entity::find().one(&target).await?.unwrap();
        assert!(user.must_change_password);
        assert_eq!(user.role, "admin");
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    fn sqlite_url(path: &std::path::Path) -> String {
        format!(
            "sqlite://{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        )
    }

    async fn create_table<E: EntityTrait>(db: &DatabaseConnection, entity: E) -> Result<()> {
        let schema = Schema::new(DbBackend::Sqlite);
        db.execute(&schema.create_table_from_entity(entity)).await?;
        Ok(())
    }

    async fn create_source_schema(db: &DatabaseConnection) -> Result<()> {
        create_table(db, cr::nodes::Entity).await?;
        create_table(db, cr::groups::Entity).await?;
        create_table(db, cr::users::Entity).await?;
        create_table(db, cr::storage_policies::Entity).await?;
        create_table(db, cr::files::Entity).await?;
        create_table(db, cr::entities::Entity).await?;
        create_table(db, cr::file_entities::Entity).await?;
        create_table(db, cr::shares::Entity).await?;
        create_table(db, cr::metadata::Entity).await?;
        Ok(())
    }

    async fn create_target_schema(db: &DatabaseConnection) -> Result<()> {
        create_table(db, ad::managed_followers::Entity).await?;
        create_table(db, ad::storage_policy_groups::Entity).await?;
        create_table(db, ad::storage_policies::Entity).await?;
        create_table(db, ad::storage_policy_group_items::Entity).await?;
        create_table(db, ad::users::Entity).await?;
        create_table(db, ad::user_profiles::Entity).await?;
        create_table(db, ad::folders::Entity).await?;
        create_table(db, ad::file_blobs::Entity).await?;
        create_table(db, ad::files::Entity).await?;
        create_table(db, ad::file_versions::Entity).await?;
        create_table(db, ad::entity_properties::Entity).await?;
        create_table(db, ad::shares::Entity).await?;
        Ok(())
    }

    async fn seed_source(db: &DatabaseConnection) -> Result<()> {
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
        Ok(())
    }
}
