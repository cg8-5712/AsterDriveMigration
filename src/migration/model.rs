use super::*;

pub(super) fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("create password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| color_eyre::eyre::eyre!("hash temporary AD password: {error}"))
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct MigrationContext {
    pub(super) policies: HashMap<i64, i64>,
    pub(super) policy_groups: HashMap<i64, i64>,
    pub(super) users: HashMap<i64, i64>,
    pub(super) usernames: HashMap<i64, String>,
    pub(super) folders: HashMap<i64, i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(super) blobs: HashMap<i64, i64>,
    pub(super) files: HashMap<i64, i64>,
    pub(super) shares: HashMap<i64, i64>,
    pub(super) tasks: HashMap<i64, i64>,
}

pub(super) fn sorted_id_mappings(values: &HashMap<i64, i64>) -> Vec<IdMapping> {
    let mut mappings = values
        .iter()
        .map(|(source_id, target_id)| IdMapping {
            source_id: *source_id,
            target_id: *target_id,
        })
        .collect::<Vec<_>>();
    mappings.sort_by_key(|mapping| mapping.source_id);
    mappings
}

pub(super) struct SourceData {
    pub(super) groups: Vec<cloudreve_schema::groups::Model>,
    pub(super) users: Vec<cloudreve_schema::users::Model>,
    pub(super) policies: Vec<cloudreve_schema::storage_policies::Model>,
    pub(super) folders: Vec<cloudreve_schema::files::Model>,
    pub(super) source_file_records: u64,
    pub(super) source_files: u64,
    pub(super) symbolic_files: u64,
    pub(super) source_entities: u64,
    pub(super) source_blobs: u64,
    pub(super) source_file_entities: u64,
    pub(super) include_deleted: bool,
    pub(super) shares: Vec<cloudreve_schema::shares::Model>,
    pub(super) metadata: Vec<cloudreve_schema::metadata::Model>,
    pub(super) direct_links: Vec<cloudreve_schema::direct_links::Model>,
    pub(super) tasks: Vec<cloudreve_schema::tasks::Model>,
}

impl SourceData {
    pub(super) async fn load(db: &DatabaseConnection, include_deleted: bool) -> Result<Self> {
        let groups = cloudreve_schema::groups::Entity::find().all(db).await?;
        let users = cloudreve_schema::users::Entity::find().all(db).await?;
        let policies = cloudreve_schema::storage_policies::Entity::find()
            .all(db)
            .await?;
        let folders = cloudreve_schema::files::Entity::find()
            .filter(cloudreve_schema::files::Column::Type.eq(1))
            .all(db)
            .await?;
        let source_file_records = cloudreve_schema::files::Entity::find().count(db).await?;
        let source_files = cloudreve_schema::files::Entity::find()
            .filter(cloudreve_schema::files::Column::Type.eq(0))
            .count(db)
            .await?;
        let symbolic_files = cloudreve_schema::files::Entity::find()
            .filter(cloudreve_schema::files::Column::Type.eq(0))
            .filter(cloudreve_schema::files::Column::IsSymbolic.eq(true))
            .count(db)
            .await?;
        let entity_query = if include_deleted {
            cloudreve_schema::entities::Entity::find()
        } else {
            cloudreve_schema::entities::Entity::find()
                .filter(cloudreve_schema::entities::Column::DeletedAt.is_null())
        };
        let source_entities = entity_query.count(db).await?;
        let blob_query = if include_deleted {
            cloudreve_schema::entities::Entity::find()
        } else {
            cloudreve_schema::entities::Entity::find()
                .filter(cloudreve_schema::entities::Column::DeletedAt.is_null())
        };
        let source_blobs = blob_query
            .filter(cloudreve_schema::entities::Column::Type.eq(0))
            .count(db)
            .await?;
        let source_file_entities = cloudreve_schema::file_entities::Entity::find()
            .count(db)
            .await?;
        let shares = cloudreve_schema::shares::Entity::find().all(db).await?;
        let metadata = cloudreve_schema::metadata::Entity::find().all(db).await?;
        let direct_links = cloudreve_schema::direct_links::Entity::find()
            .all(db)
            .await?;
        let tasks = cloudreve_schema::tasks::Entity::find().all(db).await?;

        Ok(Self {
            groups: filter_deleted(groups, include_deleted, |model| model.deleted_at.is_some()),
            users: filter_deleted(users, include_deleted, |model| model.deleted_at.is_some()),
            policies: filter_deleted(policies, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            folders,
            source_file_records,
            source_files,
            symbolic_files,
            source_entities,
            source_blobs,
            source_file_entities,
            include_deleted,
            shares: filter_deleted(shares, include_deleted, |model| model.deleted_at.is_some()),
            metadata: filter_deleted(metadata, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            direct_links: filter_deleted(direct_links, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            tasks: filter_deleted(tasks, include_deleted, |model| model.deleted_at.is_some()),
        })
    }

    pub(super) fn report(&self) -> MigrationReport {
        MigrationReport {
            source_users: self.users.len() as u64,
            source_groups: self.groups.len() as u64,
            source_policies: self.policies.len() as u64,
            source_folders: self.folders.len() as u64,
            source_files: self.source_files,
            source_entities: self.source_entities,
            source_shares: self.shares.len() as u64,
            source_direct_links: self.direct_links.len() as u64,
            source_tag_assignments: self
                .metadata
                .iter()
                .filter(|metadata| tag_name(&metadata.name).is_some())
                .count() as u64,
            source_tasks: self.tasks.len() as u64,
            ..Default::default()
        }
    }

    pub(super) fn unsupported_policy_types(&self) -> Vec<String> {
        let mut values: Vec<String> = self
            .policies
            .iter()
            .filter_map(unsupported_policy_reason)
            .collect();
        values.sort();
        values.dedup();
        values
    }

    pub(super) fn compatibility_warnings(&self) -> Vec<String> {
        let mut warnings = vec![
            "Cloudreve user passwords use SHA/legacy MD5 formats and are replaced by the supplied temporary Argon2 password; every migrated user is marked must_change_password".to_string(),
            "OAuth grants, login sessions and Cloudreve filesystem events are intentionally not migrated".to_string(),
            "Cloudreve Passkeys, WebDAV credentials and two-factor secrets are not portable to AD and must be enrolled again".to_string(),
            "file objects are reused in their existing local/object-storage locations; the migration does not duplicate object bytes".to_string(),
            "Cloudreve tasks are archived as terminal AD system_runtime records; queued, processing and suspending tasks are canceled instead of resumed".to_string(),
        ];
        let symbolic = self.symbolic_files;
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
        if !self.direct_links.is_empty() {
            warnings.push("Cloudreve direct links require --direct-link-secret to regenerate AD v2 URLs; old /f/... URLs, per-link counters, speed limits and revocation semantics cannot be preserved".to_string());
        }
        warnings
    }
}

pub(super) fn filter_deleted<T, F>(items: Vec<T>, include_deleted: bool, deleted: F) -> Vec<T>
where
    F: Fn(&T) -> bool,
{
    if include_deleted {
        items
    } else {
        items.into_iter().filter(|item| !deleted(item)).collect()
    }
}

pub(super) fn map_driver_type(source: &str) -> Option<DriverType> {
    match source {
        "local" => Some(DriverType::Local),
        "s3" | "oss" | "ks3" | "obs" => Some(DriverType::S3),
        "cos" => Some(DriverType::TencentCos),
        _ => None,
    }
}

pub(super) fn unsupported_policy_reason(
    policy: &cloudreve_schema::storage_policies::Model,
) -> Option<String> {
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

pub(super) fn source_settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
}

pub(super) fn share_token(share_id: i64) -> String {
    let digest = Sha256::digest(format!("cloudreve-share-{share_id}").as_bytes());
    format!("cr-{share_id}-{}", &format!("{digest:x}")[..16])
}

pub(super) fn tag_name(metadata_name: &str) -> Option<&str> {
    metadata_name
        .strip_prefix("tag:")
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

pub(super) fn normalize_tag_name(name: &str) -> String {
    name.trim().to_lowercase()
}

pub(super) fn target_tag_name(name: &str) -> String {
    name.trim().chars().take(64).collect()
}

pub(super) fn target_tag_color(color: &str) -> String {
    let color = color.trim().to_ascii_lowercase();
    if color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return color;
    }
    if color.len() == 4
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let mut expanded = String::with_capacity(7);
        expanded.push('#');
        for character in color[1..].chars() {
            expanded.push(character);
            expanded.push(character);
        }
        return expanded;
    }
    "#3b82f6".to_string()
}

pub(super) fn encode_base62(mut value: u64) -> String {
    const BASE62: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if value == 0 {
        return "a".to_string();
    }
    let mut encoded = Vec::new();
    while value > 0 {
        encoded.push(char::from(BASE62[(value % 62) as usize]));
        value /= 62;
    }
    encoded.iter().rev().collect()
}

pub(super) fn direct_link_url(
    file_id: i64,
    owner_user_id: i64,
    file_name: &str,
    secret: &str,
) -> Result<String> {
    let file_id = u64::try_from(file_id).wrap_err("AD direct link file ID must be non-negative")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("initialize direct link HMAC: {error}"))?;
    mac.update(b"direct_link:v2:");
    mac.update(format!("user:{owner_user_id}").as_bytes());
    mac.update(b":");
    mac.update(file_id.to_string().as_bytes());
    let signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!(
        "/d/v2.{}.{}/{}",
        encode_base62(file_id),
        signature,
        urlencoding::encode(file_name)
    ))
}

pub(super) fn archived_task_status(source_status: &str) -> &'static str {
    match source_status {
        "completed" => "succeeded",
        "error" => "failed",
        "canceled" | "queued" | "processing" | "suspending" => "canceled",
        _ => "canceled",
    }
}

pub(super) fn source_task_was_active(source_status: &str) -> bool {
    matches!(source_status, "queued" | "processing" | "suspending")
}

pub(super) fn unique_username(source: &str, source_id: i64, used: &mut HashSet<String>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aster_drive_model::types::DriverType;

    #[test]
    fn maps_supported_storage_drivers_conservatively() {
        assert_eq!(map_driver_type("local"), Some(DriverType::Local));
        assert_eq!(map_driver_type("oss"), Some(DriverType::S3));
        assert_eq!(map_driver_type("cos"), Some(DriverType::TencentCos));
        assert_eq!(map_driver_type("onedrive"), None);
        assert_eq!(map_driver_type("qiniu"), None);
    }

    #[test]
    fn parses_and_normalizes_cloudreve_tags_for_aster_drive() {
        assert_eq!(tag_name("tag:Important"), Some("Important"));
        assert_eq!(tag_name("tag:  Project A  "), Some("Project A"));
        assert_eq!(tag_name("author"), None);
        assert_eq!(normalize_tag_name(" Important "), "important");
        assert_eq!(target_tag_color("#AbC"), "#aabbcc");
        assert_eq!(target_tag_color("#3B82F6"), "#3b82f6");
        assert_eq!(target_tag_color(""), "#3b82f6");
        assert_eq!(target_tag_name(&"x".repeat(80)).chars().count(), 64);
    }

    #[test]
    fn builds_asterdrive_v2_direct_link_urls() -> Result<()> {
        let url = direct_link_url(1, 7, "hello world.txt", "test-direct-link-secret")?;
        assert!(url.starts_with("/d/v2.b."));
        assert!(url.ends_with("/hello%20world.txt"));
        assert_eq!(
            url,
            direct_link_url(1, 7, "hello world.txt", "test-direct-link-secret")?
        );
        assert_ne!(
            url,
            direct_link_url(1, 8, "hello world.txt", "test-direct-link-secret")?
        );
        Ok(())
    }

    #[test]
    fn maps_cloudreve_tasks_to_non_executable_terminal_statuses() {
        assert_eq!(archived_task_status("completed"), "succeeded");
        assert_eq!(archived_task_status("error"), "failed");
        assert_eq!(archived_task_status("canceled"), "canceled");
        for status in ["queued", "processing", "suspending"] {
            assert!(source_task_was_active(status));
            assert_eq!(archived_task_status(status), "canceled");
        }
        assert_eq!(archived_task_status("unknown"), "canceled");
    }
}
