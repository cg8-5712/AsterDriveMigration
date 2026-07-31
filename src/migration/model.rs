use super::*;

pub(super) fn hash_argon2_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("create password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| color_eyre::eyre::eyre!("hash password for AD: {error}"))
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
    pub(super) source_tasks: u64,
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
        let task_query = if include_deleted {
            cloudreve_schema::tasks::Entity::find()
        } else {
            cloudreve_schema::tasks::Entity::find()
                .filter(cloudreve_schema::tasks::Column::DeletedAt.is_null())
        };
        let source_tasks = task_query.count(db).await?;

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
            source_tasks,
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
                .filter(|metadata| {
                    metadata
                        .name
                        .strip_prefix("tag:")
                        .is_some_and(|name| !name.trim().is_empty())
                })
                .count() as u64,
            source_tasks: self.source_tasks,
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
        if self.source_tasks > 0 {
            warnings.push(format!(
                "{} Cloudreve runtime tasks were intentionally not migrated",
                self.source_tasks
            ));
        }
        let duplicate_active_share_targets =
            duplicate_active_share_targets(&self.shares, chrono::Utc::now().fixed_offset());
        if duplicate_active_share_targets > 0 {
            warnings.push(format!(
                "{duplicate_active_share_targets} owner/target pairs have multiple active Cloudreve shares; all links are preserved, but AD's share-management UI only creates one active share per resource going forward"
            ));
        }
        warnings
    }
}

pub(super) fn duplicate_active_share_targets(
    shares: &[cloudreve_schema::shares::Model],
    now: chrono::DateTime<chrono::FixedOffset>,
) -> usize {
    shares
        .iter()
        .filter(|share| {
            share.deleted_at.is_none()
                && share.expires.is_none_or(|expires| expires >= now)
                && share.remain_downloads.is_none_or(|remaining| remaining > 0)
        })
        .filter_map(|share| Some((share.user_shares?, share.file_shares?)))
        .fold(HashMap::new(), |mut counts, target| {
            *counts.entry(target).or_insert(0_usize) += 1;
            counts
        })
        .values()
        .filter(|count| **count > 1)
        .count()
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

    fn share(
        id: i64,
        owner_id: i64,
        target_id: i64,
        remaining: Option<i64>,
        expires: Option<chrono::DateTime<chrono::FixedOffset>>,
    ) -> cloudreve_schema::shares::Model {
        let now = chrono::Utc::now().fixed_offset();
        cloudreve_schema::shares::Model {
            id,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            password: None,
            views: 0,
            downloads: 0,
            expires,
            remain_downloads: remaining,
            props: None,
            file_shares: Some(target_id),
            user_shares: Some(owner_id),
        }
    }

    #[test]
    fn maps_supported_storage_drivers_conservatively() {
        assert_eq!(map_driver_type("local"), Some(DriverType::Local));
        assert_eq!(map_driver_type("oss"), Some(DriverType::S3));
        assert_eq!(map_driver_type("cos"), Some(DriverType::TencentCos));
        assert_eq!(map_driver_type("onedrive"), None);
        assert_eq!(map_driver_type("qiniu"), None);
    }

    #[test]
    fn counts_only_duplicate_active_share_targets() {
        let now = chrono::Utc::now().fixed_offset();
        let shares = vec![
            share(1, 7, 9, None, None),
            share(2, 7, 9, Some(3), None),
            share(3, 7, 10, None, None),
            share(4, 7, 10, Some(0), None),
            share(5, 7, 11, None, Some(now - chrono::TimeDelta::seconds(1))),
            share(6, 7, 11, None, None),
        ];
        assert_eq!(duplicate_active_share_targets(&shares, now), 1);
    }
}
