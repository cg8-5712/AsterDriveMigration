use super::*;

pub(super) fn local_policy_root(options: &MigrationOptions, source_policy_id: i64) -> &str {
    options
        .local_policy_roots
        .get(&source_policy_id)
        .map(String::as_str)
        .unwrap_or(&options.local_base_path)
}

pub(super) fn target_local_policy_root(
    options: &MigrationOptions,
    source_policy_id: i64,
) -> Result<&str> {
    if options.storage_mode == StorageMode::ReuseSourceStorage {
        return Ok(local_policy_root(options, source_policy_id));
    }
    options
        .target_local_policy_roots
        .get(&source_policy_id)
        .map(String::as_str)
        .or(options.target_local_base_path.as_deref())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "--storage-mode copy-local requires --target-local-base-path or --target-local-policy-root for Cloudreve policy {source_policy_id}"
            )
        })
}

pub(super) fn local_storage_path(root: &str, storage_path: &str) -> std::path::PathBuf {
    let storage_path = std::path::Path::new(storage_path);
    if storage_path.is_absolute() {
        storage_path.to_path_buf()
    } else {
        std::path::Path::new(root).join(storage_path)
    }
}

pub(super) fn validate_local_policy_roots(
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    for source_policy_id in options
        .local_policy_roots
        .keys()
        .chain(options.target_local_policy_roots.keys())
    {
        let Some(policy) = policies.get(source_policy_id) else {
            bail!(
                "local policy root references Cloudreve policy {source_policy_id}, which was not found"
            );
        };
        if policy.r#type != "local" {
            bail!(
                "local policy root references Cloudreve policy {source_policy_id}, which is not a local policy"
            );
        }
    }
    Ok(())
}

pub(super) fn verify_target_local_storage_roots(
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    for policy in source.policies.iter().filter(|policy| {
        policy.r#type == "local"
            && map_driver_type(&policy.r#type).is_some()
            && !source_settings(&policy.settings)
                .get("encryption")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }) {
        let source_root = local_policy_root(options, policy.id);
        let target_root = target_local_policy_root(options, policy.id)?;
        let target_metadata = std::fs::metadata(target_root).wrap_err_with(|| {
            format!(
                "read target local storage root for Cloudreve policy {}: {target_root}",
                policy.id
            )
        })?;
        if !target_metadata.is_dir() {
            bail!(
                "target local storage root for Cloudreve policy {} is not a directory: {target_root}",
                policy.id
            );
        }
        if same_local_directory(source_root, target_root)? {
            bail!(
                "--storage-mode copy-local source and target roots are the same for Cloudreve policy {}: {source_root}",
                policy.id
            );
        }
    }
    Ok(())
}

pub(super) fn same_local_directory(left: &str, right: &str) -> Result<bool> {
    let left = std::fs::canonicalize(left)
        .wrap_err_with(|| format!("canonicalize local storage root: {left}"))?;
    let right = std::fs::canonicalize(right)
        .wrap_err_with(|| format!("canonicalize target local storage root: {right}"))?;
    Ok(left == right)
}

#[derive(Debug, Clone)]
pub(super) struct CopiedLocalObject {
    pub(super) sha256: String,
    pub(super) storage_path: String,
}

#[derive(Debug, Default)]
pub(super) struct CopiedLocalBatch {
    pub(super) objects: HashMap<i64, CopiedLocalObject>,
    pub(super) created_paths: Vec<PathBuf>,
}

impl CopiedLocalBatch {
    pub(super) fn compensate(&self) -> Result<()> {
        for path in self.created_paths.iter().rev() {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "remove copied local object after database rollback: {}",
                            path.display()
                        )
                    });
                }
            }
        }
        Ok(())
    }
}

pub(super) fn copy_local_blob_batch(
    entities: &[cloudreve_schema::entities::Model],
    source: &SourceData,
    options: &MigrationOptions,
    context: &MigrationContext,
    run_id: &str,
) -> Result<CopiedLocalBatch> {
    if options.storage_mode != StorageMode::CopyLocal {
        return Ok(CopiedLocalBatch::default());
    }

    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    let mut batch = CopiedLocalBatch::default();
    for entity in entities {
        if !context
            .policies
            .contains_key(&entity.storage_policy_entities)
        {
            continue;
        }
        let Some(policy) = policies.get(&entity.storage_policy_entities) else {
            continue;
        };
        if policy.r#type != "local" {
            continue;
        }

        let source_path = local_storage_path(local_policy_root(options, policy.id), &entity.source);
        let target_path = target_local_storage_path(
            target_local_policy_root(options, policy.id)?,
            &entity.source,
            entity.id,
        )?;
        match copy_local_object(&source_path, &target_path, entity.size, run_id, entity.id) {
            Ok((sha256, created)) => {
                if created {
                    batch.created_paths.push(target_path);
                }
                batch.objects.insert(
                    entity.id,
                    CopiedLocalObject {
                        sha256,
                        storage_path: entity.source.clone(),
                    },
                );
            }
            Err(error) => {
                batch.compensate()?;
                return Err(error);
            }
        }
    }
    Ok(batch)
}

pub(super) fn target_local_storage_path(
    root: &str,
    storage_path: &str,
    entity_id: i64,
) -> Result<PathBuf> {
    let relative = Path::new(storage_path);
    if relative.is_absolute() {
        bail!(
            "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path is absolute: {storage_path}"
        );
    }
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                bail!(
                    "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path escapes the configured root: {storage_path}"
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!(
            "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path is empty"
        );
    }
    Ok(Path::new(root).join(normalized))
}

pub(super) fn copy_local_object(
    source_path: &Path,
    target_path: &Path,
    expected_size: i64,
    run_id: &str,
    entity_id: i64,
) -> Result<(String, bool)> {
    const BUFFER_SIZE: usize = 1024 * 1024;

    let expected_size = u64::try_from(expected_size).map_err(|_| {
        color_eyre::eyre::eyre!(
            "Cloudreve local entity {entity_id} has negative size {expected_size}"
        )
    })?;
    let source_metadata = std::fs::metadata(source_path).wrap_err_with(|| {
        format!(
            "read Cloudreve local entity {entity_id} before copy: {}",
            source_path.display()
        )
    })?;
    if !source_metadata.is_file() || source_metadata.len() != expected_size {
        bail!(
            "Cloudreve local entity {entity_id} changed or is not a regular file before copy: {}",
            source_path.display()
        );
    }
    if target_path.exists() {
        let source_hash = sha256_file(source_path)?;
        let target_metadata = std::fs::metadata(target_path).wrap_err_with(|| {
            format!(
                "read existing copied local entity {entity_id}: {}",
                target_path.display()
            )
        })?;
        if target_metadata.is_file()
            && target_metadata.len() == expected_size
            && sha256_file(target_path)? == source_hash
        {
            return Ok((source_hash, false));
        }
        bail!(
            "target local object already exists but differs from Cloudreve entity {entity_id}: {}",
            target_path.display()
        );
    }

    let parent = target_path.parent().ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "target local object for Cloudreve entity {entity_id} has no parent directory: {}",
            target_path.display()
        )
    })?;
    std::fs::create_dir_all(parent).wrap_err_with(|| {
        format!(
            "create destination directory for Cloudreve entity {entity_id}: {}",
            parent.display()
        )
    })?;
    let temporary_path = temporary_copy_path(parent, run_id, entity_id);
    let temporary_size = match std::fs::metadata(&temporary_path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => bail!(
            "copy checkpoint for Cloudreve entity {entity_id} is not a regular file: {}",
            temporary_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("read copy checkpoint: {}", temporary_path.display()));
        }
    };
    if temporary_size > expected_size {
        bail!(
            "copy checkpoint for Cloudreve entity {entity_id} is larger than the source object: {}",
            temporary_path.display()
        );
    }

    let mut source = std::fs::File::open(source_path).wrap_err_with(|| {
        format!(
            "open Cloudreve local entity {entity_id}: {}",
            source_path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut source_buffer = vec![0_u8; BUFFER_SIZE];
    if temporary_size > 0 {
        let mut checkpoint = std::fs::File::open(&temporary_path).wrap_err_with(|| {
            format!(
                "open copy checkpoint for Cloudreve entity {entity_id}: {}",
                temporary_path.display()
            )
        })?;
        let mut checkpoint_buffer = vec![0_u8; BUFFER_SIZE];
        let mut remaining = temporary_size;
        while remaining > 0 {
            let read_len =
                usize::try_from(remaining.min(BUFFER_SIZE as u64)).expect("bounded buffer size");
            source
                .read_exact(&mut source_buffer[..read_len])
                .wrap_err_with(|| format!("read source prefix for Cloudreve entity {entity_id}"))?;
            checkpoint
                .read_exact(&mut checkpoint_buffer[..read_len])
                .wrap_err_with(|| {
                    format!("read copy checkpoint for Cloudreve entity {entity_id}")
                })?;
            if source_buffer[..read_len] != checkpoint_buffer[..read_len] {
                bail!(
                    "copy checkpoint does not match Cloudreve entity {entity_id}; remove only this generated checkpoint and rerun: {}",
                    temporary_path.display()
                );
            }
            hasher.update(&source_buffer[..read_len]);
            remaining -= read_len as u64;
        }
    }

    let mut destination = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temporary_path)
        .wrap_err_with(|| {
            format!(
                "open copy checkpoint for Cloudreve entity {entity_id}: {}",
                temporary_path.display()
            )
        })?;
    let mut copied_size = temporary_size;
    loop {
        let read = source.read(&mut source_buffer).wrap_err_with(|| {
            format!(
                "read Cloudreve local entity {entity_id}: {}",
                source_path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        destination
            .write_all(&source_buffer[..read])
            .wrap_err_with(|| {
                format!(
                    "write copied local entity {entity_id}: {}",
                    temporary_path.display()
                )
            })?;
        hasher.update(&source_buffer[..read]);
        copied_size += read as u64;
    }
    if copied_size != expected_size {
        bail!(
            "Cloudreve local entity {entity_id} changed while copying: expected {expected_size} bytes, copied {copied_size} bytes"
        );
    }
    destination.sync_all().wrap_err_with(|| {
        format!(
            "sync copied local entity {entity_id}: {}",
            temporary_path.display()
        )
    })?;
    std::fs::rename(&temporary_path, target_path).wrap_err_with(|| {
        format!(
            "atomically finalize copied local entity {entity_id}: {} -> {}",
            temporary_path.display(),
            target_path.display()
        )
    })?;
    Ok((format!("{:x}", hasher.finalize()), true))
}

pub(super) fn temporary_copy_path(parent: &Path, run_id: &str, entity_id: i64) -> PathBuf {
    parent.join(format!(
        ".aster-migration-{}-{entity_id}.part",
        hash_fingerprint(run_id)
    ))
}

pub(super) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .wrap_err_with(|| format!("open file for SHA-256: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .wrap_err_with(|| format!("read file for SHA-256: {}", path.display()))?;
        if read == 0 {
            return Ok(format!("{:x}", hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumes_local_copy_from_matching_temporary_file() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let root = std::env::temp_dir().join(format!("asterdrive-copy-resume-{suffix}"));
        let source_path = root.join("source.bin");
        let target_path = root.join("target/object.bin");
        let content = b"a local object that resumes from a generated checkpoint";
        std::fs::create_dir_all(&root)?;
        std::fs::write(&source_path, content)?;
        std::fs::create_dir_all(target_path.parent().expect("target parent"))?;
        let temporary_path = temporary_copy_path(
            target_path.parent().expect("target parent"),
            "local-copy-resume",
            42,
        );
        std::fs::write(&temporary_path, &content[..17])?;

        let (sha256, created) = copy_local_object(
            &source_path,
            &target_path,
            content.len() as i64,
            "local-copy-resume",
            42,
        )?;

        assert!(created);
        assert_eq!(sha256, sha256_file(&source_path)?);
        assert_eq!(std::fs::read(&target_path)?, content);
        assert!(!temporary_path.exists());

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}

pub(super) fn verify_local_storage_roots(
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    for policy in source.policies.iter().filter(|policy| {
        policy.r#type == "local"
            && map_driver_type(&policy.r#type).is_some()
            && !source_settings(&policy.settings)
                .get("encryption")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }) {
        let root = local_policy_root(options, policy.id);
        let metadata = std::fs::metadata(root).wrap_err_with(|| {
            format!(
                "read local storage root for Cloudreve policy {}: {root}",
                policy.id
            )
        })?;
        if !metadata.is_dir() {
            bail!(
                "local storage root for Cloudreve policy {} is not a directory: {root}",
                policy.id
            );
        }
    }
    Ok(())
}

pub(super) async fn verify_all_local_source_objects(
    source_db: &DatabaseConnection,
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    const VERIFY_BATCH_SIZE: u64 = 500;

    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    let mut cursor_value = 0;
    loop {
        let mut query = cloudreve_schema::entities::Entity::find()
            .filter(cloudreve_schema::entities::Column::Type.eq(0))
            .filter(cloudreve_schema::entities::Column::Id.gt(cursor_value))
            .order_by_asc(cloudreve_schema::entities::Column::Id)
            .limit(VERIFY_BATCH_SIZE);
        if !source.include_deleted {
            query = query.filter(cloudreve_schema::entities::Column::DeletedAt.is_null());
        }
        let entities = query.all(source_db).await?;
        let Some(last_entity) = entities.last() else {
            return Ok(());
        };
        for entity in &entities {
            let Some(policy) = policies.get(&entity.storage_policy_entities) else {
                continue;
            };
            if policy.r#type == "local"
                && map_driver_type(&policy.r#type).is_some()
                && !source_settings(&policy.settings)
                    .get("encryption")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                verify_local_entity(entity, policy, options)?;
            }
        }
        cursor_value = last_entity.id;
    }
}

pub(super) fn verify_local_blob_batch(
    entities: &[cloudreve_schema::entities::Model],
    source: &SourceData,
    options: &MigrationOptions,
    context: &MigrationContext,
) -> Result<()> {
    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    for entity in entities {
        if !context
            .policies
            .contains_key(&entity.storage_policy_entities)
        {
            continue;
        }
        let Some(policy) = policies.get(&entity.storage_policy_entities) else {
            continue;
        };
        if policy.r#type != "local" {
            continue;
        }
        verify_local_entity(entity, policy, options)?;
    }
    Ok(())
}

pub(super) async fn verify_all_remote_source_objects(
    source_db: &DatabaseConnection,
    source: &SourceData,
    _options: &MigrationOptions,
) -> Result<()> {
    const VERIFY_BATCH_SIZE: u64 = 500;

    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    let mut cursor_value = 0;
    loop {
        let mut query = cloudreve_schema::entities::Entity::find()
            .filter(cloudreve_schema::entities::Column::Type.eq(0))
            .filter(cloudreve_schema::entities::Column::Id.gt(cursor_value))
            .order_by_asc(cloudreve_schema::entities::Column::Id)
            .limit(VERIFY_BATCH_SIZE);
        if !source.include_deleted {
            query = query.filter(cloudreve_schema::entities::Column::DeletedAt.is_null());
        }
        let entities = query.all(source_db).await?;
        let Some(last_entity) = entities.last() else {
            return Ok(());
        };
        for entity in &entities {
            let Some(policy) = policies.get(&entity.storage_policy_entities) else {
                continue;
            };
            if policy.r#type != "local" && map_driver_type(&policy.r#type).is_some() {
                remote::verify_object(policy, &entity.source, entity.size, entity.id).await?;
            }
        }
        cursor_value = last_entity.id;
    }
}

pub(super) async fn verify_remote_blob_batch(
    entities: &[cloudreve_schema::entities::Model],
    source: &SourceData,
    _options: &MigrationOptions,
    context: &MigrationContext,
) -> Result<()> {
    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    for entity in entities {
        if !context
            .policies
            .contains_key(&entity.storage_policy_entities)
        {
            continue;
        }
        let Some(policy) = policies.get(&entity.storage_policy_entities) else {
            continue;
        };
        if policy.r#type != "local" && map_driver_type(&policy.r#type).is_some() {
            remote::verify_object(policy, &entity.source, entity.size, entity.id).await?;
        }
    }
    Ok(())
}

pub(super) fn verify_local_entity(
    entity: &cloudreve_schema::entities::Model,
    policy: &cloudreve_schema::storage_policies::Model,
    options: &MigrationOptions,
) -> Result<()> {
    let root = local_policy_root(options, policy.id);
    let path = local_storage_path(root, &entity.source);
    let metadata = std::fs::metadata(&path).wrap_err_with(|| {
        format!(
            "read Cloudreve local entity {} at {}",
            entity.id,
            path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "Cloudreve local entity {} is not a regular file: {}",
            entity.id,
            path.display()
        );
    }
    std::fs::File::open(&path).wrap_err_with(|| {
        format!(
            "open Cloudreve local entity {} at {}",
            entity.id,
            path.display()
        )
    })?;
    let expected_size = u64::try_from(entity.size).map_err(|_| {
        color_eyre::eyre::eyre!(
            "Cloudreve local entity {} has negative size {}",
            entity.id,
            entity.size
        )
    })?;
    if metadata.len() != expected_size {
        bail!(
            "Cloudreve local entity {} size mismatch at {}: database={}, filesystem={}",
            entity.id,
            path.display(),
            expected_size,
            metadata.len()
        );
    }
    Ok(())
}
