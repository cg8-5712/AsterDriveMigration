# AsterDriveMigration

Design documents:

- [Cloudreve and AsterDrive field mapping](docs/cloudreve-to-asterdrive-field-mapping.md)
- [Migration architecture](docs/migration-architecture.md)

Database migration tool for moving a Cloudreve v4 installation to AsterDrive (AD).

## Supported data

- Cloudreve groups to AD storage policy groups
- users and profiles, including quotas and disabled status
- local, S3, OSS, KS3, OBS and Tencent COS storage policies
- folders, files, physical entities/blobs and version history
- file/folder metadata, including Cloudreve v4 `tag:*` metadata as AD tags
- public shares and regenerated AD v2 direct-link mappings
- Cloudreve background tasks as non-executable terminal history

Cloudreve password hashes are not compatible with AD. The migration assigns the supplied temporary password to every migrated user and sets `must_change_password = true`. Passkeys, WebDAV credentials, two-factor secrets, OAuth grants, sessions and filesystem events are not migrated.

Cloudreve tasks are preserved only as terminal AD `system_runtime` history. Completed/error/canceled statuses are mapped to terminal AD statuses; queued/processing/suspending tasks are archived as canceled and are never resumed.

The tool reuses existing storage objects. For local storage, pass the directory from which Cloudreve entity paths should be resolved. Object-storage policies keep their existing bucket, endpoint, credentials and object keys.

## Prerequisites

1. Stop writes to Cloudreve and back up both databases.
2. Create an empty AD database and run the AD database migrations against it.
3. Do not start the AD application against the target database until this migration completes.

## Check compatibility

```powershell
cargo run -- check `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --report-path "C:/migration/cloudreve-preflight.json"
```

The URLs can also be provided through `CLOUDREVE_DATABASE_URL` and `ASTERDRIVE_DATABASE_URL`. SQLite, MySQL and PostgreSQL URLs supported by SeaORM can be used.

## Run migration

```powershell
$env:ASTER_MIGRATION_DEFAULT_PASSWORD = "replace-with-a-strong-temporary-password"
$env:ASTER_DIRECT_LINK_SECRET = "use-the-same-auth.direct_link_secret-as-ad"

cargo run -- migrate `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --local-base-path "C:/cloudreve" `
  --run-id "cloudreve-cutover-2026-07-13" `
  --report-path "C:/migration/cloudreve-to-ad.json"
```

`ASTER_DIRECT_LINK_SECRET` is optional only when there are no direct links to regenerate. When supplied, each active Cloudreve `direct_links` row is mapped to a newly signed AD `/d/v2...` URL and stored under the target file's `cloudreve.direct_links` properties. Existing Cloudreve `/f/...` URLs cannot remain valid because the URL path, ID and signing algorithms differ.

Use `--dry-run` to perform preflight checks without writing the target. The target core tables must be empty by default. `--allow-non-empty-target` disables that guard but may still fail on unique values or conflicting data.

Cloudreve Qiniu, Upyun, remote-node, OneDrive and encrypted storage policies cannot be reused safely by AD. The migration stops when they are present. `--skip-unsupported-policies` explicitly omits those policies and all dependent files.

## Reuse local storage

For compatible Cloudreve local storage, migration keeps each `entities.source` path unchanged and configures AD to read the same files through the target policy base path. This avoids copying object bytes and therefore does not require a second full data volume.

`--local-base-path` is the fallback root for every local policy. When policies use different volumes, pass one or more explicit source-policy mappings:

```powershell
cargo run -- migrate `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --default-password "change-this-password" `
  --local-base-path "D:/cloudreve-default" `
  --local-policy-root "1=D:/cloudreve-default" `
  --local-policy-root "2=E:/cloudreve-archive" `
  --verify-local-storage
```

`--verify-local-storage` checks each compatible local policy root and every migrated local blob's resolved path, regular-file status, open permission and byte length. With `--dry-run`, it scans all eligible local blobs before any target writes. It does not verify S3-compatible buckets or prove that a running AD instance can access a Docker mount; validate those separately before cutover.

## Limited resume

Migration stages run in this order: policies, policy groups, users, folders, blobs, files, metadata, shares, direct links and tasks. Most stages are committed as one transaction. Blobs use keyset pages ordered by Cloudreve `entities.id`, while files use keyset pages ordered by Cloudreve `files.id`; each page writes target records, object mappings, its cursor and report progress in one target transaction.

Use a stable run ID for an operational migration. If a stage fails, fix the external cause and rerun the same command with `--resume`:

```powershell
cargo run -- migrate `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --local-base-path "C:/cloudreve" `
  --run-id "cloudreve-cutover-2026-07-13" `
  --blob-batch-size 500 `
  --file-batch-size 500 `
  --resume `
  --report-path "C:/migration/cloudreve-to-ad.json"
```

Resume verifies the source URL/count fingerprint, target URL fingerprint and migration-plan fingerprint. Repeat the same password, direct-link secret and migration flags used by the original run. Completed stages are skipped and their source-to-target mappings are restored from the checkpoint. Blob batch size is operational only and may be adjusted when resuming.

`--blob-batch-size` and `--file-batch-size` default to 500 and accept 1-10000. A failed blob or file page rolls back only that page; resume continues after the last committed entity or file ID. Blob and normal-file source rows are no longer loaded into memory as complete collections, and their mappings are stored row-by-row in `aster_external_migration_object_map`.

Folders, metadata, shares, direct links and tasks are still stage-level only: a failure restarts that entire stage. A file page loads only its related entity/version rows into memory. Physical object bytes are still reused in place rather than copied or uploaded.

## JSON migration report

`--report-path` writes a pretty-printed JSON report for both `check` and `migrate`. A completed migration report contains:

- source and migrated counts for every supported object type
- skipped counts grouped by type, plus source ID and reason for every skipped object
- sorted source-to-target ID mappings for policies, groups, users, folders, blobs, files, shares and archived tasks
- every Cloudreve tag metadata assignment and its AD tag/entity IDs
- every regenerated direct-link URL and its Cloudreve/AD file IDs
- post-commit database count checks, imported-task terminal-state checks, tag-binding checks and direct-link property checks
- run ID, whether the execution resumed, and the list of completed stages

The CLI writes the JSON report before returning a validation error. A failed post-migration check therefore produces a usable report and exits with a non-zero status. Direct-link URLs are bearer-style public capabilities, so the report file must be stored with restricted access.

## Verification before push

Every migration feature must include focused tests plus end-to-end coverage where it writes database state. Before pushing, run and require all of these commands to pass:

```powershell
cargo fmt -- --check
cargo check --offline
cargo clippy --offline --all-targets --all-features -- -D warnings
cargo test --offline --all-targets --all-features
```
