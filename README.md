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
  --target-url "sqlite://C:/asterdrive/asterdrive.db"
```

The URLs can also be provided through `CLOUDREVE_DATABASE_URL` and `ASTERDRIVE_DATABASE_URL`. SQLite, MySQL and PostgreSQL URLs supported by SeaORM can be used.

## Run migration

```powershell
$env:ASTER_MIGRATION_DEFAULT_PASSWORD = "replace-with-a-strong-temporary-password"
$env:ASTER_DIRECT_LINK_SECRET = "use-the-same-auth.direct_link_secret-as-ad"

cargo run -- migrate `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --local-base-path "C:/cloudreve"
```

`ASTER_DIRECT_LINK_SECRET` is optional only when there are no direct links to regenerate. When supplied, each active Cloudreve `direct_links` row is mapped to a newly signed AD `/d/v2...` URL and stored under the target file's `cloudreve.direct_links` properties. Existing Cloudreve `/f/...` URLs cannot remain valid because the URL path, ID and signing algorithms differ.

Use `--dry-run` to perform preflight checks without writing the target. The target core tables must be empty by default. `--allow-non-empty-target` disables that guard but may still fail on unique values or conflicting data.

Cloudreve Qiniu, Upyun, remote-node, OneDrive and encrypted storage policies cannot be reused safely by AD. The migration stops when they are present. `--skip-unsupported-policies` explicitly omits those policies and all dependent files.

## Verification before push

Every migration feature must include focused tests plus end-to-end coverage where it writes database state. Before pushing, run and require all of these commands to pass:

```powershell
cargo fmt -- --check
cargo check --offline
cargo clippy --offline --all-targets --all-features -- -D warnings
cargo test --offline --all-targets --all-features
```
